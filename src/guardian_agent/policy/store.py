"""PolicyStore — HMAC-signed permissions.yaml + unsigned session.yaml.

SPEC §3.1 / §3.5 / §3.6.
"""

from __future__ import annotations

import os
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from ..errors import GuardianIntegrityError
from .integrity import sign_payload, verify_payload
from .loader import validate_policy
from .site_key import SiteKey, load_or_create_site_key
from .types import Policy, PolicyDefaults, PolicyRule, PolicyScope

PERMISSIONS_FILE = "permissions.yaml"
SESSION_FILE = "session.yaml"
SITE_KEY_FILE = "site.key"
POLICY_FILE_VERSION = 1


@dataclass
class PolicyStoreOptions:
    dir: str
    agent_id: str
    default_scope: str = "prompt"
    site_key: SiteKey | None = None


class PolicyStore:
    """HMAC-signed permissions.yaml + unsigned session.yaml."""

    def __init__(self, options: PolicyStoreOptions) -> None:
        self.dir = options.dir
        self.agent_id = options.agent_id
        self._default_scope = options.default_scope
        Path(self.dir).mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.dir, 0o700)
        except OSError:  # pragma: no cover
            pass
        self._site_key = options.site_key or load_or_create_site_key(
            str(Path(self.dir) / SITE_KEY_FILE)
        )
        self._lock = threading.Lock()

    def get_policy(self) -> Policy:
        """Read merged policy: persistent rules + session rules."""
        persistent = self._read_persistent()
        session = self._read_session()
        return Policy(
            version=persistent.version,
            agent_id=self.agent_id,
            defaults=persistent.defaults,
            rules=[*persistent.rules, *session.rules],
        )

    def add_rule(self, rule: PolicyRule) -> None:
        with self._lock:
            if rule.scope in ("session", "once"):
                cur = self._read_session()
                cur.rules = [
                    r for r in cur.rules if not (r.tool == rule.tool and r.scope == rule.scope)
                ]
                cur.rules.append(rule)
                self._write_session(cur)
            else:
                cur = self._read_persistent()
                cur.rules = [
                    r for r in cur.rules if not (r.tool == rule.tool and r.scope == rule.scope)
                ]
                cur.rules.append(rule)
                self._write_persistent(cur)

    def remove_rule(self, tool: str, scope: PolicyScope) -> None:
        with self._lock:
            if scope in ("session", "once"):
                cur = self._read_session()
                cur.rules = [r for r in cur.rules if not (r.tool == tool and r.scope == scope)]
                self._write_session(cur)
            else:
                cur = self._read_persistent()
                cur.rules = [r for r in cur.rules if not (r.tool == tool and r.scope == scope)]
                self._write_persistent(cur)

    def clear_session(self) -> None:
        with self._lock:
            path = Path(self.dir) / SESSION_FILE
            if path.exists():
                _secure_unlink(path)

    def close(self) -> None:
        """Idempotent no-op (lock is per-instance, no resources to release)."""
        pass

    # ---- internal --------------------------------------------------------

    def _empty_policy(self) -> Policy:
        return Policy(
            version="0.2",
            agent_id=self.agent_id,
            defaults=PolicyDefaults(scope=self._default_scope),
            rules=[],
        )

    def _read_persistent(self) -> Policy:
        path = Path(self.dir) / PERMISSIONS_FILE
        if not path.exists():
            return self._empty_policy()
        raw = path.read_text(encoding="utf-8")
        parsed = yaml.safe_load(raw)
        if not _is_signed_file(parsed):
            raise GuardianIntegrityError(
                f"permissions.yaml at {path} is not in signed-file format"
            )
        if not verify_payload(parsed["data"], parsed["signature"], self._site_key.bytes_):
            raise GuardianIntegrityError(
                f"permissions.yaml at {path} failed HMAC verification"
            )
        data = yaml.safe_load(parsed["data"])
        return validate_policy(data)

    def _write_persistent(self, policy: Policy) -> None:
        path = Path(self.dir) / PERMISSIONS_FILE
        payload = _policy_to_dict(policy, self.agent_id)
        data_str = yaml.safe_dump(payload, sort_keys=True, default_flow_style=False)
        signature = sign_payload(data_str, self._site_key.bytes_)
        wrapper = {
            "version": POLICY_FILE_VERSION,
            "signed_at": _iso_now(),
            "signature": signature,
            "data": data_str,
        }
        path.write_text(yaml.safe_dump(wrapper, sort_keys=True), encoding="utf-8")
        try:
            os.chmod(path, 0o600)
        except OSError:  # pragma: no cover
            pass

    def _read_session(self) -> Policy:
        path = Path(self.dir) / SESSION_FILE
        if not path.exists():
            return self._empty_policy()
        raw = path.read_text(encoding="utf-8")
        if not raw:
            return self._empty_policy()
        return validate_policy(yaml.safe_load(raw))

    def _write_session(self, policy: Policy) -> None:
        path = Path(self.dir) / SESSION_FILE
        payload = _policy_to_dict(policy, self.agent_id)
        path.write_text(
            yaml.safe_dump(payload, sort_keys=True, default_flow_style=False),
            encoding="utf-8",
        )
        try:
            os.chmod(path, 0o600)
        except OSError:  # pragma: no cover
            pass


def _policy_to_dict(policy: Policy, agent_id: str) -> dict[str, Any]:
    rules: list[dict[str, Any]] = []
    for r in policy.rules:
        d: dict[str, Any] = {"tool": r.tool, "scope": r.scope}
        if r.decision is not None:
            d["decision"] = r.decision
        if r.notes is not None:
            d["notes"] = r.notes
        if r.when is not None:
            w: dict[str, Any] = {}
            if r.when.model_provider is not None:
                w["model.provider"] = r.when.model_provider
            if r.when.model_id is not None:
                w["model.id"] = r.when.model_id
            d["when"] = w
        rules.append(d)
    defaults: dict[str, Any] = {"scope": policy.defaults.scope}
    if policy.defaults.decision is not None:
        defaults["decision"] = policy.defaults.decision
    return {
        "version": policy.version,
        "agent_id": agent_id,
        "defaults": defaults,
        "rules": rules,
    }


def _is_signed_file(v: Any) -> bool:
    if not isinstance(v, dict):
        return False
    return (
        v.get("version") == POLICY_FILE_VERSION
        and isinstance(v.get("signed_at"), str)
        and isinstance(v.get("signature"), str)
        and isinstance(v.get("data"), str)
    )


def _iso_now() -> str:
    now = datetime.now(timezone.utc)
    return now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"


def _secure_unlink(path: Path) -> None:  # pragma: no cover — best-effort cleanup
    try:
        size = path.stat().st_size
        if size > 0:
            import secrets

            for _ in range(3):
                path.write_bytes(secrets.token_bytes(size))
    except OSError:
        pass
    try:
        path.unlink()
    except OSError:
        pass
