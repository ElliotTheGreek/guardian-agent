"""Policy module: HMAC-signed permissions + evaluator + gate adapter. SPEC §3."""

from .attribution import (
    ATTRIBUTION_MISSING_SEGMENT,
    flat_glob_match,
    match_attribution_path,
    render_attribution_path,
)
from .evaluator import PolicyEvaluator, glob_match
from .gate_adapter import (
    PolicyGate,
    PolicyStoreGate,
    PolicyStoreGateOptions,
    policy_store_gate,
)
from .integrity import SignedPolicyFile, sign_payload, verify_payload
from .loader import parse_policy, validate_policy
from .site_key import SITE_KEY_BYTES, SiteKey, load_or_create_site_key, site_key_from_bytes
from .store import PolicyStore, PolicyStoreOptions
from .types import (
    Policy,
    PolicyDecision,
    PolicyDefaults,
    PolicyEvaluation,
    PolicyMatchedAt,
    PolicyRule,
    PolicyScope,
    PolicyWhen,
)

__all__ = [
    "ATTRIBUTION_MISSING_SEGMENT",
    "Policy",
    "PolicyDecision",
    "PolicyDefaults",
    "PolicyEvaluation",
    "PolicyEvaluator",
    "PolicyGate",
    "PolicyMatchedAt",
    "PolicyRule",
    "PolicyScope",
    "PolicyStore",
    "PolicyStoreGate",
    "PolicyStoreGateOptions",
    "PolicyStoreOptions",
    "PolicyWhen",
    "SignedPolicyFile",
    "SiteKey",
    "SITE_KEY_BYTES",
    "flat_glob_match",
    "glob_match",
    "load_or_create_site_key",
    "match_attribution_path",
    "parse_policy",
    "policy_store_gate",
    "render_attribution_path",
    "sign_payload",
    "site_key_from_bytes",
    "validate_policy",
    "verify_payload",
]
