"""Policy module: HMAC-signed permissions + evaluator. SPEC §3."""

from .evaluator import PolicyEvaluator, glob_match
from .integrity import SignedPolicyFile, sign_payload, verify_payload
from .loader import parse_policy, validate_policy
from .site_key import SITE_KEY_BYTES, SiteKey, load_or_create_site_key, site_key_from_bytes
from .store import PolicyStore, PolicyStoreOptions
from .types import Policy, PolicyDecision, PolicyEvaluation, PolicyRule, PolicyScope, PolicyWhen

__all__ = [
    "Policy",
    "PolicyDecision",
    "PolicyEvaluation",
    "PolicyEvaluator",
    "PolicyRule",
    "PolicyScope",
    "PolicyWhen",
    "PolicyStore",
    "PolicyStoreOptions",
    "SignedPolicyFile",
    "SiteKey",
    "SITE_KEY_BYTES",
    "load_or_create_site_key",
    "site_key_from_bytes",
    "sign_payload",
    "verify_payload",
    "parse_policy",
    "validate_policy",
    "glob_match",
]
