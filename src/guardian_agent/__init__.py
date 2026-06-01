"""guardian-agent — Python reference implementation of the supervisor spec.

SPEC: https://github.com/flowdot-llc/guardian-agent/blob/main/SPEC.md
"""

from __future__ import annotations

__version__ = "0.2.0"
__spec_version__ = "0.5.0"

from .audit import (
    AuditLogReader,
    AuditLogWriter,
    AuditLogWriterOptions,
    GENESIS_HASH,
    SIGNATURE_PREFIX,
    canonical_json_string,
    canonicalize_for_hash,
    compute_record_hash,
    generate_ed25519_keypair,
    load_private_key,
    load_public_key,
    sign_record,
    verify_record,
)
from .errors import (
    GuardianConfigError,
    GuardianHaltedError,
    GuardianIntegrityError,
)
from .estop import (
    EStopClearOptions,
    EStopClearResult,
    EStopLocal,
    EStopPressOptions,
    EStopPressResult,
    EStopState,
)
from .notify import NotificationEvent, NotificationKind, Notifier
from .runtime import GuardianRuntime, GuardianRuntimeOptions, ToolOptions
from .types import (
    AuditRecord,
    AuditRecordInitiator,
    AuditRecordKind,
    AuditRecordStatus,
    ModelAttribution,
    SPEC_VERSION,
)

__all__ = [
    "__version__",
    "__spec_version__",
    "SPEC_VERSION",
    # runtime
    "GuardianRuntime",
    "GuardianRuntimeOptions",
    "ToolOptions",
    # audit
    "AuditLogReader",
    "AuditLogWriter",
    "AuditLogWriterOptions",
    "GENESIS_HASH",
    "SIGNATURE_PREFIX",
    "canonical_json_string",
    "canonicalize_for_hash",
    "compute_record_hash",
    "generate_ed25519_keypair",
    "load_private_key",
    "load_public_key",
    "sign_record",
    "verify_record",
    # estop
    "EStopLocal",
    "EStopClearOptions",
    "EStopClearResult",
    "EStopPressOptions",
    "EStopPressResult",
    "EStopState",
    # notify
    "NotificationEvent",
    "NotificationKind",
    "Notifier",
    # types
    "AuditRecord",
    "AuditRecordInitiator",
    "AuditRecordKind",
    "AuditRecordStatus",
    "ModelAttribution",
    # errors
    "GuardianConfigError",
    "GuardianHaltedError",
    "GuardianIntegrityError",
]
