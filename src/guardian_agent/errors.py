"""Public error types for guardian-agent."""

from __future__ import annotations


class GuardianHaltedError(Exception):
    """Raised inside a tool wrapper when the runtime is halted.

    SPEC §5.2.
    """

    def __init__(
        self,
        message: str,
        reason: str | None = None,
        operator_id: str | None = None,
    ) -> None:
        super().__init__(message)
        self.reason = reason
        self.operator_id = operator_id


class GuardianConfigError(Exception):
    """Invalid configuration: malformed policy, missing required options, etc."""


class GuardianIntegrityError(Exception):
    """Integrity verification failed: broken hash chain, bad HMAC, bad signature."""

    def __init__(self, message: str, detail: str | None = None) -> None:
        super().__init__(message)
        self.detail = detail


class PolicyDenialError(Exception):
    """Raised when the configured PolicyGate denied (or an operator denied a
    policy-prompt). SPEC §3 (v0.2+). Carries the composite policy identifier
    so callers can render structured errors without parsing strings.
    """

    def __init__(
        self,
        message: str,
        category: str | None = None,
        identifier: str | None = None,
        policy_identifier: str | None = None,
        scope: str | None = None,
        rule_tool: str | None = None,
    ) -> None:
        super().__init__(message)
        self.category = category
        self.identifier = identifier
        self.policy_identifier = policy_identifier
        self.scope = scope
        self.rule_tool = rule_tool
