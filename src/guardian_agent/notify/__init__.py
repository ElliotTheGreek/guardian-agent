"""Notification module. SPEC §6."""

from .console import ConsoleNotifierOptions, console_notifier
from .multi import MultiNotifierOptions, multi_notifier
from .types import NotificationEvent, NotificationKind, Notifier
from .webhook import (
    DEFAULT_TIMEOUT_SECONDS,
    WebhookNotifierOptions,
    WebhookStatusError,
    webhook_notifier,
)

__all__ = [
    "ConsoleNotifierOptions",
    "DEFAULT_TIMEOUT_SECONDS",
    "MultiNotifierOptions",
    "NotificationEvent",
    "NotificationKind",
    "Notifier",
    "WebhookNotifierOptions",
    "WebhookStatusError",
    "console_notifier",
    "multi_notifier",
    "webhook_notifier",
]
