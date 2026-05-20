"""webhook_notifier — POSTs notification events as JSON to a URL.

SPEC §6.3. Failures are reported via the optional `on_error` callback; they
do NOT raise, because notifier failures must never block the press/clear
flow the notification accompanies.

Uses urllib from the standard library to avoid pulling in an HTTP client
dependency at the library level.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Callable, Optional

from .types import NotificationEvent

DEFAULT_TIMEOUT_SECONDS = 5.0

NotifierFn = Callable[[NotificationEvent], None]
OnErrorCallback = Callable[[BaseException, NotificationEvent], None]
PostFn = Callable[[str, bytes, dict[str, str], float], None]


@dataclass
class WebhookNotifierOptions:
    url: str
    headers: dict[str, str] = field(default_factory=dict)
    on_error: Optional[OnErrorCallback] = None
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS
    post: Optional[PostFn] = None  # override for testing


def webhook_notifier(options: WebhookNotifierOptions) -> NotifierFn:
    post = options.post or _default_post

    def notify(event: NotificationEvent) -> None:
        body = json.dumps(event, sort_keys=True, separators=(",", ":")).encode("utf-8")
        headers = {"content-type": "application/json", **options.headers}
        try:
            post(options.url, body, headers, options.timeout_seconds)
        except BaseException as exc:  # noqa: BLE001 — notifier MUST NOT raise
            if options.on_error is not None:
                try:
                    options.on_error(exc, event)
                except BaseException:  # noqa: BLE001
                    pass

    return notify


def _default_post(url: str, body: bytes, headers: dict[str, str], timeout_seconds: float) -> None:
    request = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            status = response.status
            if not (200 <= status < 300):
                raise WebhookStatusError(status)
    except urllib.error.HTTPError as exc:
        # urllib raises on 4xx/5xx; surface as a typed status error.
        raise WebhookStatusError(exc.code) from exc


class WebhookStatusError(RuntimeError):
    """Raised when the webhook responds with a non-2xx status."""

    def __init__(self, status: int) -> None:
        super().__init__(f"webhook_status_{status}")
        self.status = status
