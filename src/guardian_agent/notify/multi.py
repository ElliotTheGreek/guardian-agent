"""multi_notifier — fan a notification out to several notifiers sequentially.

SPEC §6.3. Failures in one notifier never block the others. Errors are
collected and reported via the optional `on_error` callback.

(Python is sync here unlike TS's Promise.allSettled fan-out; the reference
adapters are quick and non-blocking, and threading would complicate the
shared-state model. Hosts that want parallel fan-out can wrap.)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional, Sequence

from .types import NotificationEvent

OnErrorCallback = Callable[[BaseException, NotificationEvent, int], None]
NotifierFn = Callable[[NotificationEvent], None]


@dataclass
class MultiNotifierOptions:
    notifiers: Sequence[NotifierFn]
    on_error: Optional[OnErrorCallback] = None


def multi_notifier(options: MultiNotifierOptions) -> NotifierFn:
    """Return a Notifier.notify-compatible callable that fans out."""
    notifiers = list(options.notifiers)
    on_error = options.on_error

    def notify(event: NotificationEvent) -> None:
        for i, fn in enumerate(notifiers):
            try:
                fn(event)
            except BaseException as exc:  # noqa: BLE001 — must isolate per notifier
                if on_error is not None:
                    try:
                        on_error(exc, event, i)
                    except BaseException:  # noqa: BLE001
                        # on_error must never bring the loop down either.
                        pass

    return notify
