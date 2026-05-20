"""console_notifier — writes notification events to stderr (or a configured stream).

SPEC §6.3.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from typing import IO, Callable, Optional

from .types import NotificationEvent


@dataclass
class ConsoleNotifierOptions:
    """Options for the console notifier."""

    stream: Optional[IO[str]] = None  # defaults to sys.stderr at call time
    prefix: str = "[guardian]"


def console_notifier(options: Optional[ConsoleNotifierOptions] = None) -> Callable[[NotificationEvent], None]:
    """Return a callable conforming to `Notifier.notify`."""
    opts = options or ConsoleNotifierOptions()
    prefix = opts.prefix

    def notify(event: NotificationEvent) -> None:
        stream = opts.stream if opts.stream is not None else sys.stderr
        stream.write(f"{prefix} {_format_event(event)}\n")
        try:
            stream.flush()
        except (OSError, ValueError):
            pass

    return notify


def _format_event(event: NotificationEvent) -> str:
    parts: list[str] = [
        str(event.get("kind", "?")),
        f"agent={event.get('agent_id', '-')}",
        f"source={event.get('source', '-')}",
    ]
    if "user_id" in event:
        parts.append(f"user={event['user_id']}")
    if "ts" in event:
        parts.append(f"at={event['ts']}")
    summary = event.get("summary")
    if summary:
        parts.append(f"summary={json.dumps(summary, sort_keys=True, separators=(',', ':'))}")
    if "canonical_clear_url" in event:
        parts.append(f"clear={event['canonical_clear_url']}")
    return " ".join(parts)
