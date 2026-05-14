"""EStop module: in-process emergency-stop primitive. SPEC §5."""

from .local import EStopLocal
from .types import (
    EStopClearOptions,
    EStopClearResult,
    EStopPressOptions,
    EStopPressResult,
    EStopState,
)

__all__ = [
    "EStopLocal",
    "EStopClearOptions",
    "EStopClearResult",
    "EStopPressOptions",
    "EStopPressResult",
    "EStopState",
]
