"""EStop module: in-process + hub-coordinated emergency stop. SPEC §5."""

from .heartbeat import HeartbeatMonitor, HeartbeatMonitorOptions, HeartbeatState
from .hub import (
    DEFAULT_CACHE_TTL_MS,
    EStopActorContext,
    EStopBroadcastChannel,
    EStopHub,
    EStopHubOptions,
    EStopStateStore,
    InMemoryEStopStateStore,
)
from .local import EStopLocal
from .middleware import (
    EStopMiddlewareOptions,
    create_estop_middleware,
)
from .poller import (
    DEFAULT_INTERVAL_MS,
    EStopPoller,
    EStopPollerOptions,
    create_estop_poller,
)
from .types import (
    EStopClearOptions,
    EStopClearResult,
    EStopPressOptions,
    EStopPressResult,
    EStopState,
)

__all__ = [
    "DEFAULT_CACHE_TTL_MS",
    "DEFAULT_INTERVAL_MS",
    "EStopActorContext",
    "EStopBroadcastChannel",
    "EStopClearOptions",
    "EStopClearResult",
    "EStopHub",
    "EStopHubOptions",
    "EStopLocal",
    "EStopMiddlewareOptions",
    "EStopPoller",
    "EStopPollerOptions",
    "EStopPressOptions",
    "EStopPressResult",
    "EStopState",
    "EStopStateStore",
    "HeartbeatMonitor",
    "HeartbeatMonitorOptions",
    "HeartbeatState",
    "InMemoryEStopStateStore",
    "create_estop_middleware",
    "create_estop_poller",
]
