"""Per-capability token-bucket rate limiter. SPEC §5 extension (v0.3+).

A single global bucket lets read-heavy work get blocked by a writes burst.
Per-class buckets let conservative limits on rare classes (credential,
delete, system-path) bite exfil patterns long before the global rate.

Normal workloads see zero impact at the conservative defaults; the buckets
only bite on bursts that match the exfil shape.
"""

from __future__ import annotations

import math
import time
from dataclasses import dataclass, field
from typing import Callable, Optional, Sequence, Union

CapabilityClass = str  # canonical classes are documented in capability.py


@dataclass
class BucketConfig:
    """Bucket configuration for one capability class."""

    max_calls_per_second: float
    bucket_capacity: Optional[float] = None
    """Burst capacity. Defaults to max_calls_per_second."""


@dataclass
class MultiRateLimiterOptions:
    """Per-class buckets + an optional fallback."""

    buckets: dict[CapabilityClass, BucketConfig] = field(default_factory=dict)
    default_bucket: Optional[BucketConfig] = None
    now: Optional[Callable[[], float]] = None
    """Time source returning ms. Defaults to time.monotonic()*1000."""


@dataclass
class ConsumeAllowed:
    allowed: bool = True


@dataclass
class ConsumeDenied:
    cls: CapabilityClass
    retry_after_ms: float
    allowed: bool = False


ConsumeResult = Union[ConsumeAllowed, ConsumeDenied]


# Library-recommended defaults. Tuned to never trip normal CLI workloads
# (read/write at human-edit speed, occasional outbound calls) while catching
# exfil-shaped bursts in the seconds-window.
DEFAULT_BUCKETS: dict[CapabilityClass, BucketConfig] = {
    "read": BucketConfig(max_calls_per_second=50),
    "write": BucketConfig(max_calls_per_second=10),
    "delete": BucketConfig(max_calls_per_second=1),
    "execute": BucketConfig(max_calls_per_second=5),
    "network-egress": BucketConfig(max_calls_per_second=5),
    "network-ingress": BucketConfig(max_calls_per_second=50),
    "credential": BucketConfig(max_calls_per_second=2),
    "system-path": BucketConfig(max_calls_per_second=1),
    "bulk": BucketConfig(max_calls_per_second=2),
}


def _default_now_ms() -> float:
    return time.monotonic() * 1000.0


class _Bucket:
    def __init__(self, config: BucketConfig, now: Callable[[], float]) -> None:
        self._refill_per_ms = config.max_calls_per_second / 1000.0
        self._capacity = config.bucket_capacity if config.bucket_capacity is not None else config.max_calls_per_second
        self._now = now
        self._tokens: float = float(self._capacity)
        self._last_refill: float = self._now()

    def try_consume(self) -> tuple[bool, float]:
        """Return (allowed, retry_after_ms). retry_after_ms is 0 on allowed."""
        self._refill()
        if self._tokens >= 1.0:
            self._tokens -= 1.0
            return True, 0.0
        needed = 1.0 - self._tokens
        if self._refill_per_ms == 0:
            return False, math.inf
        retry_after_ms = math.ceil(needed / self._refill_per_ms)
        return False, retry_after_ms

    def current_tokens(self) -> float:
        self._refill()
        return self._tokens

    def _refill(self) -> None:
        t = self._now()
        elapsed = t - self._last_refill
        if elapsed <= 0:
            return
        self._tokens = min(self._capacity, self._tokens + elapsed * self._refill_per_ms)
        self._last_refill = t


class MultiRateLimiter:
    """Per-capability rate limiter. One bucket per class.

    Multi-class tools consume one token from every relevant bucket. First
    denial wins; tokens already consumed from earlier classes in the call
    are NOT refunded (safety-conservative: a multi-class call blocked on its
    rarest capability is fully blocked).
    """

    def __init__(self, options: MultiRateLimiterOptions) -> None:
        self._now = options.now or _default_now_ms
        self._buckets: dict[CapabilityClass, _Bucket] = {}
        self._default_bucket: Optional[_Bucket] = None
        if options.default_bucket is not None:
            self._default_bucket = _Bucket(options.default_bucket, self._now)
        for cls, cfg in options.buckets.items():
            self._buckets[cls] = _Bucket(cfg, self._now)

    def try_consume(self, classes: Sequence[CapabilityClass]) -> ConsumeResult:
        for cls in classes:
            bucket = self._buckets.get(cls)
            if bucket is None and self._default_bucket is not None:
                bucket = self._default_bucket
            if bucket is None:
                continue  # no policy for this class → allowed
            allowed, retry_after_ms = bucket.try_consume()
            if not allowed:
                return ConsumeDenied(cls=cls, retry_after_ms=retry_after_ms)
        return ConsumeAllowed()

    def snapshot(self) -> dict[str, float]:
        """Current token count per class (tests + introspection)."""
        out: dict[str, float] = {}
        for cls, bucket in self._buckets.items():
            out[cls] = bucket.current_tokens()
        if self._default_bucket is not None:
            out["_default"] = self._default_bucket.current_tokens()
        return out
