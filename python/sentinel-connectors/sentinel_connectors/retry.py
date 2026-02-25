"""Retry and rate-limiting utilities for connector API calls."""

from __future__ import annotations

import asyncio
import logging
import time
from typing import TYPE_CHECKING, Any, TypeVar

if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine

logger = logging.getLogger(__name__)

T = TypeVar("T")


async def with_retry(
    fn: Callable[..., Coroutine[Any, Any, T]],
    *args: Any,
    max_attempts: int = 3,
    base_delay: float = 1.0,
    max_delay: float = 30.0,
    retryable_exceptions: tuple[type[Exception], ...] = (Exception,),
    **kwargs: Any,
) -> T:
    """Execute an async function with exponential backoff retry.

    Args:
        fn: Async function to call.
        max_attempts: Maximum number of attempts.
        base_delay: Initial delay between retries (seconds).
        max_delay: Maximum delay between retries (seconds).
        retryable_exceptions: Tuple of exception types that trigger a retry.
    """
    last_exc: Exception | None = None

    for attempt in range(1, max_attempts + 1):
        try:
            return await fn(*args, **kwargs)
        except retryable_exceptions as exc:
            last_exc = exc
            if attempt == max_attempts:
                break
            delay = min(base_delay * (2 ** (attempt - 1)), max_delay)
            logger.warning(
                "Attempt %d/%d failed (%s), retrying in %.1fs",
                attempt,
                max_attempts,
                exc,
                delay,
            )
            await asyncio.sleep(delay)

    raise last_exc  # type: ignore[misc]


class RateLimiter:
    """Simple token-bucket rate limiter for API calls."""

    def __init__(self, calls_per_second: float = 10.0) -> None:
        self._min_interval = 1.0 / calls_per_second
        self._last_call = 0.0

    async def acquire(self) -> None:
        """Wait if necessary to respect the rate limit."""
        now = time.monotonic()
        elapsed = now - self._last_call
        if elapsed < self._min_interval:
            await asyncio.sleep(self._min_interval - elapsed)
        self._last_call = time.monotonic()
