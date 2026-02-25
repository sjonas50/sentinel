"""Tests for retry and rate-limiting utilities."""

import pytest
from sentinel_connectors.retry import RateLimiter, with_retry


@pytest.mark.asyncio
async def test_with_retry_succeeds_first_try() -> None:
    call_count = 0

    async def ok() -> str:
        nonlocal call_count
        call_count += 1
        return "done"

    result = await with_retry(ok, max_attempts=3)
    assert result == "done"
    assert call_count == 1


@pytest.mark.asyncio
async def test_with_retry_retries_on_failure() -> None:
    call_count = 0

    async def fail_then_ok() -> str:
        nonlocal call_count
        call_count += 1
        if call_count < 3:
            raise ValueError("not yet")
        return "ok"

    result = await with_retry(fail_then_ok, max_attempts=3, base_delay=0.01)
    assert result == "ok"
    assert call_count == 3


@pytest.mark.asyncio
async def test_with_retry_exhausts_attempts() -> None:
    async def always_fail() -> str:
        raise RuntimeError("boom")

    with pytest.raises(RuntimeError, match="boom"):
        await with_retry(always_fail, max_attempts=2, base_delay=0.01)


@pytest.mark.asyncio
async def test_rate_limiter_acquire() -> None:
    limiter = RateLimiter(calls_per_second=1000.0)
    # Should not block with a high rate
    for _ in range(5):
        await limiter.acquire()


@pytest.mark.asyncio
async def test_with_retry_only_retries_specified_exceptions() -> None:
    call_count = 0

    async def fail_with_type_error() -> str:
        nonlocal call_count
        call_count += 1
        raise TypeError("wrong type")

    with pytest.raises(TypeError):
        await with_retry(
            fail_with_type_error,
            max_attempts=3,
            base_delay=0.01,
            retryable_exceptions=(ValueError,),
        )
    # Should not retry because TypeError isn't in retryable_exceptions
    assert call_count == 1
