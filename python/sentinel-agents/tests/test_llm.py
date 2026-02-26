"""Tests for LLM provider abstraction."""

from __future__ import annotations

import pytest
from pydantic import BaseModel
from sentinel_agents.llm import ClaudeLLMProvider, LLMMessage, MockLLMProvider

# ── MockLLMProvider ───────────────────────────────────────────────


@pytest.mark.asyncio
async def test_mock_provider_returns_responses() -> None:
    provider = MockLLMProvider(responses=["first", "second", "third"])

    messages = [LLMMessage(role="user", content="Hello")]

    r1 = await provider.complete(messages)
    assert r1.content == "first"
    assert r1.model == "mock-model"
    assert r1.usage == {"input_tokens": 10, "output_tokens": 20}

    r2 = await provider.complete(messages)
    assert r2.content == "second"

    r3 = await provider.complete(messages)
    assert r3.content == "third"

    # Wraps around
    r4 = await provider.complete(messages)
    assert r4.content == "first"

    assert provider.call_count == 4


@pytest.mark.asyncio
async def test_mock_provider_default_response() -> None:
    provider = MockLLMProvider()
    messages = [LLMMessage(role="user", content="test")]
    r = await provider.complete(messages)
    assert r.content == "Mock LLM response"


@pytest.mark.asyncio
async def test_mock_provider_structured_output() -> None:
    class TestModel(BaseModel):
        name: str
        count: int

    provider = MockLLMProvider(responses=['{"name": "test", "count": 42}'])
    messages = [LLMMessage(role="user", content="give me data")]

    result = await provider.complete_structured(messages, TestModel)
    assert isinstance(result, TestModel)
    assert result.name == "test"
    assert result.count == 42


# ── ClaudeLLMProvider ─────────────────────────────────────────────


def test_claude_provider_init() -> None:
    """Verify ClaudeLLMProvider can be instantiated (requires anthropic SDK)."""
    provider = ClaudeLLMProvider(api_key="test-key", model="claude-haiku-4-5-20251001")
    assert provider._model == "claude-haiku-4-5-20251001"
    assert provider._client is not None
