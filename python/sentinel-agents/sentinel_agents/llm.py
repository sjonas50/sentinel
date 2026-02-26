"""LLM provider abstraction with Claude default and mock for testing."""

from __future__ import annotations

import json
import logging
from typing import Any, TypeVar

from pydantic import BaseModel

logger = logging.getLogger(__name__)

T = TypeVar("T", bound=BaseModel)


class LLMMessage(BaseModel):
    """A single message in a conversation."""

    role: str  # "user", "assistant", "system"
    content: str


class LLMResponse(BaseModel):
    """Response from an LLM provider."""

    content: str
    model: str
    usage: dict[str, int] = {}  # input_tokens, output_tokens
    stop_reason: str | None = None


class LLMProvider:
    """Base class for LLM providers.

    Subclass and override ``complete`` / ``complete_structured`` to
    integrate a new LLM backend.
    """

    async def complete(
        self,
        messages: list[LLMMessage],
        *,
        system: str | None = None,
        max_tokens: int = 4096,
    ) -> LLMResponse:
        """Generate a completion for the given messages."""
        raise NotImplementedError

    async def complete_structured(
        self,
        messages: list[LLMMessage],
        response_model: type[T],
        *,
        system: str | None = None,
        max_tokens: int = 4096,
    ) -> T:
        """Generate a completion and parse it into a Pydantic model."""
        raise NotImplementedError


class ClaudeLLMProvider(LLMProvider):
    """Claude API provider using the Anthropic SDK."""

    def __init__(self, api_key: str, model: str = "claude-sonnet-4-20250514") -> None:
        import anthropic

        self._client = anthropic.AsyncAnthropic(api_key=api_key)
        self._model = model

    async def complete(
        self,
        messages: list[LLMMessage],
        *,
        system: str | None = None,
        max_tokens: int = 4096,
    ) -> LLMResponse:
        api_messages: list[dict[str, Any]] = [
            {"role": m.role, "content": m.content} for m in messages if m.role != "system"
        ]
        kwargs: dict[str, Any] = {
            "model": self._model,
            "max_tokens": max_tokens,
            "messages": api_messages,
        }
        if system:
            kwargs["system"] = system

        response = await self._client.messages.create(**kwargs)

        return LLMResponse(
            content=response.content[0].text,
            model=response.model,
            usage={
                "input_tokens": response.usage.input_tokens,
                "output_tokens": response.usage.output_tokens,
            },
            stop_reason=response.stop_reason,
        )

    async def complete_structured(
        self,
        messages: list[LLMMessage],
        response_model: type[T],
        *,
        system: str | None = None,
        max_tokens: int = 4096,
    ) -> T:
        schema = response_model.model_json_schema()
        prompt_suffix = f"\n\nRespond with valid JSON matching this schema:\n{json.dumps(schema)}"

        augmented = list(messages)
        if augmented:
            last = augmented[-1]
            augmented[-1] = LLMMessage(role=last.role, content=last.content + prompt_suffix)

        response = await self.complete(augmented, system=system, max_tokens=max_tokens)
        return response_model.model_validate_json(response.content)


class MockLLMProvider(LLMProvider):
    """Mock provider for testing — returns pre-configured responses."""

    def __init__(self, responses: list[str] | None = None) -> None:
        self._responses = responses or ["Mock LLM response"]
        self._call_count = 0

    @property
    def call_count(self) -> int:
        return self._call_count

    async def complete(
        self,
        messages: list[LLMMessage],
        *,
        system: str | None = None,
        max_tokens: int = 4096,
    ) -> LLMResponse:
        idx = self._call_count % len(self._responses)
        self._call_count += 1
        return LLMResponse(
            content=self._responses[idx],
            model="mock-model",
            usage={"input_tokens": 10, "output_tokens": 20},
            stop_reason="end_turn",
        )

    async def complete_structured(
        self,
        messages: list[LLMMessage],
        response_model: type[T],
        *,
        system: str | None = None,
        max_tokens: int = 4096,
    ) -> T:
        response = await self.complete(messages, system=system, max_tokens=max_tokens)
        return response_model.model_validate_json(response.content)
