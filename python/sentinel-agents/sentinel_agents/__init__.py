"""Sentinel Agent Framework — autonomous LLM-powered cyber defense agents."""

from sentinel_agents.base import BaseAgent
from sentinel_agents.llm import (
    ClaudeLLMProvider,
    LLMMessage,
    LLMProvider,
    LLMResponse,
    MockLLMProvider,
)
from sentinel_agents.orchestrator import AgentOrchestrator
from sentinel_agents.tools import Tool, ToolParam, ToolRegistry, ToolResult
from sentinel_agents.types import (
    AgentConfig,
    AgentPlan,
    AgentResult,
    AgentStatus,
    Finding,
    PlanAlternative,
    Recommendation,
)

__all__ = [
    "AgentConfig",
    "AgentOrchestrator",
    "AgentPlan",
    "AgentResult",
    "AgentStatus",
    "BaseAgent",
    "ClaudeLLMProvider",
    "Finding",
    "LLMMessage",
    "LLMProvider",
    "LLMResponse",
    "MockLLMProvider",
    "PlanAlternative",
    "Recommendation",
    "Tool",
    "ToolParam",
    "ToolRegistry",
    "ToolResult",
]
