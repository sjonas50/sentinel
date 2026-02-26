"""Known AI service domain registry for shadow AI detection."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel


class AiServiceCategory(StrEnum):
    """Category of AI service."""

    LLM_PROVIDER = "llm_provider"
    AI_PLATFORM = "ai_platform"
    CODE_AI = "code_ai"
    IMAGE_MEDIA_AI = "image_media_ai"
    VOICE_AI = "voice_ai"
    SEARCH_AI = "search_ai"
    ENTERPRISE_AI = "enterprise_ai"


class RiskTier(StrEnum):
    """Inherent risk tier for an AI service."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class AiServiceDomain(BaseModel):
    """A known AI service domain with classification metadata."""

    domain: str
    service_name: str
    category: AiServiceCategory
    risk_tier: RiskTier
    description: str = ""
    api_patterns: list[str] = []


# ---------------------------------------------------------------------------
# Master registry of known AI service domains
# ---------------------------------------------------------------------------

AI_SERVICE_DOMAINS: list[AiServiceDomain] = [
    # ── LLM Providers ─────────────────────────────────────────
    AiServiceDomain(
        domain="api.openai.com",
        service_name="OpenAI",
        category=AiServiceCategory.LLM_PROVIDER,
        risk_tier=RiskTier.CRITICAL,
        description="OpenAI ChatGPT / GPT API",
        api_patterns=["/v1/chat/completions", "/v1/embeddings"],
    ),
    AiServiceDomain(
        domain="api.anthropic.com",
        service_name="Anthropic",
        category=AiServiceCategory.LLM_PROVIDER,
        risk_tier=RiskTier.CRITICAL,
        description="Anthropic Claude API",
        api_patterns=["/v1/messages", "/v1/complete"],
    ),
    AiServiceDomain(
        domain="generativelanguage.googleapis.com",
        service_name="Google AI (Gemini)",
        category=AiServiceCategory.LLM_PROVIDER,
        risk_tier=RiskTier.CRITICAL,
        description="Google Gemini API",
        api_patterns=["/v1beta/models"],
    ),
    AiServiceDomain(
        domain="aiplatform.googleapis.com",
        service_name="Google Vertex AI",
        category=AiServiceCategory.LLM_PROVIDER,
        risk_tier=RiskTier.CRITICAL,
        description="Google Vertex AI platform",
    ),
    AiServiceDomain(
        domain="api.cohere.ai",
        service_name="Cohere",
        category=AiServiceCategory.LLM_PROVIDER,
        risk_tier=RiskTier.HIGH,
        description="Cohere language models",
    ),
    AiServiceDomain(
        domain="api.cohere.com",
        service_name="Cohere",
        category=AiServiceCategory.LLM_PROVIDER,
        risk_tier=RiskTier.HIGH,
        description="Cohere language models (alternate domain)",
    ),
    AiServiceDomain(
        domain="api.mistral.ai",
        service_name="Mistral AI",
        category=AiServiceCategory.LLM_PROVIDER,
        risk_tier=RiskTier.HIGH,
        description="Mistral language models",
    ),
    AiServiceDomain(
        domain="api.groq.com",
        service_name="Groq",
        category=AiServiceCategory.LLM_PROVIDER,
        risk_tier=RiskTier.HIGH,
        description="Groq inference API",
    ),
    AiServiceDomain(
        domain="api.perplexity.ai",
        service_name="Perplexity AI",
        category=AiServiceCategory.LLM_PROVIDER,
        risk_tier=RiskTier.HIGH,
        description="Perplexity search-augmented LLM",
    ),
    AiServiceDomain(
        domain="api.deepseek.com",
        service_name="DeepSeek",
        category=AiServiceCategory.LLM_PROVIDER,
        risk_tier=RiskTier.CRITICAL,
        description="DeepSeek language models",
    ),
    AiServiceDomain(
        domain="api.x.ai",
        service_name="xAI (Grok)",
        category=AiServiceCategory.LLM_PROVIDER,
        risk_tier=RiskTier.HIGH,
        description="xAI Grok API",
    ),
    AiServiceDomain(
        domain="dashscope.aliyuncs.com",
        service_name="Alibaba Qwen",
        category=AiServiceCategory.LLM_PROVIDER,
        risk_tier=RiskTier.CRITICAL,
        description="Alibaba Qwen / DashScope",
    ),
    # ── AI Platforms ──────────────────────────────────────────
    AiServiceDomain(
        domain="api-inference.huggingface.co",
        service_name="HuggingFace Inference",
        category=AiServiceCategory.AI_PLATFORM,
        risk_tier=RiskTier.HIGH,
        description="HuggingFace hosted inference API",
    ),
    AiServiceDomain(
        domain="huggingface.co",
        service_name="HuggingFace",
        category=AiServiceCategory.AI_PLATFORM,
        risk_tier=RiskTier.MEDIUM,
        description="HuggingFace model hub",
    ),
    AiServiceDomain(
        domain="api.replicate.com",
        service_name="Replicate",
        category=AiServiceCategory.AI_PLATFORM,
        risk_tier=RiskTier.HIGH,
        description="Replicate model hosting",
    ),
    AiServiceDomain(
        domain="api.together.xyz",
        service_name="Together AI",
        category=AiServiceCategory.AI_PLATFORM,
        risk_tier=RiskTier.HIGH,
        description="Together AI inference",
    ),
    AiServiceDomain(
        domain="api.fireworks.ai",
        service_name="Fireworks AI",
        category=AiServiceCategory.AI_PLATFORM,
        risk_tier=RiskTier.HIGH,
        description="Fireworks AI inference",
    ),
    AiServiceDomain(
        domain="api.deepinfra.com",
        service_name="DeepInfra",
        category=AiServiceCategory.AI_PLATFORM,
        risk_tier=RiskTier.HIGH,
        description="DeepInfra model hosting",
    ),
    AiServiceDomain(
        domain="api.lepton.ai",
        service_name="Lepton AI",
        category=AiServiceCategory.AI_PLATFORM,
        risk_tier=RiskTier.MEDIUM,
        description="Lepton AI inference",
    ),
    # ── Code AI ───────────────────────────────────────────────
    AiServiceDomain(
        domain="copilot-proxy.githubusercontent.com",
        service_name="GitHub Copilot",
        category=AiServiceCategory.CODE_AI,
        risk_tier=RiskTier.CRITICAL,
        description="GitHub Copilot code completion",
    ),
    AiServiceDomain(
        domain="api2.cursor.sh",
        service_name="Cursor",
        category=AiServiceCategory.CODE_AI,
        risk_tier=RiskTier.CRITICAL,
        description="Cursor AI code editor",
    ),
    AiServiceDomain(
        domain="server.codeium.com",
        service_name="Codeium",
        category=AiServiceCategory.CODE_AI,
        risk_tier=RiskTier.HIGH,
        description="Codeium code completion",
    ),
    AiServiceDomain(
        domain="api.tabnine.com",
        service_name="Tabnine",
        category=AiServiceCategory.CODE_AI,
        risk_tier=RiskTier.HIGH,
        description="Tabnine code completion",
    ),
    AiServiceDomain(
        domain="api.sourcegraph.com",
        service_name="Sourcegraph Cody",
        category=AiServiceCategory.CODE_AI,
        risk_tier=RiskTier.HIGH,
        description="Sourcegraph Cody AI assistant",
    ),
    # ── Image / Media AI ──────────────────────────────────────
    AiServiceDomain(
        domain="api.stability.ai",
        service_name="Stability AI",
        category=AiServiceCategory.IMAGE_MEDIA_AI,
        risk_tier=RiskTier.MEDIUM,
        description="Stable Diffusion API",
    ),
    AiServiceDomain(
        domain="api.midjourney.com",
        service_name="Midjourney",
        category=AiServiceCategory.IMAGE_MEDIA_AI,
        risk_tier=RiskTier.MEDIUM,
        description="Midjourney image generation",
    ),
    AiServiceDomain(
        domain="api.runwayml.com",
        service_name="RunwayML",
        category=AiServiceCategory.IMAGE_MEDIA_AI,
        risk_tier=RiskTier.MEDIUM,
        description="RunwayML video generation",
    ),
    # ── Voice AI ──────────────────────────────────────────────
    AiServiceDomain(
        domain="api.elevenlabs.io",
        service_name="ElevenLabs",
        category=AiServiceCategory.VOICE_AI,
        risk_tier=RiskTier.MEDIUM,
        description="ElevenLabs voice synthesis",
    ),
    # ── Search AI ─────────────────────────────────────────────
    AiServiceDomain(
        domain="api.you.com",
        service_name="You.com",
        category=AiServiceCategory.SEARCH_AI,
        risk_tier=RiskTier.MEDIUM,
        description="You.com AI search",
    ),
    # ── Enterprise AI ─────────────────────────────────────────
    AiServiceDomain(
        domain="api.openai.azure.com",
        service_name="Azure OpenAI",
        category=AiServiceCategory.ENTERPRISE_AI,
        risk_tier=RiskTier.MEDIUM,
        description="Azure-hosted OpenAI models",
    ),
    AiServiceDomain(
        domain="bedrock-runtime.*.amazonaws.com",
        service_name="AWS Bedrock",
        category=AiServiceCategory.ENTERPRISE_AI,
        risk_tier=RiskTier.MEDIUM,
        description="AWS Bedrock managed AI models",
    ),
]


def build_domain_lookup() -> dict[str, AiServiceDomain]:
    """Build a dict mapping domain -> AiServiceDomain for O(1) lookup."""
    return {entry.domain: entry for entry in AI_SERVICE_DOMAINS}


def match_domain(
    query_domain: str,
    lookup: dict[str, AiServiceDomain],
) -> AiServiceDomain | None:
    """Match a queried domain against the known AI service registry.

    Supports exact match first, then wildcard suffix matching for
    entries like ``bedrock-runtime.*.amazonaws.com``.
    """
    query_domain = query_domain.lower().rstrip(".")

    # Exact match
    if query_domain in lookup:
        return lookup[query_domain]

    # Wildcard matching — entries with '*' in the domain
    for key, entry in lookup.items():
        if "*" not in key:
            continue
        # Split pattern on '*', e.g. "bedrock-runtime." and ".amazonaws.com"
        parts = key.split("*", 1)
        prefix = parts[0]
        suffix = parts[1] if len(parts) > 1 else ""
        if query_domain.startswith(prefix) and query_domain.endswith(suffix):
            # Ensure there's something in between the prefix and suffix
            middle = query_domain[len(prefix) : len(query_domain) - len(suffix)]
            if middle:
                return entry

    return None
