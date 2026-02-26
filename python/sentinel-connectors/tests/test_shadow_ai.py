"""Shadow AI discovery connector tests."""

from __future__ import annotations

from uuid import uuid4

import pytest
from sentinel_connectors.governance.dns_analyzer import DnsLogAnalyzer
from sentinel_connectors.governance.domains import (
    AI_SERVICE_DOMAINS,
    AiServiceCategory,
    RiskTier,
    build_domain_lookup,
    match_domain,
)
from sentinel_connectors.governance.flow_analyzer import NetworkFlowAnalyzer
from sentinel_connectors.governance.models import ShadowAiServiceRecord
from sentinel_connectors.governance.risk_scorer import compute_risk_score
from sentinel_connectors.governance.shadow_ai import ShadowAiConnector

# ── Domain Registry Tests ────────────────────────────────────


class TestDomainRegistry:
    def test_registry_not_empty(self) -> None:
        assert len(AI_SERVICE_DOMAINS) >= 20

    def test_all_entries_have_required_fields(self) -> None:
        for entry in AI_SERVICE_DOMAINS:
            assert entry.domain
            assert entry.service_name
            assert entry.category in AiServiceCategory
            assert entry.risk_tier in RiskTier

    def test_build_lookup(self) -> None:
        lookup = build_domain_lookup()
        assert "api.openai.com" in lookup
        assert "api.anthropic.com" in lookup

    def test_match_exact_domain(self) -> None:
        lookup = build_domain_lookup()
        result = match_domain("api.openai.com", lookup)
        assert result is not None
        assert result.service_name == "OpenAI"

    def test_match_unknown_domain_returns_none(self) -> None:
        lookup = build_domain_lookup()
        result = match_domain("example.com", lookup)
        assert result is None

    def test_match_with_trailing_dot(self) -> None:
        lookup = build_domain_lookup()
        result = match_domain("api.openai.com.", lookup)
        assert result is not None
        assert result.service_name == "OpenAI"

    def test_match_case_insensitive(self) -> None:
        lookup = build_domain_lookup()
        result = match_domain("API.OpenAI.COM", lookup)
        assert result is not None

    def test_match_wildcard_bedrock(self) -> None:
        lookup = build_domain_lookup()
        result = match_domain("bedrock-runtime.us-east-1.amazonaws.com", lookup)
        assert result is not None
        assert result.service_name == "AWS Bedrock"

    def test_categories_cover_key_types(self) -> None:
        categories = {e.category for e in AI_SERVICE_DOMAINS}
        assert AiServiceCategory.LLM_PROVIDER in categories
        assert AiServiceCategory.CODE_AI in categories
        assert AiServiceCategory.AI_PLATFORM in categories
        assert AiServiceCategory.ENTERPRISE_AI in categories


# ── DNS Analyzer Tests ───────────────────────────────────────


class TestDnsAnalyzer:
    def setup_method(self) -> None:
        self.analyzer = DnsLogAnalyzer()

    def test_match_openai_dns(self) -> None:
        logs = [{"query_domain": "api.openai.com", "source_ip": "10.0.0.5"}]
        matches = self.analyzer.analyze_logs(logs)
        assert len(matches) == 1
        assert matches[0].query_domain == "api.openai.com"
        assert matches[0].source_ip == "10.0.0.5"

    def test_no_match_for_normal_domain(self) -> None:
        logs = [{"query_domain": "www.google.com", "source_ip": "10.0.0.5"}]
        matches = self.analyzer.analyze_logs(logs)
        assert len(matches) == 0

    def test_ecs_format_dns_log(self) -> None:
        logs = [
            {
                "dns": {"question": {"name": "api.anthropic.com"}},
                "source": {"ip": "10.0.0.10"},
            }
        ]
        matches = self.analyzer.analyze_logs(logs)
        assert len(matches) == 1
        assert matches[0].source_ip == "10.0.0.10"

    def test_zeek_format_dns_log(self) -> None:
        logs = [{"query": "api.mistral.ai", "id.orig_h": "10.0.0.20"}]
        matches = self.analyzer.analyze_logs(logs)
        assert len(matches) == 1
        assert matches[0].source_ip == "10.0.0.20"

    def test_empty_logs(self) -> None:
        assert self.analyzer.analyze_logs([]) == []

    def test_batch_processing(self) -> None:
        logs = [
            {"query_domain": "api.openai.com", "source_ip": "10.0.0.1"},
            {"query_domain": "www.example.com", "source_ip": "10.0.0.2"},
            {"query_domain": "api.anthropic.com", "source_ip": "10.0.0.3"},
        ]
        matches = self.analyzer.analyze_logs(logs)
        assert len(matches) == 2

    def test_extracts_hostname(self) -> None:
        logs = [
            {
                "query_domain": "api.openai.com",
                "source_ip": "10.0.0.1",
                "source_host": "workstation-42",
            }
        ]
        matches = self.analyzer.analyze_logs(logs)
        assert matches[0].source_host == "workstation-42"


# ── Network Flow Analyzer Tests ──────────────────────────────


class TestFlowAnalyzer:
    def setup_method(self) -> None:
        self.analyzer = NetworkFlowAnalyzer()

    def test_match_openai_flow(self) -> None:
        flows = [
            {
                "dest_domain": "api.openai.com",
                "source_ip": "10.0.0.5",
                "dest_port": 443,
                "bytes_sent": 1024,
                "bytes_received": 4096,
            }
        ]
        matches = self.analyzer.analyze_flows(flows)
        assert len(matches) == 1
        assert matches[0].bytes_sent == 1024
        assert matches[0].bytes_received == 4096

    def test_skip_non_https_port(self) -> None:
        flows = [
            {
                "dest_domain": "api.openai.com",
                "source_ip": "10.0.0.5",
                "dest_port": 22,
            }
        ]
        matches = self.analyzer.analyze_flows(flows)
        assert len(matches) == 0

    def test_accept_port_8443(self) -> None:
        flows = [
            {
                "dest_domain": "api.openai.com",
                "source_ip": "10.0.0.5",
                "dest_port": 8443,
            }
        ]
        matches = self.analyzer.analyze_flows(flows)
        assert len(matches) == 1

    def test_no_match_for_normal_domain(self) -> None:
        flows = [
            {
                "dest_domain": "cdn.example.com",
                "source_ip": "10.0.0.5",
                "dest_port": 443,
            }
        ]
        matches = self.analyzer.analyze_flows(flows)
        assert len(matches) == 0

    def test_empty_flows(self) -> None:
        assert self.analyzer.analyze_flows([]) == []

    def test_ecs_format_flow(self) -> None:
        flows = [
            {
                "destination": {"domain": "api.cohere.ai", "port": 443},
                "source": {"ip": "10.0.0.7"},
            }
        ]
        matches = self.analyzer.analyze_flows(flows)
        assert len(matches) == 1


# ── Risk Scorer Tests ────────────────────────────────────────


class TestRiskScorer:
    def test_critical_unsanctioned_high_volume(self) -> None:
        svc = ShadowAiServiceRecord(
            tenant_id=uuid4(),
            service_name="OpenAI",
            domain="api.openai.com",
            category=AiServiceCategory.LLM_PROVIDER,
            risk_tier=RiskTier.CRITICAL,
            total_bytes_sent=50 * 1024 * 1024,
            unique_source_ips=20,
            total_network_flows=200,
            sanctioned=False,
        )
        score = compute_risk_score(svc)
        assert score >= 80.0

    def test_low_risk_sanctioned(self) -> None:
        svc = ShadowAiServiceRecord(
            tenant_id=uuid4(),
            service_name="Azure OpenAI",
            domain="api.openai.azure.com",
            category=AiServiceCategory.ENTERPRISE_AI,
            risk_tier=RiskTier.MEDIUM,
            total_bytes_sent=1024,
            unique_source_ips=1,
            total_network_flows=5,
            sanctioned=True,
        )
        score = compute_risk_score(svc)
        assert score < 20.0

    def test_score_in_range(self) -> None:
        svc = ShadowAiServiceRecord(
            tenant_id=uuid4(),
            service_name="Test",
            domain="test.example.com",
            category=AiServiceCategory.AI_PLATFORM,
            risk_tier=RiskTier.LOW,
        )
        score = compute_risk_score(svc)
        assert 0.0 <= score <= 100.0

    def test_sanctioned_halves_score(self) -> None:
        svc = ShadowAiServiceRecord(
            tenant_id=uuid4(),
            service_name="Test",
            domain="test.example.com",
            category=AiServiceCategory.LLM_PROVIDER,
            risk_tier=RiskTier.HIGH,
            total_network_flows=50,
            unique_source_ips=5,
        )
        unsanctioned_score = compute_risk_score(svc)
        svc.sanctioned = True
        sanctioned_score = compute_risk_score(svc)
        assert sanctioned_score == pytest.approx(unsanctioned_score * 0.5, rel=0.01)


# ── ShadowAiConnector Tests ─────────────────────────────────


class TestShadowAiConnector:
    def test_connector_name(self) -> None:
        connector = ShadowAiConnector(tenant_id=uuid4())
        assert connector.name == "shadow_ai"

    @pytest.mark.asyncio
    async def test_health_check_always_true(self) -> None:
        connector = ShadowAiConnector(tenant_id=uuid4())
        assert await connector.health_check() is True

    @pytest.mark.asyncio
    async def test_scan_with_mixed_data(self) -> None:
        connector = ShadowAiConnector(tenant_id=uuid4())
        dns_logs = [
            {"query_domain": "api.openai.com", "source_ip": "10.0.0.1"},
            {"query_domain": "api.openai.com", "source_ip": "10.0.0.2"},
            {
                "query_domain": "api.anthropic.com",
                "source_ip": "10.0.0.1",
            },
        ]
        flows = [
            {
                "dest_domain": "api.openai.com",
                "source_ip": "10.0.0.1",
                "dest_port": 443,
                "bytes_sent": 1024,
            },
        ]
        result = await connector.scan(dns_logs, flows)
        assert len(result.services) >= 2
        assert result.total_dns_matches == 3
        assert result.total_flow_matches == 1
        # OpenAI should have 2 DNS queries + 1 flow + 2 unique IPs
        openai_svc = next(
            (s for s in result.services if s.service_name == "OpenAI"),
            None,
        )
        assert openai_svc is not None
        assert openai_svc.total_dns_queries == 2
        assert openai_svc.total_network_flows == 1
        assert openai_svc.unique_source_ips == 2

    @pytest.mark.asyncio
    async def test_scan_empty_data(self) -> None:
        connector = ShadowAiConnector(tenant_id=uuid4())
        result = await connector.scan([], [])
        assert len(result.services) == 0
        assert result.total_dns_matches == 0
        assert result.total_flow_matches == 0

    @pytest.mark.asyncio
    async def test_sanctioned_domains_config(self) -> None:
        connector = ShadowAiConnector(
            tenant_id=uuid4(),
            config={"sanctioned_domains": ["api.openai.azure.com"]},
        )
        dns_logs = [
            {
                "query_domain": "api.openai.azure.com",
                "source_ip": "10.0.0.1",
            },
        ]
        result = await connector.scan(dns_logs, [])
        if result.services:
            azure_svc = next(
                (s for s in result.services if "Azure" in s.service_name),
                None,
            )
            if azure_svc:
                assert azure_svc.sanctioned is True

    @pytest.mark.asyncio
    async def test_services_sorted_by_risk(self) -> None:
        connector = ShadowAiConnector(tenant_id=uuid4())
        dns_logs = [
            {"query_domain": "api.openai.com", "source_ip": "10.0.0.1"},
            {"query_domain": "huggingface.co", "source_ip": "10.0.0.2"},
        ]
        result = await connector.scan(dns_logs, [])
        if len(result.services) >= 2:
            # Services should be sorted by risk_score descending
            scores = [s.risk_score for s in result.services]
            assert scores == sorted(scores, reverse=True)
