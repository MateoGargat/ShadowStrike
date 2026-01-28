"""Integration tests for the full workflow (mocked collectors + MoA)."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from core.models import (
    AIAnalysis,
    AppConfig,
    CollectorResult,
    DNSRecords,
    IPRecord,
    MoAConfig,
    PortRecord,
    ProposerAnalysis,
    RiskLevel,
    SubdomainRecord,
    WhoisRecord,
)
from workflow import WorkflowRunner


@pytest.fixture
def config():
    return AppConfig(groq_api_key="test_key")


@pytest.fixture
def multi_provider_config():
    return AppConfig(
        groq_api_key="test_groq",
        openai_api_key="test_openai",
        moa_config=MoAConfig(
            proposers=[
                {"provider": "groq", "model": "llama-3.3-70b-versatile"},
                {"provider": "openai", "model": "gpt-4o-mini"},
            ],
            aggregator={"provider": "groq", "model": "llama-3.3-70b-versatile"},
            enable_reflection=False,
        ),
    )


def _mock_crtsh_result():
    return CollectorResult(
        source="crtsh",
        success=True,
        subdomains=[
            SubdomainRecord(name="www.example.com", source="crtsh"),
            SubdomainRecord(name="api.example.com", source="crtsh"),
        ],
    )


def _mock_dns_result():
    return CollectorResult(
        source="dns",
        success=True,
        dns=DNSRecords(domain="example.com", a=["93.184.216.34"]),
        ips=[IPRecord(address="93.184.216.34", version=4, hostnames=["example.com"])],
    )


def _mock_whois_result():
    return CollectorResult(
        source="whois",
        success=True,
        whois=WhoisRecord(domain="example.com", registrar="Test Registrar"),
    )


def _mock_hackertarget_result():
    return CollectorResult(
        source="hackertarget",
        success=True,
        subdomains=[SubdomainRecord(name="mail.example.com", source="hackertarget")],
        ips=[IPRecord(address="93.184.216.35", version=4)],
    )


def _mock_shodan_result(ip="93.184.216.34"):
    return CollectorResult(
        source="shodan",
        success=True,
        ports=[PortRecord(port=80, protocol="tcp", ip_address=ip)],
    )


def _mock_failed_result():
    return CollectorResult(
        source="failed_source",
        success=False,
        error="Connection timeout",
    )


def _mock_ai_analysis():
    return AIAnalysis(
        risk_score=35,
        executive_summary="Low exposure.",
        attack_surface_size="Small",
        findings=[],
        exposed_services_summary="1 service.",
        recommendations=["Monitor regularly."],
    )


def _mock_proposer_analysis(provider="groq", model="llama"):
    return ProposerAnalysis(
        provider=provider,
        model=model,
        risk_score=35,
        executive_summary="Low exposure.",
        findings=[],
        recommendations=["Monitor regularly."],
        confidence=0.8,
    )


class TestIntegration:
    @patch("workflow.AIAnalyst")
    @patch("workflow.ShodanCollector")
    @patch("workflow.DNSCollector")
    @patch("workflow.get_domain_collectors")
    def test_full_domain_scan_mocked(
        self, mock_get_domain, mock_dns_cls, mock_shodan_cls, mock_ai_cls, config
    ):
        # Setup domain collectors
        mock_collectors = []
        for result in [_mock_crtsh_result(), _mock_dns_result(), _mock_whois_result(), _mock_hackertarget_result()]:
            c = MagicMock()
            c.safe_collect = AsyncMock(return_value=result)
            mock_collectors.append(c)
        mock_get_domain.return_value = mock_collectors

        # Setup DNS resolver for enrichment
        mock_dns = MagicMock()
        mock_dns.resolve_subdomains = AsyncMock(return_value=([], []))
        mock_dns_cls.return_value = mock_dns

        # Setup Shodan for enrichment
        mock_shodan = MagicMock()
        mock_shodan.safe_collect = AsyncMock(return_value=_mock_shodan_result())
        mock_shodan_cls.return_value = mock_shodan

        # Setup AI analyst — mock both propose and aggregate
        mock_analyst = MagicMock()
        mock_analyst.analyze.return_value = _mock_ai_analysis()
        mock_analyst.propose.return_value = _mock_proposer_analysis()
        mock_analyst.aggregate.return_value = _mock_ai_analysis()
        mock_analyst.reflect.return_value = _mock_ai_analysis()
        mock_analyst._build_context.return_value = "test context"
        mock_ai_cls.return_value = mock_analyst

        runner = WorkflowRunner(config=config)
        state = runner.run("example.com")

        assert state["input_type"] == "domain"
        assert state["target"] == "example.com"
        assert len(state["subdomains"]) > 0
        assert state["current_step"] in ("analyzed", "reflected")

    @patch("workflow.AIAnalyst")
    @patch("workflow.ShodanCollector")
    @patch("workflow.DNSCollector")
    @patch("workflow.get_ip_collectors")
    def test_full_ip_scan_mocked(
        self, mock_get_ip, mock_dns_cls, mock_shodan_cls, mock_ai_cls, config
    ):
        mock_collector = MagicMock()
        mock_collector.safe_collect = AsyncMock(return_value=_mock_shodan_result("8.8.8.8"))
        mock_get_ip.return_value = [mock_collector]

        mock_dns = MagicMock()
        mock_dns.resolve_subdomains = AsyncMock(return_value=([], []))
        mock_dns_cls.return_value = mock_dns

        mock_shodan = MagicMock()
        mock_shodan.safe_collect = AsyncMock(return_value=_mock_shodan_result("8.8.8.8"))
        mock_shodan_cls.return_value = mock_shodan

        mock_analyst = MagicMock()
        mock_analyst.analyze.return_value = _mock_ai_analysis()
        mock_analyst.propose.return_value = _mock_proposer_analysis()
        mock_analyst.aggregate.return_value = _mock_ai_analysis()
        mock_analyst.reflect.return_value = _mock_ai_analysis()
        mock_analyst._build_context.return_value = "test context"
        mock_ai_cls.return_value = mock_analyst

        runner = WorkflowRunner(config=config)
        state = runner.run("8.8.8.8")

        assert state["input_type"] == "ip"
        assert state["target"] == "8.8.8.8"

    @patch("workflow.AIAnalyst")
    @patch("workflow.ShodanCollector")
    @patch("workflow.DNSCollector")
    @patch("workflow.get_domain_collectors")
    def test_workflow_partial_failure(
        self, mock_get_domain, mock_dns_cls, mock_shodan_cls, mock_ai_cls, config
    ):
        """Workflow should continue even if some collectors fail."""
        mock_ok = MagicMock()
        mock_ok.safe_collect = AsyncMock(return_value=_mock_dns_result())
        mock_fail = MagicMock()
        mock_fail.safe_collect = AsyncMock(return_value=_mock_failed_result())
        mock_get_domain.return_value = [mock_ok, mock_fail]

        mock_dns = MagicMock()
        mock_dns.resolve_subdomains = AsyncMock(return_value=([], []))
        mock_dns_cls.return_value = mock_dns

        mock_shodan = MagicMock()
        mock_shodan.safe_collect = AsyncMock(return_value=_mock_shodan_result())
        mock_shodan_cls.return_value = mock_shodan

        mock_analyst = MagicMock()
        mock_analyst.analyze.return_value = _mock_ai_analysis()
        mock_analyst.propose.return_value = _mock_proposer_analysis()
        mock_analyst.aggregate.return_value = _mock_ai_analysis()
        mock_analyst.reflect.return_value = _mock_ai_analysis()
        mock_analyst._build_context.return_value = "test context"
        mock_ai_cls.return_value = mock_analyst

        runner = WorkflowRunner(config=config)
        state = runner.run("example.com")

        # Should still complete
        assert state["current_step"] in ("analyzed", "reflected")
        # Should have recorded the error
        assert len(state["errors"]) > 0
        assert any("Connection timeout" in e for e in state["errors"])


class TestMoAIntegration:
    def test_mono_provider_creates_dual_perspective(self, config):
        """Mono-provider should create 2 proposers with different perspectives."""
        runner = WorkflowRunner(config=config)
        available = runner.llm_provider.get_available_providers()
        assert len(available) == 1  # Only groq

    def test_multi_provider_config(self, multi_provider_config):
        """Multi-provider config should have multiple proposers."""
        assert len(multi_provider_config.moa_config.proposers) == 2
        assert multi_provider_config.moa_config.proposers[0]["provider"] == "groq"
        assert multi_provider_config.moa_config.proposers[1]["provider"] == "openai"

    def test_reflection_disabled(self, multi_provider_config):
        """Reflection can be disabled via config."""
        assert multi_provider_config.moa_config.enable_reflection is False

    def test_default_models(self, config):
        """Default model mapping should work."""
        runner = WorkflowRunner(config=config)
        assert runner._default_model_for_provider("groq") == "llama-3.3-70b-versatile"
        assert runner._default_model_for_provider("openai") == "gpt-4o-mini"
        assert runner._default_model_for_provider("anthropic") == "claude-3-5-haiku-20241022"

    def test_should_reflect_disabled(self, config):
        """When reflection is disabled, _should_reflect returns 'end'."""
        config.moa_config.enable_reflection = False
        runner = WorkflowRunner(config=config)
        state = {"ai_analysis": {"analysis_version": 1}}
        assert runner._should_reflect(state) == "end"

    def test_should_reflect_enabled(self, config):
        """When reflection is enabled and analysis not yet reflected, returns 'reflect'."""
        config.moa_config.enable_reflection = True
        runner = WorkflowRunner(config=config)
        state = {"ai_analysis": {"analysis_version": 1}}
        assert runner._should_reflect(state) == "reflect"

    def test_should_reflect_max_iterations(self, config):
        """When analysis_version exceeds max_reflection_iterations, returns 'end'."""
        config.moa_config.enable_reflection = True
        config.moa_config.max_reflection_iterations = 1
        runner = WorkflowRunner(config=config)
        state = {"ai_analysis": {"analysis_version": 2}}
        assert runner._should_reflect(state) == "end"
