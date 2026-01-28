"""Tests for analyzers.ai_analyst module (MoA architecture)."""

from unittest.mock import MagicMock, patch

import pytest

from analyzers.ai_analyst import AIAnalyst
from analyzers.prompts import PROPOSER_PROMPT, AGGREGATOR_PROMPT, REFLECTION_PROMPT
from core.models import (
    AIAnalysis,
    AppConfig,
    Finding,
    InputType,
    IPRecord,
    MoAConfig,
    PortRecord,
    ProposerAnalysis,
    RiskLevel,
    ScanResult,
    SubdomainRecord,
)


@pytest.fixture
def config():
    return AppConfig(groq_api_key="test_groq_key")


@pytest.fixture
def multi_config():
    return AppConfig(
        groq_api_key="test_groq_key",
        openai_api_key="test_openai_key",
        moa_config=MoAConfig(
            proposers=[
                {"provider": "groq", "model": "llama-3.3-70b-versatile"},
                {"provider": "openai", "model": "gpt-4o-mini"},
            ],
            aggregator={"provider": "groq", "model": "llama-3.3-70b-versatile"},
            enable_reflection=True,
        ),
    )


@pytest.fixture
def analyst(config):
    return AIAnalyst(config=config)


@pytest.fixture
def scan_result():
    return ScanResult(
        target="example.com",
        input_type=InputType.DOMAIN,
        subdomains=[
            SubdomainRecord(name="www.example.com", source="crtsh"),
            SubdomainRecord(name="api.example.com", source="crtsh"),
        ],
        ips=[IPRecord(address="1.2.3.4", version=4)],
        ports=[
            PortRecord(port=80, protocol="tcp", ip_address="1.2.3.4"),
            PortRecord(port=443, protocol="tcp", ip_address="1.2.3.4"),
        ],
        sources_used=["crtsh", "dns", "shodan"],
    )


@pytest.fixture
def mock_analysis():
    return AIAnalysis(
        risk_score=45,
        executive_summary="Moderate exposure detected.",
        attack_surface_size="Small",
        findings=[
            Finding(
                title="HTTP without HTTPS redirect",
                severity=RiskLevel.MEDIUM,
                description="Port 80 is open without confirmed HTTPS redirect.",
                affected_assets=["1.2.3.4:80"],
                recommendation="Ensure HTTP redirects to HTTPS.",
            )
        ],
        exposed_services_summary="2 services exposed on 1 IP.",
        recommendations=["Enable HTTPS redirect", "Review exposed ports"],
    )


@pytest.fixture
def mock_proposal():
    return ProposerAnalysis(
        provider="groq",
        model="llama-3.3-70b-versatile",
        risk_score=45,
        executive_summary="Moderate exposure detected.",
        findings=[
            Finding(
                title="HTTP without HTTPS redirect",
                severity=RiskLevel.MEDIUM,
                description="Port 80 is open.",
                affected_assets=["1.2.3.4:80"],
                recommendation="Enable HTTPS redirect.",
            )
        ],
        recommendations=["Enable HTTPS redirect"],
        confidence=0.8,
    )


class TestAIAnalyst:
    def test_analyze_success(self, analyst, scan_result, mock_analysis):
        with patch.object(analyst.provider, "call", return_value=mock_analysis):
            result = analyst.analyze(scan_result)
            assert isinstance(result, AIAnalysis)
            assert result.risk_score == 45
            assert len(result.findings) == 1

    def test_analyze_minimal(self, analyst, mock_analysis):
        scan = ScanResult(target="8.8.8.8", input_type=InputType.IP)
        with patch.object(analyst.provider, "call", return_value=mock_analysis):
            result = analyst.analyze(scan)
            assert isinstance(result, AIAnalysis)

    def test_build_context(self, analyst, scan_result):
        context = analyst._build_context(scan_result)
        assert "example.com" in context
        assert "www.example.com" in context
        assert "1.2.3.4" in context
        assert "80" in context

    def test_risk_score_range(self, mock_analysis):
        assert 0 <= mock_analysis.risk_score <= 100

    def test_groq_error(self, analyst, scan_result):
        with patch.object(analyst.provider, "call", side_effect=Exception("API error")):
            result = analyst.analyze(scan_result)
            assert isinstance(result, AIAnalysis)
            assert result.risk_score == 0
            assert "failed" in result.executive_summary.lower() or "error" in result.executive_summary.lower()


class TestMoAPropose:
    def test_propose_success(self, analyst, mock_proposal):
        with patch.object(analyst.provider, "call", return_value=mock_proposal):
            result = analyst.propose(
                provider="groq",
                model="llama-3.3-70b-versatile",
                system_prompt=PROPOSER_PROMPT,
                context="test context",
            )
            assert isinstance(result, ProposerAnalysis)
            assert result.provider == "groq"
            assert result.confidence == 0.8

    def test_propose_sets_provider(self, analyst, mock_proposal):
        mock_proposal.provider = "wrong"
        with patch.object(analyst.provider, "call", return_value=mock_proposal):
            result = analyst.propose(
                provider="openai",
                model="gpt-4o-mini",
                system_prompt=PROPOSER_PROMPT,
                context="test",
            )
            assert result.provider == "openai"
            assert result.model == "gpt-4o-mini"


class TestMoAAggregate:
    def test_aggregate_success(self, analyst, mock_analysis):
        proposals = [
            ProposerAnalysis(
                provider="groq", model="llama", risk_score=40,
                executive_summary="Low risk.", findings=[], recommendations=[], confidence=0.8,
            ),
            ProposerAnalysis(
                provider="openai", model="gpt-4o", risk_score=50,
                executive_summary="Moderate risk.", findings=[], recommendations=[], confidence=0.9,
            ),
        ]
        with patch.object(analyst.provider, "call", return_value=mock_analysis):
            with patch.object(analyst.provider, "get_available_providers", return_value=["groq"]):
                result = analyst.aggregate(proposals, "test context")
                assert isinstance(result, AIAnalysis)
                assert result.proposer_count == 2

    def test_aggregate_formats_proposals(self, analyst):
        proposals = [
            ProposerAnalysis(
                provider="groq", model="llama", risk_score=40,
                executive_summary="Summary A.",
                findings=[Finding(title="F1", severity=RiskLevel.HIGH, description="D1",
                                  affected_assets=[], recommendation="R1")],
                recommendations=["R1"], confidence=0.7,
            ),
        ]
        text = analyst._format_proposals_for_aggregator(proposals)
        assert "groq" in text
        assert "Summary A" in text
        assert "F1" in text


class TestMoAReflect:
    def test_reflect_success(self, analyst, mock_analysis):
        mock_analysis.analysis_version = 1
        improved = AIAnalysis(
            risk_score=42, executive_summary="Improved.", attack_surface_size="Small",
            findings=[], exposed_services_summary="Better.", recommendations=[],
        )
        with patch.object(analyst.provider, "call", return_value=improved):
            with patch.object(analyst.provider, "get_available_providers", return_value=["groq"]):
                result = analyst.reflect(mock_analysis, "context")
                assert isinstance(result, AIAnalysis)
                assert result.analysis_version == 2

    def test_reflect_increments_version(self, analyst, mock_analysis):
        mock_analysis.analysis_version = 3
        improved = AIAnalysis(
            risk_score=42, executive_summary="V4.", attack_surface_size="S",
            findings=[], exposed_services_summary="S.", recommendations=[],
        )
        with patch.object(analyst.provider, "call", return_value=improved):
            with patch.object(analyst.provider, "get_available_providers", return_value=["groq"]):
                result = analyst.reflect(mock_analysis, "ctx")
                assert result.analysis_version == 4


class TestAIAnalysisModel:
    def test_new_fields_defaults(self):
        a = AIAnalysis(
            risk_score=50, executive_summary="Test", attack_surface_size="Medium",
            findings=[], exposed_services_summary="Test", recommendations=[],
        )
        assert a.confidence_score == 0.0
        assert a.analysis_version == 1
        assert a.proposer_count == 1
        assert a.consensus_level == "single"

    def test_new_fields_set(self):
        a = AIAnalysis(
            risk_score=50, executive_summary="Test", attack_surface_size="Medium",
            findings=[], exposed_services_summary="Test", recommendations=[],
            confidence_score=0.85, analysis_version=2, proposer_count=3,
            consensus_level="high",
        )
        assert a.confidence_score == 0.85
        assert a.analysis_version == 2
        assert a.proposer_count == 3
        assert a.consensus_level == "high"
