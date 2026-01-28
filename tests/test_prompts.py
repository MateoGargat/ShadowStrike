"""Tests for analyzers.prompts module."""

import pytest

from analyzers.prompts import (
    AGGREGATOR_PROMPT,
    PROPOSER_DEFENSIVE_PROMPT,
    PROPOSER_OFFENSIVE_PROMPT,
    PROPOSER_PROMPT,
    REFLECTION_PROMPT,
    build_adaptive_prompt,
)
from core.models import (
    InputType,
    ScanResult,
    VulnerabilityRecord,
    VulnSeverity,
    WAFRecord,
    SSLRecord,
)


@pytest.fixture
def basic_scan():
    return ScanResult(
        target="example.com",
        input_type=InputType.DOMAIN,
        sources_used=["crtsh"],
    )


@pytest.fixture
def active_scan():
    return ScanResult(
        target="example.com",
        input_type=InputType.DOMAIN,
        sources_used=["crtsh", "nmap"],
        active_scan_performed=True,
        vulnerabilities=[
            VulnerabilityRecord(
                title="CVE-2024-1234",
                severity=VulnSeverity.HIGH,
                scanner="nuclei",
            ),
        ],
        waf_info=[WAFRecord(host="example.com", detected=True, waf_name="Cloudflare")],
        ssl_info=[
            SSLRecord(host="1.2.3.4", port=443, has_weak_ciphers=True),
        ],
    )


class TestProposerPrompts:
    def test_proposer_prompt_has_scoring(self):
        assert "0-100" in PROPOSER_PROMPT
        assert "Risk Scoring" in PROPOSER_PROMPT

    def test_proposer_prompt_has_severity_levels(self):
        assert "critical" in PROPOSER_PROMPT
        assert "high" in PROPOSER_PROMPT
        assert "medium" in PROPOSER_PROMPT

    def test_offensive_prompt_has_perspective(self):
        assert "RED TEAM" in PROPOSER_OFFENSIVE_PROMPT
        assert "attacker" in PROPOSER_OFFENSIVE_PROMPT

    def test_defensive_prompt_has_perspective(self):
        assert "BLUE TEAM" in PROPOSER_DEFENSIVE_PROMPT
        assert "defensive" in PROPOSER_DEFENSIVE_PROMPT.lower()

    def test_prompts_are_different(self):
        assert PROPOSER_OFFENSIVE_PROMPT != PROPOSER_DEFENSIVE_PROMPT
        assert PROPOSER_PROMPT != PROPOSER_OFFENSIVE_PROMPT


class TestAggregatorPrompt:
    def test_has_placeholders(self):
        assert "{n}" in AGGREGATOR_PROMPT
        assert "{analyses}" in AGGREGATOR_PROMPT

    def test_format_works(self):
        formatted = AGGREGATOR_PROMPT.format(n=3, analyses="Test analyses")
        assert "3" in formatted
        assert "Test analyses" in formatted

    def test_has_consensus_instructions(self):
        assert "consensus" in AGGREGATOR_PROMPT.lower()
        assert "conflict" in AGGREGATOR_PROMPT.lower()


class TestReflectionPrompt:
    def test_has_placeholders(self):
        assert "{analysis}" in REFLECTION_PROMPT
        assert "{context}" in REFLECTION_PROMPT

    def test_has_review_criteria(self):
        assert "hallucination" in REFLECTION_PROMPT.lower()
        assert "missing findings" in REFLECTION_PROMPT.lower()


class TestBuildAdaptivePrompt:
    def test_basic_scan_returns_empty(self, basic_scan):
        result = build_adaptive_prompt(basic_scan)
        assert result == ""

    def test_active_scan_has_section(self, active_scan):
        result = build_adaptive_prompt(active_scan)
        assert "Active Scan Data" in result

    def test_vulnerabilities_mentioned(self, active_scan):
        result = build_adaptive_prompt(active_scan)
        assert "1 confirmed vulnerabilities" in result or "vulnerabilities detected" in result

    def test_waf_mentioned(self, active_scan):
        result = build_adaptive_prompt(active_scan)
        assert "WAF detected" in result

    def test_weak_ssl_mentioned(self, active_scan):
        result = build_adaptive_prompt(active_scan)
        assert "Weak SSL/TLS" in result or "weak" in result.lower()
