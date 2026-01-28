"""Parse wpscan JSON output into structured records."""

from __future__ import annotations

import json
import logging

from core.models import TechnologyRecord, VulnerabilityRecord, VulnSeverity

logger = logging.getLogger(__name__)


def parse_wpscan_json(json_output: str) -> dict:
    """Parse wpscan JSON output.

    Args:
        json_output: Raw JSON string from wpscan --format json.

    Returns:
        Dict with keys: vulnerabilities, technologies.
    """
    vulnerabilities: list[VulnerabilityRecord] = []
    technologies: list[TechnologyRecord] = []

    try:
        data = json.loads(json_output)
    except json.JSONDecodeError as exc:
        logger.error("Failed to parse wpscan JSON: %s", exc)
        return {"vulnerabilities": vulnerabilities, "technologies": technologies}

    if not isinstance(data, dict):
        return {"vulnerabilities": vulnerabilities, "technologies": technologies}

    target_url = data.get("target_url", "")

    # WordPress version
    version_data = data.get("version", {})
    if isinstance(version_data, dict) and version_data.get("number"):
        technologies.append(TechnologyRecord(
            name="WordPress",
            version=version_data["number"],
            category="cms",
        ))
        for vuln in version_data.get("vulnerabilities", []):
            vulnerabilities.append(_parse_wp_vuln(vuln, target_url))

    # Main theme
    main_theme = data.get("main_theme", {})
    if isinstance(main_theme, dict):
        theme_name = main_theme.get("slug", "")
        theme_version = main_theme.get("version", {})
        if isinstance(theme_version, dict):
            theme_version = theme_version.get("number", "")
        if theme_name:
            technologies.append(TechnologyRecord(
                name=f"WP Theme: {theme_name}",
                version=str(theme_version) if theme_version else None,
                category="wordpress-theme",
            ))
        for vuln in main_theme.get("vulnerabilities", []):
            vulnerabilities.append(_parse_wp_vuln(vuln, target_url))

    # Plugins
    plugins = data.get("plugins", {})
    if isinstance(plugins, dict):
        for plugin_slug, plugin_data in plugins.items():
            if not isinstance(plugin_data, dict):
                continue
            version_info = plugin_data.get("version", {})
            plugin_version = None
            if isinstance(version_info, dict):
                plugin_version = version_info.get("number")

            technologies.append(TechnologyRecord(
                name=f"WP Plugin: {plugin_slug}",
                version=plugin_version,
                category="wordpress-plugin",
            ))

            for vuln in plugin_data.get("vulnerabilities", []):
                vulnerabilities.append(_parse_wp_vuln(vuln, target_url))

    return {"vulnerabilities": vulnerabilities, "technologies": technologies}


def _parse_wp_vuln(vuln_data: dict, target_url: str) -> VulnerabilityRecord:
    """Parse a single wpscan vulnerability entry."""
    title = vuln_data.get("title", "Unknown WP Vulnerability")

    references = []
    ref_data = vuln_data.get("references", {})
    if isinstance(ref_data, dict):
        for ref_type, ref_list in ref_data.items():
            if isinstance(ref_list, list):
                references.extend(str(r) for r in ref_list)

    # Look for CVE in references
    cve_refs = [r for r in references if "CVE" in r.upper()]
    vuln_id = vuln_data.get("id")
    if not vuln_id and cve_refs:
        vuln_id = cve_refs[0]

    # Determine severity from CVSS or default
    cvss = None
    cvss_data = vuln_data.get("cvss", {})
    if isinstance(cvss_data, dict):
        score = cvss_data.get("score")
        if score:
            try:
                cvss = float(score)
            except (ValueError, TypeError):
                pass

    severity = VulnSeverity.MEDIUM
    if cvss is not None:
        if cvss >= 9.0:
            severity = VulnSeverity.CRITICAL
        elif cvss >= 7.0:
            severity = VulnSeverity.HIGH
        elif cvss >= 4.0:
            severity = VulnSeverity.MEDIUM
        else:
            severity = VulnSeverity.LOW

    return VulnerabilityRecord(
        vuln_id=str(vuln_id) if vuln_id else None,
        title=title,
        severity=severity,
        affected_url=target_url or None,
        scanner="wpscan",
        references=references,
        cvss=cvss,
    )
