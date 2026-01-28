"""Parse nuclei JSONL output into structured records."""

from __future__ import annotations

import json
import logging
import re

from core.models import VulnerabilityRecord, VulnSeverity

logger = logging.getLogger(__name__)

_SEVERITY_MAP: dict[str, VulnSeverity] = {
    "critical": VulnSeverity.CRITICAL,
    "high": VulnSeverity.HIGH,
    "medium": VulnSeverity.MEDIUM,
    "low": VulnSeverity.LOW,
    "info": VulnSeverity.INFO,
    "unknown": VulnSeverity.UNKNOWN,
}


def parse_nuclei_jsonl(jsonl_output: str) -> list[VulnerabilityRecord]:
    """Parse nuclei JSONL output.

    Args:
        jsonl_output: Raw JSONL string from nuclei -jsonl.

    Returns:
        List of VulnerabilityRecord entries.
    """
    records: list[VulnerabilityRecord] = []

    for line in jsonl_output.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue

        if not isinstance(entry, dict):
            continue

        template_id = entry.get("template-id", entry.get("templateID", ""))
        info = entry.get("info", {})
        if not isinstance(info, dict):
            info = {}

        name = info.get("name", template_id)
        severity_str = info.get("severity", "unknown").lower()
        severity = _SEVERITY_MAP.get(severity_str, VulnSeverity.UNKNOWN)

        matched_at = entry.get("matched-at", entry.get("matched", ""))
        host = entry.get("host", "")

        # Extract references
        references = []
        ref_data = info.get("reference", [])
        if isinstance(ref_data, list):
            references = [str(r) for r in ref_data if r]
        elif isinstance(ref_data, str) and ref_data:
            references = [ref_data]

        # Extract classification
        classification = info.get("classification", {})
        if isinstance(classification, dict):
            cve_id = classification.get("cve-id")
            if isinstance(cve_id, list):
                references.extend(cve_id)
            elif isinstance(cve_id, str) and cve_id:
                references.append(cve_id)

            cvss_metrics = classification.get("cvss-score")
            cvss = None
            if cvss_metrics:
                try:
                    cvss = float(cvss_metrics)
                except (ValueError, TypeError):
                    pass
        else:
            cvss = None

        description = info.get("description", "")

        # Deduplicate references
        references = list(dict.fromkeys(references))

        vuln_id = None
        cve_refs = [r for r in references if r.startswith("CVE-")]
        if cve_refs:
            vuln_id = cve_refs[0]
        elif template_id:
            vuln_id = template_id

        records.append(VulnerabilityRecord(
            vuln_id=vuln_id,
            title=name,
            severity=severity,
            affected_host=host or None,
            affected_url=matched_at or None,
            scanner="nuclei",
            references=references,
            cvss=cvss,
            description=description[:500] if description else None,
        ))

    return records
