"""Nuclei vulnerability scanner using templates."""

from __future__ import annotations

from scanners.base import BaseActiveScanner
from scanners.output_parsers.nuclei_parser import parse_nuclei_jsonl
from core.models import ActiveScannerResult


class NucleiScanner(BaseActiveScanner):
    TOOL_NAME = "nuclei"
    BINARY_NAME = "nuclei"

    def build_command(self, target: str, context: dict) -> list[str]:
        binary = self.get_binary_path()
        profile = self._profile

        url = target
        if not url.startswith(("http://", "https://")):
            url = f"http://{target}"

        severity = profile.get("nuclei_severity", "high,critical")

        cmd = [
            binary,
            "-target", url,
            "-jsonl",
            "-severity", severity,
            "-silent",
            "-no-color",
        ]

        return cmd

    def parse_output(
        self, stdout: str, stderr: str, return_code: int
    ) -> ActiveScannerResult:
        output_text = stdout.strip()
        if not output_text:
            # nuclei with no findings still returns 0
            return ActiveScannerResult(
                scanner_name=self.TOOL_NAME,
                success=True,
                vulnerabilities=[],
            )

        vulns = parse_nuclei_jsonl(output_text)
        return ActiveScannerResult(
            scanner_name=self.TOOL_NAME,
            success=True,
            vulnerabilities=vulns,
        )
