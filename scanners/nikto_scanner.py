"""Nikto web vulnerability scanner."""

from __future__ import annotations

from scanners.base import BaseActiveScanner
from scanners.output_parsers.nikto_parser import parse_nikto_json
from core.models import ActiveScannerResult


class NiktoScanner(BaseActiveScanner):
    TOOL_NAME = "nikto"
    BINARY_NAME = "nikto"

    def build_command(self, target: str, context: dict) -> list[str]:
        binary = self.get_binary_path()

        url = target
        if not url.startswith(("http://", "https://")):
            url = f"http://{target}"

        cmd = [
            binary,
            "-h", url,
            "-Format", "json",
            "-output", "-",
            "-nointeractive",
        ]

        return cmd

    def parse_output(
        self, stdout: str, stderr: str, return_code: int
    ) -> ActiveScannerResult:
        # nikto outputs JSON to stdout when -output - is used
        output_text = stdout.strip()
        if not output_text:
            return ActiveScannerResult(
                scanner_name=self.TOOL_NAME,
                success=False,
                error=stderr.strip() or "No output from nikto",
            )

        vulns = parse_nikto_json(output_text)
        return ActiveScannerResult(
            scanner_name=self.TOOL_NAME,
            success=True,
            vulnerabilities=vulns,
        )
