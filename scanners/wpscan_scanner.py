"""WPScan WordPress vulnerability scanner."""

from __future__ import annotations

from scanners.base import BaseActiveScanner
from scanners.output_parsers.wpscan_parser import parse_wpscan_json
from core.models import ActiveScannerResult


class WPScanScanner(BaseActiveScanner):
    TOOL_NAME = "wpscan"
    BINARY_NAME = "wpscan"

    def build_command(self, target: str, context: dict) -> list[str]:
        binary = self.get_binary_path()

        url = target
        if not url.startswith(("http://", "https://")):
            url = f"http://{target}"

        cmd = [
            binary,
            "--url", url,
            "--format", "json",
            "--no-banner",
            "--random-user-agent",
        ]

        return cmd

    def parse_output(
        self, stdout: str, stderr: str, return_code: int
    ) -> ActiveScannerResult:
        output_text = stdout.strip()
        if not output_text:
            return ActiveScannerResult(
                scanner_name=self.TOOL_NAME,
                success=False,
                error=stderr.strip() or "No output from wpscan",
            )

        parsed = parse_wpscan_json(output_text)
        return ActiveScannerResult(
            scanner_name=self.TOOL_NAME,
            success=True,
            vulnerabilities=parsed["vulnerabilities"],
            technologies=parsed["technologies"],
        )
