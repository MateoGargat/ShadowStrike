"""wafw00f WAF detection scanner."""

from __future__ import annotations

from scanners.base import BaseActiveScanner
from scanners.output_parsers.wafw00f_parser import parse_wafw00f_json
from core.models import ActiveScannerResult


class Wafw00fScanner(BaseActiveScanner):
    TOOL_NAME = "wafw00f"
    BINARY_NAME = "wafw00f"

    def build_command(self, target: str, context: dict) -> list[str]:
        binary = self.get_binary_path()

        url = target
        if not url.startswith(("http://", "https://")):
            url = f"http://{target}"

        cmd = [
            binary,
            url,
            "-o", "-",
            "-f", "json",
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
                error=stderr.strip() or "No output from wafw00f",
            )

        waf_records = parse_wafw00f_json(output_text)
        return ActiveScannerResult(
            scanner_name=self.TOOL_NAME,
            success=True,
            waf_records=waf_records,
        )
