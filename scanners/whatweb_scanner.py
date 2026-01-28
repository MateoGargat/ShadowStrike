"""WhatWeb active web fingerprinting scanner."""

from __future__ import annotations

from scanners.base import BaseActiveScanner
from scanners.output_parsers.whatweb_parser import parse_whatweb_json
from core.models import ActiveScannerResult


class WhatWebScanner(BaseActiveScanner):
    TOOL_NAME = "whatweb"
    BINARY_NAME = "whatweb"

    def build_command(self, target: str, context: dict) -> list[str]:
        binary = self.get_binary_path()
        profile = self._profile

        url = target
        if not url.startswith(("http://", "https://")):
            url = f"http://{target}"

        aggression = profile.get("whatweb_aggression", "3")

        cmd = [
            binary,
            f"--log-json=-",
            f"-a{aggression}",
            "--no-errors",
            "--color=never",
            url,
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
                error=stderr.strip() or "No output from whatweb",
            )

        technologies = parse_whatweb_json(output_text)
        return ActiveScannerResult(
            scanner_name=self.TOOL_NAME,
            success=True,
            technologies=technologies,
        )
