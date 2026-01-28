"""Gobuster directory brute-force scanner."""

from __future__ import annotations

from scanners.base import BaseActiveScanner
from scanners.output_parsers.gobuster_parser import parse_gobuster_output
from core.models import ActiveScannerResult


class GobusterScanner(BaseActiveScanner):
    TOOL_NAME = "gobuster"
    BINARY_NAME = "gobuster"

    def build_command(self, target: str, context: dict) -> list[str]:
        binary = self.get_binary_path()
        profile = self._profile

        # Determine target URL
        url = target
        if not url.startswith(("http://", "https://")):
            url = f"http://{target}"

        # Select wordlist
        wordlist = self.config.wordlist_path
        if not wordlist:
            wordlist_name = profile.get("gobuster_wordlist", "common.txt")
            wordlist = f"/usr/share/wordlists/dirb/{wordlist_name}"

        cmd = [
            binary, "dir",
            "-u", url,
            "-w", wordlist,
            "-q",
            "--no-color",
            "-t", "10",
            "--timeout", "10s",
        ]

        return cmd

    def parse_output(
        self, stdout: str, stderr: str, return_code: int
    ) -> ActiveScannerResult:
        # gobuster may return non-zero even with results
        records = parse_gobuster_output(stdout)
        return ActiveScannerResult(
            scanner_name=self.TOOL_NAME,
            success=True,
            web_directories=records,
        )
