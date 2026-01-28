"""ffuf web fuzzer scanner."""

from __future__ import annotations

from scanners.base import BaseActiveScanner
from scanners.output_parsers.ffuf_parser import parse_ffuf_json
from core.models import ActiveScannerResult


class FfufScanner(BaseActiveScanner):
    TOOL_NAME = "ffuf"
    BINARY_NAME = "ffuf"

    def build_command(self, target: str, context: dict) -> list[str]:
        binary = self.get_binary_path()
        profile = self._profile

        url = target
        if not url.startswith(("http://", "https://")):
            url = f"http://{target}"

        # Append FUZZ keyword if not present
        if "FUZZ" not in url:
            url = url.rstrip("/") + "/FUZZ"

        # Select wordlist
        wordlist = self.config.wordlist_path
        if not wordlist:
            wordlist_name = profile.get("gobuster_wordlist", "common.txt")
            wordlist = f"/usr/share/wordlists/dirb/{wordlist_name}"

        cmd = [
            binary,
            "-u", url,
            "-w", wordlist,
            "-of", "json",
            "-o", "-",
            "-s",
            "-mc", "200,201,301,302,307,401,403",
            "-t", "10",
        ]

        return cmd

    def parse_output(
        self, stdout: str, stderr: str, return_code: int
    ) -> ActiveScannerResult:
        output_text = stdout.strip()
        if not output_text:
            return ActiveScannerResult(
                scanner_name=self.TOOL_NAME,
                success=True,
                web_directories=[],
            )

        directories = parse_ffuf_json(output_text)
        return ActiveScannerResult(
            scanner_name=self.TOOL_NAME,
            success=True,
            web_directories=directories,
        )
