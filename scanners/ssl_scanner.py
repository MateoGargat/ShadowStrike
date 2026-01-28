"""SSL/TLS scanner using sslscan."""

from __future__ import annotations

from scanners.base import BaseActiveScanner
from scanners.output_parsers.sslscan_parser import parse_sslscan_xml
from core.models import ActiveScannerResult


class SSLScanner(BaseActiveScanner):
    TOOL_NAME = "sslscan"
    BINARY_NAME = "sslscan"

    def build_command(self, target: str, context: dict) -> list[str]:
        binary = self.get_binary_path()

        # target can be host:port or just host (defaults to 443)
        host_port = target
        if "://" in host_port:
            # Strip protocol
            host_port = host_port.split("://", 1)[1]
        host_port = host_port.rstrip("/")

        cmd = [
            binary,
            f"--xml=-",
            "--no-colour",
            host_port,
        ]

        return cmd

    def parse_output(
        self, stdout: str, stderr: str, return_code: int
    ) -> ActiveScannerResult:
        output_text = stdout.strip()
        if not output_text or "<?xml" not in output_text:
            return ActiveScannerResult(
                scanner_name=self.TOOL_NAME,
                success=False,
                error=stderr.strip() or "No XML output from sslscan",
            )

        ssl_records = parse_sslscan_xml(output_text)
        return ActiveScannerResult(
            scanner_name=self.TOOL_NAME,
            success=True,
            ssl_records=ssl_records,
        )
