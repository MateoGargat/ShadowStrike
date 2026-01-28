"""DNS reconnaissance scanner using dnsrecon."""

from __future__ import annotations

from scanners.base import BaseActiveScanner
from scanners.output_parsers.dnsrecon_parser import parse_dnsrecon_json
from core.models import ActiveScannerResult


class DNSReconScanner(BaseActiveScanner):
    TOOL_NAME = "dnsrecon"
    BINARY_NAME = "dnsrecon"

    def build_command(self, target: str, context: dict) -> list[str]:
        binary = self.get_binary_path()
        profile = self._profile

        # Extract domain — strip protocol/path if present
        domain = target
        if "://" in domain:
            domain = domain.split("://", 1)[1]
        domain = domain.split("/")[0].split(":")[0]

        scan_types = profile.get("dnsrecon_types", "std,axfr")

        cmd = [
            binary,
            "-d", domain,
            "-j", "-",
            "-t", scan_types,
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
                error=stderr.strip() or "No output from dnsrecon",
            )

        dns_records = parse_dnsrecon_json(output_text)
        return ActiveScannerResult(
            scanner_name=self.TOOL_NAME,
            success=True,
            active_dns_records=dns_records,
        )
