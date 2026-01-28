"""Nmap port scanner — services, OS detection, NSE scripts."""

from __future__ import annotations

from scanners.base import BaseActiveScanner
from scanners.output_parsers.nmap_parser import parse_nmap_xml
from core.models import ActiveScanConfig, ActiveScannerResult


class NmapScanner(BaseActiveScanner):
    TOOL_NAME = "nmap"
    BINARY_NAME = "nmap"

    def build_command(self, target: str, context: dict) -> list[str]:
        binary = self.get_binary_path()
        profile = self._profile
        cmd = [binary]

        # Port specification
        if self.config.nmap_top_ports:
            cmd.extend(["--top-ports", str(self.config.nmap_top_ports)])
        else:
            ports_spec = profile.get("nmap_ports", "--top-ports 1000")
            cmd.extend(ports_spec.split())

        # Scan flags
        cmd.extend(profile.get("nmap_flags", ["-sV"]))

        # XML output to stdout
        cmd.extend(["-oX", "-"])

        # Target
        cmd.append(target)

        return cmd

    def parse_output(
        self, stdout: str, stderr: str, return_code: int
    ) -> ActiveScannerResult:
        if not stdout.strip() or "<?xml" not in stdout:
            return ActiveScannerResult(
                scanner_name=self.TOOL_NAME,
                success=False,
                error=stderr.strip() or "No XML output from nmap",
            )

        parsed = parse_nmap_xml(stdout)
        return ActiveScannerResult(
            scanner_name=self.TOOL_NAME,
            success=True,
            ports=parsed["ports"],
            technologies=parsed["technologies"],
            os_detections=parsed["os_detections"],
            vulnerabilities=parsed["vulnerabilities"],
        )

    def get_timeout(self) -> int:
        return self.config.scanner_timeout or self._profile.get("nmap_timeout", 600)
