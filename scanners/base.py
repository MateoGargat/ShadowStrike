"""Abstract base class for active scanners using subprocess execution."""

from __future__ import annotations

import abc
import asyncio
import logging
import shutil
import time
from typing import Callable, Optional

from core.models import ActiveScanConfig, ActiveScannerResult, ToolInfo
from scanners.profiles import get_profile

logger = logging.getLogger(__name__)


class BaseActiveScanner(abc.ABC):
    """Abstract base for all active security scanners.

    Subclasses must define TOOL_NAME and BINARY_NAME, and implement
    build_command() and parse_output().
    """

    TOOL_NAME: str = "unknown"
    BINARY_NAME: str = "unknown"

    def __init__(
        self,
        config: ActiveScanConfig,
        output_callback: Optional[Callable[[str], None]] = None,
    ):
        self.config = config
        self.output_callback = output_callback
        self._profile = get_profile(config.intensity)

    @abc.abstractmethod
    def build_command(self, target: str, context: dict) -> list[str]:
        """Build the command-line arguments for this scanner.

        Args:
            target: The target to scan (domain, IP, URL).
            context: Results from previous scan phases.

        Returns:
            List of command-line arguments (including the binary).
        """

    @abc.abstractmethod
    def parse_output(
        self, stdout: str, stderr: str, return_code: int
    ) -> ActiveScannerResult:
        """Parse the tool's output into structured results.

        Args:
            stdout: Standard output from the process.
            stderr: Standard error from the process.
            return_code: Process exit code.

        Returns:
            Structured scanner result.
        """

    def get_timeout(self) -> int:
        """Get the timeout for this scanner based on the profile."""
        return self.config.scanner_timeout or self._profile.get("default_timeout", 600)

    def get_binary_path(self) -> Optional[str]:
        """Get the binary path, using custom path if set."""
        attr_name = f"{self.TOOL_NAME}_path"
        custom_path = getattr(self.config, attr_name, None)
        if custom_path:
            return custom_path
        return shutil.which(self.BINARY_NAME)

    @classmethod
    def detect_tool(cls) -> ToolInfo:
        """Detect if this tool is installed on the system."""
        from scanners.tool_detector import detect_tool
        return detect_tool(cls.TOOL_NAME)

    async def scan(self, target: str, context: Optional[dict] = None) -> ActiveScannerResult:
        """Execute the scanner against a target.

        Args:
            target: The target to scan.
            context: Optional context from previous phases.

        Returns:
            Structured scanner result.
        """
        context = context or {}
        binary = self.get_binary_path()

        if not binary:
            return ActiveScannerResult(
                scanner_name=self.TOOL_NAME,
                success=False,
                error=f"{self.BINARY_NAME} not found on system",
            )

        try:
            cmd = self.build_command(target, context)
        except Exception as exc:
            return ActiveScannerResult(
                scanner_name=self.TOOL_NAME,
                success=False,
                error=f"Failed to build command: {exc}",
            )

        cmd_display = " ".join(cmd)
        logger.info("[%s] Running: %s", self.TOOL_NAME, cmd_display)

        start_time = time.time()
        timeout = self.get_timeout()

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            try:
                stdout_bytes, stderr_bytes = await asyncio.wait_for(
                    process.communicate(),
                    timeout=timeout,
                )
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                duration = time.time() - start_time
                return ActiveScannerResult(
                    scanner_name=self.TOOL_NAME,
                    success=False,
                    error=f"Timed out after {timeout}s",
                    duration_seconds=duration,
                    command_executed=cmd_display,
                )

            duration = time.time() - start_time
            stdout_str = stdout_bytes.decode("utf-8", errors="replace")
            stderr_str = stderr_bytes.decode("utf-8", errors="replace")
            return_code = process.returncode or 0

            if self.output_callback:
                self.output_callback(stdout_str)

            logger.info(
                "[%s] Completed in %.1fs (rc=%d)",
                self.TOOL_NAME, duration, return_code,
            )

            result = self.parse_output(stdout_str, stderr_str, return_code)
            result.duration_seconds = duration
            result.command_executed = cmd_display
            return result

        except FileNotFoundError:
            return ActiveScannerResult(
                scanner_name=self.TOOL_NAME,
                success=False,
                error=f"{self.BINARY_NAME} binary not found at execution time",
            )
        except Exception as exc:
            duration = time.time() - start_time
            logger.error("[%s] Error: %s", self.TOOL_NAME, exc)
            return ActiveScannerResult(
                scanner_name=self.TOOL_NAME,
                success=False,
                error=f"{type(exc).__name__}: {exc}",
                duration_seconds=duration,
            )
