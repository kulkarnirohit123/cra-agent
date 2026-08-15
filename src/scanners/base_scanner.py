"""Base scanner interface — abstract class for all vulnerability scanners.

All scanner implementations must inherit from BaseScanner and implement
the required abstract methods.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

from src.core.models import FileChange, Finding, Severity
from src.utils.logger import get_logger

if TYPE_CHECKING:
    from pathlib import Path

logger = get_logger(__name__)


class BaseScanner(ABC):
    """Abstract base class for vulnerability scanners.

    All scanners must implement:
    - name(): Returns the scanner identifier
    - scan(): Scans files and returns findings
    - is_applicable(): Checks if scanner should run on given files
    """

    def __init__(self, repo_path: Path, severity_threshold: Severity = Severity.MEDIUM) -> None:
        """Initialize the scanner.

        Args:
            repo_path: Path to the git repository.
            severity_threshold: Minimum severity to report.
        """
        self.repo_path = repo_path
        self.severity_threshold = severity_threshold

    @abstractmethod
    def name(self) -> str:
        """Return the scanner identifier.

        Returns:
            Scanner name (e.g., 'dependency', 'sast', 'secrets').
        """
        ...

    @abstractmethod
    async def scan(self, files: list[FileChange]) -> list[Finding]:
        """Scan files and return findings.

        Args:
            files: List of file changes to scan.

        Returns:
            List of findings detected by this scanner.
        """
        ...

    @abstractmethod
    def is_applicable(self, files: list[FileChange]) -> bool:
        """Check if this scanner should run on the given files.

        Args:
            files: List of file changes.

        Returns:
            True if scanner should run, False otherwise.
        """
        ...

    def filter_by_severity(self, findings: list[Finding]) -> list[Finding]:
        """Filter findings by severity threshold.

        Args:
            findings: List of findings to filter.

        Returns:
            Findings that meet or exceed the severity threshold.
        """
        return [f for f in findings if f.severity >= self.severity_threshold]

    async def run(self, files: list[FileChange]) -> list[Finding]:
        """Run the scanner with standard workflow.

        This method:
        1. Checks if scanner is applicable
        2. Runs the scan
        3. Filters by severity
        4. Logs results

        Args:
            files: List of file changes to scan.

        Returns:
            Filtered list of findings.
        """
        if not self.is_applicable(files):
            logger.debug("Scanner not applicable", scanner=self.name())
            return []

        logger.info("Running scanner", scanner=self.name(), files=len(files))

        try:
            raw_findings = await self.scan(files)
            filtered_findings = self.filter_by_severity(raw_findings)

            logger.info(
                "Scanner completed",
                scanner=self.name(),
                raw_findings=len(raw_findings),
                filtered_findings=len(filtered_findings),
            )

            return filtered_findings

        except Exception as e:
            logger.error("Scanner failed", scanner=self.name(), error=str(e))
            return []