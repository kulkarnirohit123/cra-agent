"""Scanner Agent — coordinates all vulnerability scanners.

This agent runs all configured scanners on commit diffs and aggregates
the findings into a unified list.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from src.core.diff_analyzer import DiffAnalyzer
from src.core.models import FileChange, Finding
from src.scanners.dependency_scanner import DependencyScanner
from src.scanners.sast_scanner import SASTScanner
from src.scanners.secrets_scanner import SecretsScanner
from src.scanners.suppression_store import SuppressionStore
from src.utils.logger import get_logger

if TYPE_CHECKING:
    from pathlib import Path

logger = get_logger(__name__)


class ScannerAgent:
    """Coordinates all vulnerability scanners.

    Responsibilities:
    - Initialize and configure all scanners
    - Run scanners on commit diffs
    - Aggregate findings from all scanners
    - Apply initial filtering (severity threshold)
    """

    def __init__(
        self,
        repo_path: Path,
        suppression_store: SuppressionStore,
        enabled_scanners: list[str] | None = None,
    ) -> None:
        """Initialize the scanner agent.

        Args:
            repo_path: Path to the git repository.
            suppression_store: Suppression rules store.
            enabled_scanners: List of scanner names to enable.
        """
        self.repo_path = repo_path
        self.suppression_store = suppression_store
        self.diff_analyzer = DiffAnalyzer(repo_path)

        # Initialize scanners
        self.scanners = self._initialize_scanners(enabled_scanners)

        logger.info(
            "Scanner agent initialized",
            scanners=[s.name() for s in self.scanners],
        )

    def _initialize_scanners(self, enabled: list[str] | None) -> list:
        """Initialize configured scanners.

        Args:
            enabled: List of scanner names to enable.

        Returns:
            List of initialized scanner instances.
        """
        if enabled is None:
            enabled = ["dependency", "sast", "secrets"]

        scanners = []

        if "dependency" in enabled:
            scanners.append(DependencyScanner(repo_path=self.repo_path))

        if "sast" in enabled:
            scanners.append(SASTScanner(repo_path=self.repo_path))

        if "secrets" in enabled:
            scanners.append(SecretsScanner(repo_path=self.repo_path))

        return scanners

    async def scan_commit(
        self,
        commit_info: dict[str, Any],
        changed_files: list[dict[str, Any]],
    ) -> list[Finding]:
        """Scan a commit for vulnerabilities.

        Args:
            commit_info: Commit information dict.
            changed_files: List of file change dicts.

        Returns:
            List of findings from all scanners.
        """
        commit_hash = commit_info.get("hash", "")
        logger.info("Scanning commit", commit=commit_hash[:7])

        # Convert dicts to FileChange objects
        file_changes = [FileChange(**f) for f in changed_files]

        # Run all scanners concurrently
        all_findings: list[Finding] = []

        for scanner in self.scanners:
            try:
                findings = await scanner.run(file_changes)

                # Set commit hash on all findings
                for finding in findings:
                    finding.commit_hash = commit_hash

                all_findings.extend(findings)

                logger.info(
                    "Scanner completed",
                    scanner=scanner.name(),
                    findings=len(findings),
                )

            except Exception as e:
                logger.error(
                    "Scanner failed",
                    scanner=scanner.name(),
                    error=str(e),
                )

        logger.info(
            "Scan completed",
            commit=commit_hash[:7],
            total_findings=len(all_findings),
        )

        return all_findings

    async def scan_files(self, file_paths: list[str]) -> list[Finding]:
        """Scan specific files (not tied to a commit).

        Args:
            file_paths: List of file paths to scan.

        Returns:
            List of findings.
        """
        # Create FileChange objects for the files
        file_changes = []
        for file_path in file_paths:
            full_path = self.repo_path / file_path
            if full_path.exists():
                file_content = full_path.read_text()
                file_changes.append(
                    FileChange(
                        file_path=file_path,
                        change_type="modified",
                        file_content=file_content,
                    )
                )

        # Run scanners
        all_findings: list[Finding] = []
        for scanner in self.scanners:
            findings = await scanner.run(file_changes)
            all_findings.extend(findings)

        return all_findings