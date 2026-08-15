"""Bandit scanner — Python-specific security linter.

Bandit is a tool designed to find common security issues in Python code.
It processes each file and builds an Abstract Syntax Tree (AST) to check
for security issues.
"""

from __future__ import annotations

import asyncio
import json
import subprocess
from pathlib import Path
from typing import TYPE_CHECKING

from src.core.models import FileChange, Finding, Severity
from src.scanners.base_scanner import BaseScanner
from src.utils.logger import get_logger

if TYPE_CHECKING:
    pass

logger = get_logger(__name__)


# Python file extensions
PYTHON_EXTENSIONS = {".py", ".pyw", ".pyi"}


class BanditScanner(BaseScanner):
    """Python security linter using Bandit.

    Bandit detects common security issues in Python code:
    - Hardcoded passwords
    - SQL injection
    - Shell injection
    - Use of insecure functions
    - Weak cryptography
    - Unsafe YAML loading
    - And more...
    """

    def __init__(
        self,
        repo_path: Path,
        severity_threshold: Severity = Severity.MEDIUM,
        bandit_path: str = "bandit",
        confidence_threshold: str = "MEDIUM",  # LOW, MEDIUM, HIGH
    ) -> None:
        """Initialize the Bandit scanner.

        Args:
            repo_path: Path to the git repository.
            severity_threshold: Minimum severity to report.
            bandit_path: Path to bandit executable.
            confidence_threshold: Minimum confidence level.
        """
        super().__init__(repo_path, severity_threshold)
        self.bandit_path = bandit_path
        self.confidence_threshold = confidence_threshold

    def name(self) -> str:
        """Return scanner identifier."""
        return "bandit"

    def is_applicable(self, files: list[FileChange]) -> bool:
        """Check if any changed files are Python files."""
        for file_change in files:
            if file_change.file_extension in PYTHON_EXTENSIONS:
                return True
        return False

    async def scan(self, files: list[FileChange]) -> list[Finding]:
        """Run Bandit on Python files.

        Args:
            files: List of file changes to scan.

        Returns:
            List of findings.
        """
        findings: list[Finding] = []

        # Filter to Python files
        python_files = [
            f for f in files
            if f.file_extension in PYTHON_EXTENSIONS
        ]

        if not python_files:
            return findings

        # Get file paths
        file_paths = [str(self.repo_path / f.file_path) for f in python_files]

        try:
            # Build bandit command
            cmd = [
                self.bandit_path,
                "-f", "json",
                "-c", "-",  # Use default config
                "-ll",  # Report only high severity
                "-ii",  # Report only medium+ confidence
            ]
            cmd.extend(file_paths)

            result = await asyncio.to_thread(
                subprocess.run,
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
            )

            # Bandit returns non-zero if issues found, but still outputs JSON
            if result.stdout:
                try:
                    bandit_data = json.loads(result.stdout)
                    findings = self._parse_bandit_output(bandit_data, python_files)
                except json.JSONDecodeError:
                    logger.warning("Failed to parse Bandit JSON output")

        except subprocess.TimeoutExpired:
            logger.error("Bandit scan timeout")
        except FileNotFoundError:
            logger.warning("Bandit not found. Install with: pip install bandit")
        except Exception as e:
            logger.error("Bandit scan failed", error=str(e))

        return findings

    def _parse_bandit_output(
        self,
        bandit_data: dict,
        files: list[FileChange],
    ) -> list[Finding]:
        """Parse Bandit JSON output into Finding objects.

        Args:
            bandit_data: Parsed JSON from Bandit.
            files: List of file changes for context.

        Returns:
            List of findings.
        """
        findings: list[Finding] = []

        # Create file lookup
        file_lookup = {f.file_path: f for f in files}

        results = bandit_data.get("results", [])
        for result in results:
            # Extract finding details
            test_id = result.get("test_id", "")
            test_name = result.get("test_name", "")
            issue_text = result.get("issue_text", "")
            severity_str = result.get("issue_severity", "MEDIUM")
            confidence_str = result.get("issue_confidence", "MEDIUM")
            file_path = result.get("filename", "")
            line_number = result.get("line_number", 0)
            line_range = result.get("line_range", [line_number, line_number])
            code = result.get("code", "")
            more_info = result.get("more_info", "")

            # Map severity
            severity = self._map_severity(severity_str)

            # Get relative path
            try:
                rel_path = str(Path(file_path).relative_to(self.repo_path))
            except ValueError:
                rel_path = file_path

            # Get file change for commit hash
            file_change = file_lookup.get(rel_path)
            commit_hash = ""
            if file_change:
                commit_hash = file_change.file_path  # placeholder

            finding = Finding(
                id=Finding.generate_id(
                    scanner=self.name(),
                    vuln_id=test_id,
                    file_path=rel_path,
                    line_start=line_number,
                    commit_hash=commit_hash,
                ),
                scanner=self.name(),
                vuln_id=test_id,
                title=f"{test_name}: {issue_text[:60]}",
                description=issue_text,
                severity=severity,
                file_path=rel_path,
                line_start=line_range[0] if line_range else line_number,
                line_end=line_range[1] if line_range and len(line_range) > 1 else line_number,
                code_snippet=code,
                metadata={
                    "test_id": test_id,
                    "test_name": test_name,
                    "confidence": confidence_str,
                    "more_info": more_info,
                },
                commit_hash=commit_hash,
            )
            findings.append(finding)

        return findings

    def _map_severity(self, severity_str: str) -> Severity:
        """Map Bandit severity to our Severity enum.

        Bandit uses: LOW, MEDIUM, HIGH
        """
        severity_map = {
            "HIGH": Severity.HIGH,
            "MEDIUM": Severity.MEDIUM,
            "LOW": Severity.LOW,
        }
        return severity_map.get(severity_str.upper(), Severity.MEDIUM)