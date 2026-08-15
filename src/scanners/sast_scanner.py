"""SAST scanner — static application security testing.

Uses semgrep to detect code-level vulnerabilities like SQL injection,
XSS, command injection, insecure cryptography, and more.
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


# File extensions that SAST should scan
SAST_FILE_EXTENSIONS = {
    ".py",
    ".js",
    ".ts",
    ".jsx",
    ".tsx",
    ".java",
    ".go",
    ".rb",
    ".php",
    ".c",
    ".cpp",
    ".h",
    ".hpp",
    ".rs",
    ".swift",
    ".kt",
    ".scala",
}

# Directories to exclude from scanning
EXCLUDE_DIRS = {
    "node_modules",
    "vendor",
    "dist",
    "build",
    ".git",
    "__pycache__",
    ".venv",
    "venv",
    "env",
}


class SASTScanner(BaseScanner):
    """Static Application Security Testing scanner using semgrep.

    Detects code-level vulnerabilities including:
    - SQL injection
    - Cross-site scripting (XSS)
    - Command injection
    - Path traversal
    - Insecure cryptography
    - Hardcoded credentials
    - Unsafe deserialization
    """

    def __init__(
        self,
        repo_path: Path,
        severity_threshold: Severity = Severity.MEDIUM,
        semgrep_path: str = "semgrep",
        rulesets: list[str] | None = None,
    ) -> None:
        """Initialize the SAST scanner.

        Args:
            repo_path: Path to the git repository.
            severity_threshold: Minimum severity to report.
            semgrep_path: Path to semgrep executable.
            rulesets: List of semgrep rulesets to use.
        """
        super().__init__(repo_path, severity_threshold)
        self.semgrep_path = semgrep_path
        self.rulesets = rulesets or ["p/owasp-top-ten", "p/cwe-top-25"]

    def name(self) -> str:
        """Return scanner identifier."""
        return "sast"

    def is_applicable(self, files: list[FileChange]) -> bool:
        """Check if any changed files are code files that SAST can scan."""
        for file_change in files:
            if file_change.file_extension in SAST_FILE_EXTENSIONS:
                # Check if file is in excluded directory
                if not self._is_excluded(file_change.file_path):
                    return True
        return False

    def _is_excluded(self, file_path: str) -> bool:
        """Check if file path is in an excluded directory.

        Args:
            file_path: Path to check.

        Returns:
            True if file should be excluded.
        """
        path_parts = Path(file_path).parts
        return any(part in EXCLUDE_DIRS for part in path_parts)

    async def scan(self, files: list[FileChange]) -> list[Finding]:
        """Run semgrep on changed code files.

        Args:
            files: List of file changes to scan.

        Returns:
            List of vulnerability findings.
        """
        findings: list[Finding] = []

        # Filter to scannable files
        scannable_files = [
            f for f in files if f.file_extension in SAST_FILE_EXTENSIONS and not self._is_excluded(f.file_path)
        ]

        if not scannable_files:
            return findings

        # Get list of file paths to scan
        file_paths = [str(self.repo_path / f.file_path) for f in scannable_files]

        try:
            # Build semgrep command
            cmd = [
                self.semgrep_path,
                "--json",
                "--quiet",
                "--no-git-ignore",
            ]

            # Add rulesets
            for ruleset in self.rulesets:
                cmd.extend(["--config", ruleset])

            # Add files to scan
            cmd.extend(file_paths)

            # Run semgrep
            result = await asyncio.to_thread(
                subprocess.run,
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
                cwd=str(self.repo_path),
            )

            # Parse output (semgrep returns non-zero if findings exist)
            if result.stdout:
                semgrep_data = json.loads(result.stdout)
                findings = self._parse_semgrep_output(semgrep_data, scannable_files)

        except subprocess.TimeoutExpired:
            logger.error("semgrep timeout", files=len(file_paths))
        except Exception as e:
            logger.error("semgrep failed", error=str(e))

        return findings

    def _parse_semgrep_output(
        self,
        semgrep_data: dict,
        files: list[FileChange],
    ) -> list[Finding]:
        """Parse semgrep JSON output into Finding objects.

        Args:
            semgrep_data: Parsed JSON from semgrep.
            files: List of file changes for context.

        Returns:
            List of findings.
        """
        findings: list[Finding] = []

        # Create a lookup for file changes
        file_lookup = {f.file_path: f for f in files}

        results = semgrep_data.get("results", [])
        for result in results:
            # Extract finding details
            check_id = result.get("check_id", "")
            path = result.get("path", "")
            start_line = result.get("start", {}).get("line", 0)
            end_line = result.get("end", {}).get("line", 0)
            message = result.get("extra", {}).get("message", "")
            severity_str = result.get("extra", {}).get("severity", "WARNING")
            code_snippet = result.get("extra", {}).get("lines", "")
            metadata = result.get("extra", {}).get("metadata", {})

            # Map semgrep severity to our Severity enum
            severity = self._map_semgrep_severity(severity_str)

            # Get relative path
            try:
                rel_path = str(Path(path).relative_to(self.repo_path))
            except ValueError:
                rel_path = path

            # Get file change for commit hash
            file_change = file_lookup.get(rel_path)
            commit_hash = ""
            if file_change:
                commit_hash = file_change.file_path  # placeholder

            # Extract CWE/CVE from metadata
            vuln_id = None
            cwe_ids = metadata.get("cwe", [])
            if cwe_ids:
                vuln_id = cwe_ids[0] if isinstance(cwe_ids, list) else cwe_ids

            finding = Finding(
                id=Finding.generate_id(
                    scanner=self.name(),
                    vuln_id=vuln_id or check_id,
                    file_path=rel_path,
                    line_start=start_line,
                    commit_hash=commit_hash,
                ),
                scanner=self.name(),
                vuln_id=vuln_id,
                title=f"{check_id}: {message[:100]}",
                description=message,
                severity=severity,
                file_path=rel_path,
                line_start=start_line,
                line_end=end_line,
                code_snippet=code_snippet,
                metadata={
                    "check_id": check_id,
                    "semgrep_metadata": metadata,
                },
                commit_hash=commit_hash,
            )
            findings.append(finding)

        return findings

    def _map_semgrep_severity(self, severity_str: str) -> Severity:
        """Map semgrep severity string to Severity enum.

        Args:
            severity_str: Semgrep severity (ERROR, WARNING, INFO).

        Returns:
            Mapped Severity level.
        """
        severity_map = {
            "ERROR": Severity.HIGH,
            "WARNING": Severity.MEDIUM,
            "INFO": Severity.LOW,
        }
        return severity_map.get(severity_str.upper(), Severity.MEDIUM)
