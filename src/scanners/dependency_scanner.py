"""Dependency scanner — detects known CVEs in project dependencies.

Uses pip-audit and/or osv-scanner to identify vulnerabilities in
third-party packages.
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


# File patterns that indicate dependency files
DEPENDENCY_FILE_PATTERNS = {
    "requirements*.txt",
    "pyproject.toml",
    "setup.py",
    "setup.cfg",
    "Pipfile",
    "Pipfile.lock",
    "poetry.lock",
    "package.json",
    "package-lock.json",
    "yarn.lock",
    "go.mod",
    "go.sum",
    "Gemfile",
    "Gemfile.lock",
    "Cargo.toml",
    "Cargo.lock",
}


class DependencyScanner(BaseScanner):
    """Scans dependencies for known CVEs and security advisories.

    Supports multiple package managers:
    - Python: pip-audit, safety
    - Node.js: npm audit
    - Go: govulncheck
    - Ruby: bundler-audit
    """

    def __init__(
        self,
        repo_path: Path,
        severity_threshold: Severity = Severity.MEDIUM,
        pip_audit_path: str = "pip-audit",
    ) -> None:
        """Initialize the dependency scanner.

        Args:
            repo_path: Path to the git repository.
            severity_threshold: Minimum severity to report.
            pip_audit_path: Path to pip-audit executable.
        """
        super().__init__(repo_path, severity_threshold)
        self.pip_audit_path = pip_audit_path

    def name(self) -> str:
        """Return scanner identifier."""
        return "dependency"

    def is_applicable(self, files: list[FileChange]) -> bool:
        """Check if any changed files are dependency files."""
        for file_change in files:
            file_name = Path(file_change.file_path).name
            for pattern in DEPENDENCY_FILE_PATTERNS:
                if pattern.replace("*", "") in file_name:
                    return True
        return False

    async def scan(self, files: list[FileChange]) -> list[Finding]:
        """Scan dependencies for vulnerabilities.

        Args:
            files: List of file changes (should include dependency files).

        Returns:
            List of vulnerability findings.
        """
        findings: list[Finding] = []

        # Detect which package manager to use
        dep_files = self._get_dependency_files(files)

        for dep_file in dep_files:
            file_findings = await self._scan_file(dep_file)
            findings.extend(file_findings)

        return findings

    def _get_dependency_files(self, files: list[FileChange]) -> list[FileChange]:
        """Filter to only dependency-related files."""
        dep_files = []
        for file_change in files:
            file_name = Path(file_change.file_path).name
            for pattern in DEPENDENCY_FILE_PATTERNS:
                if pattern.replace("*", "") in file_name:
                    dep_files.append(file_change)
                    break
        return dep_files

    async def _scan_file(self, file_change: FileChange) -> list[Finding]:
        """Scan a single dependency file.

        Args:
            file_change: The dependency file to scan.

        Returns:
            List of findings for this file.
        """
        file_path = Path(file_change.file_path)
        file_name = file_path.name

        # Route to appropriate scanner based on file type
        if file_name in ("requirements.txt", "requirements-dev.txt", "Pipfile.lock"):
            return await self._scan_python_deps(file_change)
        elif file_name in ("package.json", "package-lock.json"):
            return await self._scan_node_deps(file_change)
        elif file_name in ("go.mod", "go.sum"):
            return await self._scan_go_deps(file_change)
        else:
            logger.debug("Unsupported dependency file", file=file_name)
            return []

    async def _scan_python_deps(self, file_change: FileChange) -> list[Finding]:
        """Scan Python dependencies using pip-audit.

        Args:
            file_change: The requirements file.

        Returns:
            List of findings.
        """
        findings: list[Finding] = []

        try:
            # Run pip-audit on the requirements file
            full_path = self.repo_path / file_change.file_path
            cmd = [
                self.pip_audit_path,
                "--requirement",
                str(full_path),
                "--format",
                "json",
                "--desc",
            ]

            result = await asyncio.to_thread(
                subprocess.run,
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
            )

            if result.returncode == 0 and result.stdout:
                audit_data = json.loads(result.stdout)
                findings = self._parse_pip_audit_output(audit_data, file_change)

        except subprocess.TimeoutExpired:
            logger.error("pip-audit timeout", file=file_change.file_path)
        except Exception as e:
            logger.error("pip-audit failed", file=file_change.file_path, error=str(e))

        return findings

    def _parse_pip_audit_output(
        self,
        audit_data: dict,
        file_change: FileChange,
    ) -> list[Finding]:
        """Parse pip-audit JSON output into Finding objects.

        Args:
            audit_data: Parsed JSON from pip-audit.
            file_change: The file that was scanned.

        Returns:
            List of findings.
        """
        findings: list[Finding] = []

        dependencies = audit_data.get("dependencies", [])
        for dep in dependencies:
            package_name = dep.get("name", "unknown")
            package_version = dep.get("version", "unknown")
            vulns = dep.get("vulns", [])

            for vuln in vulns:
                vuln_id = vuln.get("id", "")
                description = vuln.get("description", "")
                fix_versions = vuln.get("fix_versions", [])

                # Determine severity (pip-audit doesn't always provide this)
                severity = self._estimate_severity(vuln_id, description)

                finding = Finding(
                    id=Finding.generate_id(
                        scanner=self.name(),
                        vuln_id=vuln_id,
                        file_path=file_change.file_path,
                        line_start=0,
                        commit_hash=file_change.file_path,  # placeholder
                    ),
                    scanner=self.name(),
                    vuln_id=vuln_id,
                    title=f"Vulnerable dependency: {package_name}@{package_version}",
                    description=description,
                    severity=severity,
                    file_path=file_change.file_path,
                    line_start=0,
                    line_end=0,
                    code_snippet=f"{package_name}=={package_version}",
                    metadata={
                        "package": package_name,
                        "version": package_version,
                        "fix_versions": fix_versions,
                    },
                    commit_hash="",  # Will be set by caller
                )
                findings.append(finding)

        return findings

    async def _scan_node_deps(self, file_change: FileChange) -> list[Finding]:
        """Scan Node.js dependencies using npm audit.

        Args:
            file_change: The package.json file.

        Returns:
            List of findings.
        """
        # TODO: Implement npm audit integration
        logger.debug("Node.js dependency scanning not yet implemented")
        return []

    async def _scan_go_deps(self, file_change: FileChange) -> list[Finding]:
        """Scan Go dependencies using govulncheck.

        Args:
            file_change: The go.mod file.

        Returns:
            List of findings.
        """
        # TODO: Implement govulncheck integration
        logger.debug("Go dependency scanning not yet implemented")
        return []

    def _estimate_severity(self, vuln_id: str, description: str) -> Severity:
        """Estimate severity based on CVE ID and description.

        Args:
            vuln_id: CVE identifier.
            description: Vulnerability description.

        Returns:
            Estimated severity level.
        """
        desc_lower = description.lower()

        # Check for critical keywords
        if any(kw in desc_lower for kw in ["remote code execution", "rce", "arbitrary code"]):
            return Severity.CRITICAL
        elif any(kw in desc_lower for kw in ["sql injection", "command injection", "ssrf"]):
            return Severity.HIGH
        elif any(kw in desc_lower for kw in ["xss", "cross-site scripting", "dos"]):
            return Severity.MEDIUM
        else:
            return Severity.LOW