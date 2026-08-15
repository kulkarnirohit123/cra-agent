"""Trivy scanner — comprehensive vulnerability scanner.

Trivy by Aqua Security scans:
- Container images
- Filesystems
- Git repositories
- Dependencies (multiple ecosystems)
- Misconfigurations (IaC)
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


class TrivyScanner(BaseScanner):
    """Comprehensive vulnerability scanner using Trivy.

    Trivy can scan:
    - Dependencies (Python, Node.js, Go, Ruby, Rust, etc.)
    - Container images
    - Filesystems
    - Git repositories
    - Infrastructure as Code (Terraform, Dockerfile, K8s)
    """

    def __init__(
        self,
        repo_path: Path,
        severity_threshold: Severity = Severity.MEDIUM,
        trivy_path: str = "trivy",
        scan_type: str = "fs",  # fs, image, repo, config
    ) -> None:
        """Initialize the Trivy scanner.

        Args:
            repo_path: Path to the git repository.
            severity_threshold: Minimum severity to report.
            trivy_path: Path to trivy executable.
            scan_type: Type of scan (fs, image, repo, config).
        """
        super().__init__(repo_path, severity_threshold)
        self.trivy_path = trivy_path
        self.scan_type = scan_type

    def name(self) -> str:
        """Return scanner identifier."""
        return "trivy"

    def is_applicable(self, files: list[FileChange]) -> bool:
        """Trivy can scan any repository."""
        return True

    async def scan(self, files: list[FileChange]) -> list[Finding]:
        """Run Trivy scan on the repository.

        Args:
            files: List of file changes (used for context).

        Returns:
            List of findings.
        """
        findings: list[Finding] = []

        try:
            # Build trivy command
            cmd = [
                self.trivy_path,
                self.scan_type,
                "--format",
                "json",
                "--severity",
                "LOW,MEDIUM,HIGH,CRITICAL",
                "--scanners",
                "vuln,config,secret",
                str(self.repo_path),
            ]

            result = await asyncio.to_thread(
                subprocess.run,
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
            )

            if result.stdout:
                try:
                    trivy_data = json.loads(result.stdout)
                    findings = self._parse_trivy_output(trivy_data, files)
                except json.JSONDecodeError:
                    logger.warning("Failed to parse Trivy JSON output")

        except subprocess.TimeoutExpired:
            logger.error("Trivy scan timeout")
        except FileNotFoundError:
            logger.warning("Trivy not found. Install with: brew install trivy")
        except Exception as e:
            logger.error("Trivy scan failed", error=str(e))

        return findings

    def _parse_trivy_output(
        self,
        trivy_data: dict,
        files: list[FileChange],
    ) -> list[Finding]:
        """Parse Trivy JSON output into Finding objects.

        Args:
            trivy_data: Parsed JSON from Trivy.
            files: List of file changes for context.

        Returns:
            List of findings.
        """
        findings: list[Finding] = []

        results = trivy_data.get("Results", [])
        for result in results:
            target = result.get("Target", "")
            vulns = result.get("Vulnerabilities", [])
            misconfigs = result.get("Misconfigurations", [])

            # Process vulnerabilities
            for vuln in vulns or []:
                finding = self._parse_vulnerability(vuln, target, files)
                if finding:
                    findings.append(finding)

            # Process misconfigurations
            for misconfig in misconfigs or []:
                finding = self._parse_misconfiguration(misconfig, target, files)
                if finding:
                    findings.append(finding)

        return findings

    def _parse_vulnerability(
        self,
        vuln: dict,
        target: str,
        files: list[FileChange],
    ) -> Finding | None:
        """Parse a Trivy vulnerability into a Finding.

        Args:
            vuln: Vulnerability data from Trivy.
            target: Target file/path.
            files: List of file changes.

        Returns:
            Finding object or None.
        """
        vuln_id = vuln.get("VulnerabilityID", "")
        pkg_name = vuln.get("PkgName", "")
        installed_version = vuln.get("InstalledVersion", "")
        fixed_version = vuln.get("FixedVersion", "")
        severity_str = vuln.get("Severity", "MEDIUM")
        title = vuln.get("Title", "")
        description = vuln.get("Description", "")

        # Map severity
        severity = self._map_severity(severity_str)

        # Get relative path
        try:
            rel_path = str(Path(target).relative_to(self.repo_path))
        except ValueError:
            rel_path = target

        return Finding(
            id=Finding.generate_id(
                scanner=self.name(),
                vuln_id=vuln_id,
                file_path=rel_path,
                line_start=0,
                commit_hash="",
            ),
            scanner=self.name(),
            vuln_id=vuln_id,
            title=f"{pkg_name}: {title[:80]}" if title else f"Vulnerable: {pkg_name}",
            description=description[:500] if description else f"Vulnerability in {pkg_name}",
            severity=severity,
            file_path=rel_path,
            line_start=0,
            line_end=0,
            code_snippet=f"{pkg_name}=={installed_version}",
            metadata={
                "package": pkg_name,
                "installed_version": installed_version,
                "fixed_version": fixed_version,
                "cvss_score": vuln.get("CVSS", {}),
            },
            commit_hash="",
        )

    def _parse_misconfiguration(
        self,
        misconfig: dict,
        target: str,
        files: list[FileChange],
    ) -> Finding | None:
        """Parse a Trivy misconfiguration into a Finding.

        Args:
            misconfig: Misconfiguration data from Trivy.
            target: Target file/path.
            files: List of file changes.

        Returns:
            Finding object or None.
        """
        misconfig_id = misconfig.get("ID", "")
        title = misconfig.get("Title", "")
        description = misconfig.get("Description", "")
        severity_str = misconfig.get("Severity", "MEDIUM")
        resolution = misconfig.get("Resolution", "")
        start_line = misconfig.get("CauseMetadata", {}).get("StartLine", 0)
        end_line = misconfig.get("CauseMetadata", {}).get("EndLine", 0)

        severity = self._map_severity(severity_str)

        try:
            rel_path = str(Path(target).relative_to(self.repo_path))
        except ValueError:
            rel_path = target

        return Finding(
            id=Finding.generate_id(
                scanner=self.name(),
                vuln_id=misconfig_id,
                file_path=rel_path,
                line_start=start_line,
                commit_hash="",
            ),
            scanner=self.name(),
            vuln_id=misconfig_id,
            title=f"Misconfig: {title[:80]}",
            description=description[:500] if description else f"Misconfiguration: {title}",
            severity=severity,
            file_path=rel_path,
            line_start=start_line,
            line_end=end_line,
            code_snippet="",
            metadata={
                "type": "misconfiguration",
                "resolution": resolution,
            },
            commit_hash="",
        )

    def _map_severity(self, severity_str: str) -> Severity:
        """Map Trivy severity to our Severity enum."""
        severity_map = {
            "CRITICAL": Severity.CRITICAL,
            "HIGH": Severity.HIGH,
            "MEDIUM": Severity.MEDIUM,
            "LOW": Severity.LOW,
        }
        return severity_map.get(severity_str.upper(), Severity.MEDIUM)
