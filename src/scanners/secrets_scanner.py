"""Secrets scanner — detects hardcoded secrets, API keys, and credentials.

Uses gitleaks to scan for sensitive information that should not be
committed to version control.
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


# Files/patterns to exclude from secrets scanning
SECRETS_EXCLUDE_PATTERNS = {
    ".env.example",
    "*.md",
    "test/fixtures/*",
    "tests/fixtures/*",
    "*.test.*",
    "*.spec.*",
}

# Known safe placeholder patterns
SAFE_PLACEHOLDERS = {
    "EXAMPLE_KEY",
    "YOUR_API_KEY",
    "sk-your-",
    "placeholder",
    "xxx",
    "changeme",
    "TODO",
    "REPLACE_ME",
}


class SecretsScanner(BaseScanner):
    """Detects hardcoded secrets, API keys, and credentials.

    Uses gitleaks to scan for:
    - API keys (AWS, GCP, Azure, etc.)
    - Database connection strings
    - Private keys
    - OAuth tokens
    - Passwords
    - Generic secrets
    """

    def __init__(
        self,
        repo_path: Path,
        severity_threshold: Severity = Severity.HIGH,
        gitleaks_path: str = "gitleaks",
        allowlist: list[str] | None = None,
    ) -> None:
        """Initialize the secrets scanner.

        Args:
            repo_path: Path to the git repository.
            severity_threshold: Minimum severity to report.
            gitleaks_path: Path to gitleaks executable.
            allowlist: List of safe placeholder patterns to ignore.
        """
        super().__init__(repo_path, severity_threshold)
        self.gitleaks_path = gitleaks_path
        self.allowlist = allowlist or list(SAFE_PLACEHOLDERS)

    def name(self) -> str:
        """Return scanner identifier."""
        return "secrets"

    def is_applicable(self, files: list[FileChange]) -> bool:
        """Check if any changed files should be scanned for secrets.

        Secrets scanner runs on all files except excluded patterns.
        """
        for file_change in files:
            if not self._is_excluded(file_change.file_path):
                return True
        return False

    def _is_excluded(self, file_path: str) -> bool:
        """Check if file should be excluded from secrets scanning.

        Args:
            file_path: Path to check.

        Returns:
            True if file should be excluded.
        """
        import fnmatch

        for pattern in SECRETS_EXCLUDE_PATTERNS:
            if fnmatch.fnmatch(file_path, pattern):
                return True
        return False

    async def scan(self, files: list[FileChange]) -> list[Finding]:
        """Run gitleaks on changed files.

        Args:
            files: List of file changes to scan.

        Returns:
            List of secret findings.
        """
        findings: list[Finding] = []

        # Filter to scannable files
        scannable_files = [f for f in files if not self._is_excluded(f.file_path)]

        if not scannable_files:
            return findings

        try:
            # Run gitleaks on the repository (it will scan git history)
            cmd = [
                self.gitleaks_path,
                "detect",
                "--source",
                str(self.repo_path),
                "--report-format",
                "json",
                "--report-path",
                "-",  # Output to stdout
                "--no-git",  # Scan files directly, not git history
            ]

            # Add specific files to scan
            for file_change in scannable_files:
                full_path = self.repo_path / file_change.file_path
                if full_path.exists():
                    cmd.extend(["--log-opts", f"-- {full_path}"])

            result = await asyncio.to_thread(
                subprocess.run,
                cmd,
                capture_output=True,
                text=True,
                timeout=180,
                cwd=str(self.repo_path),
            )

            # Parse output (gitleaks returns 0 if no findings, 1 if findings)
            if result.stdout:
                try:
                    gitleaks_data = json.loads(result.stdout)
                    findings = self._parse_gitleaks_output(gitleaks_data, scannable_files)
                except json.JSONDecodeError:
                    logger.warning("Failed to parse gitleaks JSON output")

        except subprocess.TimeoutExpired:
            logger.error("gitleaks timeout")
        except Exception as e:
            logger.error("gitleaks failed", error=str(e))

        return findings

    def _parse_gitleaks_output(
        self,
        gitleaks_data: list[dict],
        files: list[FileChange],
    ) -> list[Finding]:
        """Parse gitleaks JSON output into Finding objects.

        Args:
            gitleaks_data: Parsed JSON from gitleaks (list of findings).
            files: List of file changes for context.

        Returns:
            List of findings.
        """
        findings: list[Finding] = []

        # Create a lookup for file changes
        file_lookup = {f.file_path: f for f in files}

        for leak in gitleaks_data:
            # Extract finding details
            rule_id = leak.get("RuleID", "")
            description = leak.get("Description", "")
            file_path = leak.get("File", "")
            line_number = leak.get("StartLine", 0)
            end_line = leak.get("EndLine", line_number)
            secret = leak.get("Secret", "")
            match = leak.get("Match", "")

            # Check if this is a safe placeholder
            if self._is_safe_placeholder(secret):
                logger.debug("Skipping safe placeholder", secret=secret[:20])
                continue

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

            # Determine severity based on rule type
            severity = self._determine_severity(rule_id, description)

            # Mask the secret in the code snippet
            masked_secret = self._mask_secret(secret)
            code_snippet = match.replace(secret, masked_secret) if secret else match

            finding = Finding(
                id=Finding.generate_id(
                    scanner=self.name(),
                    vuln_id=rule_id,
                    file_path=rel_path,
                    line_start=line_number,
                    commit_hash=commit_hash,
                ),
                scanner=self.name(),
                vuln_id=rule_id,
                title=f"Hardcoded secret: {description}",
                description=f"Detected {description} in {rel_path} at line {line_number}",
                severity=severity,
                file_path=rel_path,
                line_start=line_number,
                line_end=end_line,
                code_snippet=code_snippet,
                metadata={
                    "rule_id": rule_id,
                    "secret_type": description,
                    "masked_secret": masked_secret,
                },
                commit_hash=commit_hash,
            )
            findings.append(finding)

        return findings

    def _is_safe_placeholder(self, secret: str) -> bool:
        """Check if the detected secret is a safe placeholder.

        Args:
            secret: The detected secret string.

        Returns:
            True if it's a safe placeholder.
        """
        secret_lower = secret.lower()
        for placeholder in self.allowlist:
            if placeholder.lower() in secret_lower:
                return True
        return False

    def _determine_severity(self, rule_id: str, description: str) -> Severity:
        """Determine severity based on rule type.

        Args:
            rule_id: Gitleaks rule ID.
            description: Rule description.

        Returns:
            Severity level.
        """
        desc_lower = description.lower()

        # Critical: Private keys, AWS/GCP/Azure credentials
        if any(kw in desc_lower for kw in ["private key", "aws", "gcp", "azure", "github token", "slack"]):
            return Severity.CRITICAL

        # High: API keys, passwords, database credentials
        elif any(kw in desc_lower for kw in ["api key", "password", "database", "connection string", "oauth"]):
            return Severity.HIGH

        # Medium: Generic secrets
        elif "secret" in desc_lower or "token" in desc_lower:
            return Severity.MEDIUM

        # Low: Other
        else:
            return Severity.LOW

    def _mask_secret(self, secret: str) -> str:
        """Mask a secret value for safe display.

        Args:
            secret: The secret to mask.

        Returns:
            Masked secret string.
        """
        if len(secret) <= 8:
            return "*" * len(secret)
        # Show first 4 and last 4 characters
        return f"{secret[:4]}{'*' * (len(secret) - 8)}{secret[-4:]}"
