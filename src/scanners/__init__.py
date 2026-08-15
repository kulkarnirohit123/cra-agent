"""Scanner module — vulnerability detection tools.

This module contains all scanner implementations that detect different
types of vulnerabilities in code and dependencies.

Available Scanners:
- DependencyScanner: Scans dependencies for known CVEs (pip-audit, osv-scanner)
- SASTScanner: Static analysis for code vulnerabilities (semgrep)
- SecretsScanner: Detects hardcoded secrets (gitleaks)
- TrivyScanner: Comprehensive scanner for deps, containers, IaC (trivy)
- BanditScanner: Python-specific security linter (bandit)
"""

from src.scanners.bandit_scanner import BanditScanner
from src.scanners.base_scanner import BaseScanner
from src.scanners.dependency_scanner import DependencyScanner
from src.scanners.sast_scanner import SASTScanner
from src.scanners.secrets_scanner import SecretsScanner
from src.scanners.suppression_store import SuppressionStore
from src.scanners.trivy_scanner import TrivyScanner

__all__ = [
    "BanditScanner",
    "BaseScanner",
    "DependencyScanner",
    "SASTScanner",
    "SecretsScanner",
    "SuppressionStore",
    "TrivyScanner",
]
