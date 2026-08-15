"""Application settings loaded from environment variables."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """CRA-AGENT application settings.

    All settings are loaded from environment variables with the prefix
    defined in model_config.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # -------------------------------------------------------------------------
    # General
    # -------------------------------------------------------------------------
    app_env: Literal["development", "staging", "production"] = "development"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    data_dir: Path = Path("./data")

    # -------------------------------------------------------------------------
    # Git Repository
    # -------------------------------------------------------------------------
    git_repo_path: Path = Path("./target-repo")
    git_branches: str = "main,develop"
    git_poll_interval_seconds: int = 60

    @property
    def git_branch_list(self) -> list[str]:
        """Parse comma-separated branch list."""
        return [b.strip() for b in self.git_branches.split(",") if b.strip()]

    # -------------------------------------------------------------------------
    # LLM Provider
    # -------------------------------------------------------------------------
    llm_provider: Literal["openai", "anthropic"] = "openai"
    llm_model: str = "gpt-4o"
    llm_temperature: float = 0.1
    llm_max_tokens: int = 4096
    openai_api_key: str = ""
    openai_base_url: str = "https://api.openai.com/v1"
    anthropic_api_key: str = ""

    # -------------------------------------------------------------------------
    # Jira Integration
    # -------------------------------------------------------------------------
    jira_base_url: str = ""
    jira_project_key: str = "CRA"
    jira_email: str = ""
    jira_api_token: str = ""
    jira_webhook_secret: str = ""
    jira_issue_type: str = "Bug"
    jira_labels: str = "cra-agent,security,vulnerability"
    jira_component: str = "Security"

    @property
    def jira_label_list(self) -> list[str]:
        """Parse comma-separated label list."""
        return [label.strip() for label in self.jira_labels.split(",") if label.strip()]

    # -------------------------------------------------------------------------
    # Scanner Configuration
    # -------------------------------------------------------------------------
    scanners_enabled: str = "dependency,sast,secrets"
    semgrep_path: str = "semgrep"
    pip_audit_path: str = "pip-audit"
    gitleaks_path: str = "gitleaks"
    severity_threshold: Literal["critical", "high", "medium", "low", "info"] = "medium"

    @property
    def scanner_list(self) -> list[str]:
        """Parse comma-separated scanner list."""
        return [s.strip() for s in self.scanners_enabled.split(",") if s.strip()]

    # -------------------------------------------------------------------------
    # Suppression Store
    # -------------------------------------------------------------------------
    suppression_db_path: Path = Path("./data/suppressions.db")

    # -------------------------------------------------------------------------
    # Webhook Server
    # -------------------------------------------------------------------------
    webhook_host: str = "0.0.0.0"
    webhook_port: int = 8080

    # -------------------------------------------------------------------------
    # Fixer Agent
    # -------------------------------------------------------------------------
    fixer_branch_prefix: str = "cra-agent/fix-"
    fixer_auto_merge: bool = False
    fixer_max_files_changed: int = 5

    # -------------------------------------------------------------------------
    # CRA Compliance
    # -------------------------------------------------------------------------
    cra_sbom_format: Literal["cyclonedx", "spdx"] = "cyclonedx"
    cra_reporting_authority: str = "BSI"
    cra_report_exploited_within_hours: int = 24

    # -------------------------------------------------------------------------
    # GitHub App Integration
    # -------------------------------------------------------------------------
    github_app_id: str = ""
    github_installation_id: str = ""
    github_webhook_secret: str = ""
    github_private_key_path: Path = Path("./cra-agent.private-key.pem")
    github_api_url: str = "https://api.github.com"
    github_repos_config: Path = Path("./config/repos.yaml")

    @property
    def github_enabled(self) -> bool:
        """Check if GitHub integration is configured."""
        return bool(self.github_app_id and self.github_private_key_path.exists())

    @property
    def github_private_key(self) -> str:
        """Read GitHub App private key from file."""
        if self.github_private_key_path.exists():
            return self.github_private_key_path.read_text()
        return ""


@lru_cache
def get_settings() -> Settings:
    """Get cached application settings instance."""
    return Settings()
