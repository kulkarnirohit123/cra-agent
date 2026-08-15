"""Integrations module — external service clients.

This module contains clients for external services:
- Jira API client
- LLM provider client (OpenAI/Anthropic)
- Git operations client
- EU VD (Vulnerability Database) client
"""

from src.integrations.eu_vd_client import EUVDClient
from src.integrations.git_client import GitClient
from src.integrations.jira_client import JiraClient
from src.integrations.llm_client import LLMClient

__all__ = [
    "EUVDClient",
    "GitClient",
    "JiraClient",
    "LLMClient",
]
