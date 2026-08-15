"""Pytest configuration and shared fixtures for CRA-AGENT tests."""

from __future__ import annotations

import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from src.core.models import (
    ChangeType,
    CRARelevance,
    Exploitability,
    FileChange,
    Finding,
    RecommendedAction,
    Severity,
    TriagedFinding,
    TriageResult,
)
from src.scanners.suppression_store import SuppressionStore

# =============================================================================
# Fixtures: Paths and Directories
# =============================================================================


@pytest.fixture
def temp_dir() -> Path:
    """Create a temporary directory for test files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def temp_repo(temp_dir: Path) -> Path:
    """Create a temporary git repository for testing."""
    import git

    repo_path = temp_dir / "test-repo"
    repo_path.mkdir()

    # Initialize git repo
    repo = git.Repo.init(repo_path)

    # Create initial commit
    readme = repo_path / "README.md"
    readme.write_text("# Test Repository")
    repo.index.add(["README.md"])
    repo.index.commit("Initial commit")

    return repo_path


@pytest.fixture
def suppression_db(temp_dir: Path) -> SuppressionStore:
    """Create a temporary suppression store for testing."""
    db_path = temp_dir / "test_suppressions.db"
    return SuppressionStore(db_path=db_path)


# =============================================================================
# Fixtures: Mock Clients
# =============================================================================


@pytest.fixture
def mock_llm_client() -> MagicMock:
    """Create a mock LLM client for testing."""
    client = MagicMock()
    client.generate = AsyncMock(return_value='{"result": "test"}')
    client.generate_json = AsyncMock(return_value={"result": "test"})
    client.chat = AsyncMock(return_value="Test response")
    client.close = AsyncMock()
    return client


@pytest.fixture
def mock_jira_client() -> MagicMock:
    """Create a mock Jira client for testing."""
    client = MagicMock()
    client.create_issue = AsyncMock(
        return_value={
            "key": "CRA-123",
            "id": "12345",
            "url": "https://jira.example.com/browse/CRA-123",
            "status": "Open",
        }
    )
    client.add_comment = AsyncMock(return_value={"id": "1"})
    client.transition_issue = AsyncMock(return_value=True)
    client.add_labels = AsyncMock(return_value=True)
    client.attach_file = AsyncMock(return_value={"id": "1"})
    client.get_issue = AsyncMock(
        return_value={
            "key": "CRA-123",
            "fields": {
                "summary": "[HIGH] CVE-2024-1234: Test vulnerability",
                "labels": ["cve-2024-1234"],
            },
        }
    )
    client.close = AsyncMock()
    return client


@pytest.fixture
def mock_git_client() -> MagicMock:
    """Create a mock Git client for testing."""
    client = MagicMock()
    client.create_branch = AsyncMock(return_value="cra-agent/fix-test")
    client.apply_fix = AsyncMock(return_value=True)
    client.commit = AsyncMock(return_value="abc123def456")
    client.push = AsyncMock(return_value=True)
    client.create_pull_request = AsyncMock(return_value="https://github.com/org/repo/pull/1")
    client.checkout = AsyncMock(return_value=True)
    client.get_current_branch = AsyncMock(return_value="main")
    return client


# =============================================================================
# Fixtures: Sample Data
# =============================================================================


@pytest.fixture
def sample_file_change() -> FileChange:
    """Create a sample file change for testing."""
    return FileChange(
        file_path="src/app.py",
        change_type=ChangeType.MODIFIED,
        file_extension=".py",
        language="python",
        file_content='import os\npassword = "secret123"\n',
    )


@pytest.fixture
def sample_finding() -> Finding:
    """Create a sample finding for testing."""
    return Finding(
        id="test-finding-001",
        scanner="secrets",
        vuln_id="CWE-798",
        title="Hardcoded password detected",
        description="A hardcoded password was found in the source code.",
        severity=Severity.HIGH,
        file_path="src/app.py",
        line_start=2,
        line_end=2,
        code_snippet='password = "secret123"',
        commit_hash="abc123def456",
    )


@pytest.fixture
def sample_triage_result() -> TriageResult:
    """Create a sample triage result for testing."""
    return TriageResult(
        severity=Severity.HIGH,
        exploitability=Exploitability.LIKELY,
        cra_relevance=[CRARelevance.ANNEX_I_SECTION_1],
        recommended_action=RecommendedAction.FIX_NOW,
        reasoning="Hardcoded credentials pose a significant security risk.",
        fix_suggestion="Use environment variables or a secrets manager.",
        confidence=0.9,
    )


@pytest.fixture
def sample_triaged_finding(sample_finding: Finding, sample_triage_result: TriageResult) -> TriagedFinding:
    """Create a sample triaged finding for testing."""
    return TriagedFinding(
        **sample_finding.model_dump(),
        triage=sample_triage_result,
        cra_mapping=["annex_i_section_1"],
        sbom_component=None,
    )


@pytest.fixture
def sample_webhook_payload() -> dict:
    """Create a sample Jira webhook payload for testing."""
    return {
        "webhookEvent": "jira:issue_updated",
        "issue": {
            "key": "CRA-123",
            "id": "12345",
            "fields": {
                "summary": "[HIGH] CVE-2024-1234: SQL Injection",
                "labels": ["cve-2024-1234", "security"],
            },
        },
        "changelog": {
            "items": [
                {
                    "field": "status",
                    "fromString": "Open",
                    "toString": "Won't Fix",
                }
            ]
        },
        "user": {
            "displayName": "Test User",
            "emailAddress": "test@example.com",
        },
    }


# =============================================================================
# Fixtures: Async Support
# =============================================================================


@pytest.fixture
def anyio_backend() -> str:
    """Configure anyio backend for async tests."""
    return "asyncio"
