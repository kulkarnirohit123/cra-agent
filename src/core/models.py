"""Core data models for CRA-AGENT.

All models use Pydantic v2 for validation and serialization.
These models are shared across agents, scanners, integrations, and the webhook server.
"""

from __future__ import annotations

import hashlib
from datetime import datetime
from enum import StrEnum
from typing import Any, TypedDict

from pydantic import BaseModel, Field

# =============================================================================
# Enums
# =============================================================================


class Severity(StrEnum):
    """Vulnerability severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def weight(self) -> int:
        """Numeric weight for priority sorting."""
        weights = {
            Severity.CRITICAL: 10,
            Severity.HIGH: 8,
            Severity.MEDIUM: 5,
            Severity.LOW: 2,
            Severity.INFO: 1,
        }
        return weights[self]

    def __ge__(self, other: Severity) -> bool:
        """Compare severity levels."""
        return self.weight >= other.weight


class ChangeType(StrEnum):
    """Type of file change in a commit."""

    ADDED = "added"
    MODIFIED = "modified"
    DELETED = "deleted"
    RENAMED = "renamed"


class ActionType(StrEnum):
    """Types of actions the agent can take."""

    SCAN = "scan"
    TRIAGE = "triage"
    CREATE_TICKET = "create_ticket"
    UPDATE_TICKET = "update_ticket"
    SUPPRESS = "suppress"
    FIX = "fix"
    CREATE_PR = "create_pr"
    NOTIFY = "notify"


class Exploitability(StrEnum):
    """Exploitability assessment levels."""

    CONFIRMED = "confirmed"
    LIKELY = "likely"
    POSSIBLE = "possible"
    UNLIKELY = "unlikely"


class CRARelevance(StrEnum):
    """CRA article/annex relevance mapping."""

    ANNEX_I_SECTION_1 = "annex_i_section_1"
    ANNEX_I_SECTION_2 = "annex_i_section_2"
    ANNEX_II = "annex_ii"
    ARTICLE_13 = "article_13"
    NONE = "none"


class RecommendedAction(StrEnum):
    """Recommended triage actions."""

    FIX_NOW = "fix_now"
    FIX_SOON = "fix_soon"
    SUPPRESS = "suppress"
    INVESTIGATE = "investigate"


# =============================================================================
# Git / Diff Models
# =============================================================================


class Hunk(BaseModel):
    """A single diff hunk (contiguous block of changes)."""

    old_start: int = Field(description="Start line in old file")
    old_count: int = Field(description="Number of lines in old file")
    new_start: int = Field(description="Start line in new file")
    new_count: int = Field(description="Number of lines in new file")
    added_lines: list[str] = Field(default_factory=list, description="Lines added")
    removed_lines: list[str] = Field(default_factory=list, description="Lines removed")
    context_lines: list[str] = Field(default_factory=list, description="Unchanged context lines")

    @property
    def diff_text(self) -> str:
        """Render the hunk as a unified diff string."""
        lines = [f"@@ -{self.old_start},{self.old_count} +{self.new_start},{self.new_count} @@"]
        for line in self.removed_lines:
            lines.append(f"-{line}")
        for line in self.added_lines:
            lines.append(f"+{line}")
        return "\n".join(lines)


class FileChange(BaseModel):
    """Represents a single file change in a commit."""

    file_path: str = Field(description="Path to the file relative to repo root")
    change_type: ChangeType = Field(description="Type of change")
    old_path: str | None = Field(default=None, description="Previous path (for renames)")
    hunks: list[Hunk] = Field(default_factory=list, description="Diff hunks")
    file_content: str | None = Field(default=None, description="Full file content (new version)")
    file_extension: str = Field(default="", description="File extension")
    language: str = Field(default="", description="Detected programming language")

    @property
    def diff_summary(self) -> str:
        """Get a summary of all hunks in this file change."""
        if not self.hunks:
            return f"[{self.change_type.value}] {self.file_path}"
        return "\n".join(h.diff_text for h in self.hunks)


class CommitInfo(BaseModel):
    """Information about a git commit."""

    hash: str = Field(description="Full commit hash")
    short_hash: str = Field(description="Short commit hash (7 chars)")
    author: str = Field(description="Commit author name")
    author_email: str = Field(description="Commit author email")
    message: str = Field(description="Commit message")
    timestamp: datetime = Field(description="Commit timestamp")
    branch: str = Field(description="Branch name")
    parent_hash: str | None = Field(default=None, description="Parent commit hash")


# =============================================================================
# Finding Models
# =============================================================================


class Finding(BaseModel):
    """A single vulnerability finding from a scanner."""

    id: str = Field(description="Unique finding ID (hash-based)")
    scanner: str = Field(description="Scanner that found this (dependency/sast/secrets)")
    vuln_id: str | None = Field(default=None, description="CVE/CWE identifier")
    title: str = Field(description="Short title of the finding")
    description: str = Field(description="Detailed description")
    severity: Severity = Field(description="Severity level")
    file_path: str = Field(description="File where finding was detected")
    line_start: int = Field(default=0, description="Start line number")
    line_end: int = Field(default=0, description="End line number")
    code_snippet: str = Field(default="", description="Relevant code snippet")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Scanner-specific metadata")
    commit_hash: str = Field(description="Commit hash where finding was detected")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Detection timestamp")

    @classmethod
    def generate_id(
        cls,
        scanner: str,
        vuln_id: str | None,
        file_path: str,
        line_start: int,
        commit_hash: str,
    ) -> str:
        """Generate a deterministic finding ID."""
        raw = f"{scanner}:{vuln_id or 'unknown'}:{file_path}:{line_start}:{commit_hash[:12]}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    @property
    def is_critical(self) -> bool:
        """Check if finding is critical or high severity."""
        return self.severity in (Severity.CRITICAL, Severity.HIGH)


class TriageResult(BaseModel):
    """LLM-powered triage assessment for a finding."""

    severity: Severity = Field(description="Assessed severity")
    exploitability: Exploitability = Field(description="Exploitability assessment")
    cra_relevance: list[CRARelevance] = Field(default_factory=list, description="Applicable CRA articles")
    recommended_action: RecommendedAction = Field(description="Recommended action")
    reasoning: str = Field(description="LLM reasoning for the assessment")
    fix_suggestion: str | None = Field(default=None, description="Suggested fix approach")
    confidence: float = Field(default=0.0, ge=0.0, le=1.0, description="Confidence score")


class TriagedFinding(Finding):
    """A finding enriched with triage assessment."""

    triage: TriageResult = Field(description="Triage assessment")
    cra_mapping: list[str] = Field(default_factory=list, description="Applicable CRA article references")
    sbom_component: str | None = Field(default=None, description="Affected SBOM component identifier")


# =============================================================================
# Suppression Models
# =============================================================================


class Suppression(BaseModel):
    """A vulnerability suppression rule."""

    id: str = Field(description="Unique suppression ID")
    vuln_id: str = Field(description="Vulnerability ID to suppress (e.g., CVE-2024-1234)")
    file_pattern: str | None = Field(default=None, description="Optional file glob pattern")
    reason: str = Field(description="Reason for suppression")
    jira_issue_key: str | None = Field(default=None, description="Linked Jira ticket")
    created_at: datetime = Field(default_factory=datetime.utcnow)
    expires_at: datetime | None = Field(default=None, description="Optional expiry date")
    created_by: str = Field(default="agent", description="Who created the suppression")

    @property
    def is_expired(self) -> bool:
        """Check if suppression has expired."""
        if self.expires_at is None:
            return False
        return datetime.utcnow() > self.expires_at

    def matches(self, finding: Finding) -> bool:
        """Check if this suppression matches a given finding."""
        if self.is_expired:
            return False
        if self.vuln_id != finding.vuln_id:
            return False
        if self.file_pattern:
            import fnmatch

            if not fnmatch.fnmatch(finding.file_path, self.file_pattern):
                return False
        return True


# =============================================================================
# Jira Models
# =============================================================================


class JiraTicket(BaseModel):
    """Represents a Jira ticket created by the agent."""

    key: str = Field(description="Jira issue key (e.g., CRA-123)")
    finding_id: str = Field(description="Linked finding ID")
    title: str = Field(description="Issue summary")
    status: str = Field(default="Open", description="Current issue status")
    url: str = Field(description="Full URL to the Jira issue")
    priority: str = Field(default="Medium", description="Jira priority")
    labels: list[str] = Field(default_factory=list, description="Issue labels")
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


class JiraWebhookEvent(BaseModel):
    """Parsed Jira webhook event payload."""

    webhook_event: str = Field(description="Event type (e.g., jira:issue_updated)")
    issue_key: str = Field(description="Issue key from the event")
    issue_id: str = Field(description="Issue ID")
    transition_name: str | None = Field(default=None, description="Workflow transition name (if any)")
    comment_body: str | None = Field(default=None, description="Comment body (if comment event)")
    user_name: str = Field(default="", description="User who triggered the event")
    user_email: str = Field(default="", description="User email")
    changelog_items: list[dict[str, Any]] = Field(default_factory=list, description="Changed fields")
    raw_payload: dict[str, Any] = Field(default_factory=dict, description="Full webhook payload")


# =============================================================================
# Action Models
# =============================================================================


class Action(BaseModel):
    """An action taken by the agent."""

    action_type: ActionType = Field(description="Type of action")
    description: str = Field(description="Human-readable description")
    details: dict[str, Any] = Field(default_factory=dict, description="Action-specific details")
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    success: bool = Field(default=True, description="Whether the action succeeded")
    error: str | None = Field(default=None, description="Error message if failed")


# =============================================================================
# Agent State (LangGraph)
# =============================================================================


class AgentState(TypedDict):
    """State schema for the LangGraph agent state machine.

    This is the shared state passed between all agent nodes.
    """

    # Input
    commit_info: dict[str, Any]  # CommitInfo serialized
    changed_files: list[dict[str, Any]]  # list[FileChange] serialized

    # Scanner output
    raw_findings: list[dict[str, Any]]  # list[Finding] serialized

    # Filter output
    filtered_findings: list[dict[str, Any]]  # list[Finding] after suppression

    # Triage output
    triaged_findings: list[dict[str, Any]]  # list[TriagedFinding] serialized

    # Jira output
    jira_tickets: list[dict[str, Any]]  # list[JiraTicket] serialized

    # Actions taken
    actions: list[dict[str, Any]]  # list[Action] serialized

    # Errors
    errors: list[str]

    # Metadata
    scan_started_at: str
    scan_completed_at: str | None
