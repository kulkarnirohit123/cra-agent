"""Analytics data models for metrics tracking and ROI calculation.

These models track agent performance, effectiveness, and business value.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class SeverityDistribution(BaseModel):
    """Distribution of findings by severity."""

    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0

    @property
    def total(self) -> int:
        """Total findings count."""
        return self.critical + self.high + self.medium + self.low + self.info


class ScanMetrics(BaseModel):
    """Metrics for a single scan operation."""

    scan_id: str = Field(description="Unique scan identifier")
    commit_hash: str = Field(description="Commit that was scanned")
    branch: str = Field(description="Branch name")
    started_at: datetime = Field(description="Scan start time")
    completed_at: datetime | None = Field(default=None, description="Scan completion time")
    duration_seconds: float | None = Field(default=None, description="Scan duration")
    files_scanned: int = Field(default=0, description="Number of files scanned")
    findings_count: int = Field(default=0, description="Total findings detected")
    suppressed_count: int = Field(default=0, description="Findings suppressed")
    severity_distribution: SeverityDistribution = Field(default_factory=SeverityDistribution)
    scanners_used: list[str] = Field(default_factory=list, description="Scanners that ran")
    errors: list[str] = Field(default_factory=list, description="Errors during scan")

    @property
    def success(self) -> bool:
        """Check if scan completed successfully."""
        return self.completed_at is not None and len(self.errors) == 0


class FindingMetrics(BaseModel):
    """Metrics for individual findings lifecycle."""

    finding_id: str = Field(description="Finding identifier")
    vuln_id: str | None = Field(default=None, description="CVE/CWE identifier")
    scanner: str = Field(description="Scanner that detected it")
    severity: str = Field(description="Severity level")
    file_path: str = Field(description="File where found")
    detected_at: datetime = Field(description="When detected")
    triaged_at: datetime | None = Field(default=None, description="When triaged")
    ticket_created_at: datetime | None = Field(default=None, description="When Jira ticket created")
    ticket_key: str | None = Field(default=None, description="Jira ticket key")
    fix_started_at: datetime | None = Field(default=None, description="When fix started")
    fix_completed_at: datetime | None = Field(default=None, description="When fix completed")
    pr_url: str | None = Field(default=None, description="Pull request URL")
    suppressed: bool = Field(default=False, description="Whether suppressed")
    suppression_reason: str | None = Field(default=None, description="Why suppressed")
    time_to_triage_seconds: float | None = Field(default=None)
    time_to_ticket_seconds: float | None = Field(default=None)
    time_to_fix_seconds: float | None = Field(default=None)


class CommitMetrics(BaseModel):
    """Metrics for commit-level analysis."""

    commit_hash: str = Field(description="Commit hash")
    branch: str = Field(description="Branch name")
    author: str = Field(description="Commit author")
    committed_at: datetime = Field(description="Commit timestamp")
    scanned_at: datetime | None = Field(default=None, description="When scanned")
    files_changed: int = Field(default=0, description="Files changed in commit")
    lines_added: int = Field(default=0, description="Lines added")
    lines_removed: int = Field(default=0, description="Lines removed")
    findings_introduced: int = Field(default=0, description="New findings from this commit")
    findings_fixed: int = Field(default=0, description="Findings fixed in this commit")


class AgentMetrics(BaseModel):
    """Overall agent performance metrics."""

    period_start: datetime = Field(description="Metrics period start")
    period_end: datetime = Field(description="Metrics period end")

    # Scan metrics
    total_scans: int = Field(default=0, description="Total scans performed")
    successful_scans: int = Field(default=0, description="Successful scans")
    failed_scans: int = Field(default=0, description="Failed scans")
    avg_scan_duration_seconds: float = Field(default=0.0, description="Average scan time")

    # Finding metrics
    total_findings: int = Field(default=0, description="Total findings detected")
    unique_vulnerabilities: int = Field(default=0, description="Unique CVEs/CWEs")
    suppressed_findings: int = Field(default=0, description="Findings suppressed")
    false_positive_rate: float = Field(default=0.0, description="Estimated FP rate")

    # Triage metrics
    triaged_findings: int = Field(default=0, description="Findings triaged")
    avg_triage_time_seconds: float = Field(default=0.0, description="Average triage time")
    auto_triage_accuracy: float = Field(default=0.0, description="Auto-triage accuracy")

    # Ticket metrics
    tickets_created: int = Field(default=0, description="Jira tickets created")
    tickets_closed: int = Field(default=0, description="Tickets closed/resolved")
    avg_time_to_ticket_seconds: float = Field(default=0.0)

    # Fix metrics
    fixes_attempted: int = Field(default=0, description="Auto-fixes attempted")
    fixes_successful: int = Field(default=0, description="Successful auto-fixes")
    fix_success_rate: float = Field(default=0.0, description="Fix success rate")
    avg_time_to_fix_seconds: float = Field(default=0.0)

    # PR metrics
    prs_created: int = Field(default=0, description="Pull requests created")
    prs_merged: int = Field(default=0, description="PRs merged")

    @property
    def scan_success_rate(self) -> float:
        """Calculate scan success rate."""
        if self.total_scans == 0:
            return 0.0
        return self.successful_scans / self.total_scans

    @property
    def suppression_rate(self) -> float:
        """Calculate suppression rate."""
        if self.total_findings == 0:
            return 0.0
        return self.suppressed_findings / self.total_findings


class ROIMetrics(BaseModel):
    """Return on Investment metrics for the agent."""

    period_start: datetime = Field(description="ROI period start")
    period_end: datetime = Field(description="ROI period end")

    # Cost metrics
    llm_api_cost_usd: float = Field(default=0.0, description="LLM API costs")
    compute_cost_usd: float = Field(default=0.0, description="Compute/infrastructure costs")
    total_operational_cost: float = Field(default=0.0, description="Total operational cost")

    # Time savings
    manual_triage_time_hours: float = Field(default=0.0, description="Hours saved on manual triage")
    manual_ticket_creation_hours: float = Field(default=0.0, description="Hours saved on ticket creation")
    manual_fix_time_hours: float = Field(default=0.0, description="Hours saved on manual fixes")
    total_time_saved_hours: float = Field(default=0.0, description="Total hours saved")

    # Value metrics
    hourly_rate_usd: float = Field(default=100.0, description="Average security engineer hourly rate")
    time_savings_value_usd: float = Field(default=0.0, description="Value of time saved")
    vulnerabilities_prevented: int = Field(default=0, description="Estimated vulns prevented")
    breach_cost_avoided_usd: float = Field(default=0.0, description="Estimated breach cost avoided")

    # ROI calculation
    total_value_usd: float = Field(default=0.0, description="Total value generated")
    roi_percentage: float = Field(default=0.0, description="ROI percentage")

    # Effectiveness scores
    detection_effectiveness: float = Field(default=0.0, description="Detection effectiveness 0-1")
    triage_effectiveness: float = Field(default=0.0, description="Triage effectiveness 0-1")
    fix_effectiveness: float = Field(default=0.0, description="Fix effectiveness 0-1")
    overall_effectiveness: float = Field(default=0.0, description="Overall effectiveness 0-1")

    @classmethod
    def calculate(
        cls,
        agent_metrics: AgentMetrics,
        llm_cost: float = 0.0,
        compute_cost: float = 0.0,
        hourly_rate: float = 100.0,
        avg_breach_cost: float = 4_000_000.0,
    ) -> ROIMetrics:
        """Calculate ROI from agent metrics.

        Args:
            agent_metrics: Agent performance metrics.
            llm_cost: LLM API costs for the period.
            compute_cost: Infrastructure costs for the period.
            hourly_rate: Average security engineer hourly rate.
            avg_breach_cost: Average cost of a security breach.

        Returns:
            Calculated ROI metrics.
        """
        # Calculate time savings (assuming manual processes take longer)
        manual_triage_hours = (agent_metrics.triaged_findings * 0.5) / 60  # 30 min per finding manually
        manual_ticket_hours = (agent_metrics.tickets_created * 0.25) / 60  # 15 min per ticket manually
        manual_fix_hours = (agent_metrics.fixes_successful * 2) / 60  # 2 hours per fix manually

        total_time_saved = manual_triage_hours + manual_ticket_hours + manual_fix_hours
        time_savings_value = total_time_saved * hourly_rate

        # Estimate breach prevention value
        critical_fixes = agent_metrics.fixes_successful  # Assume all fixes prevent potential breaches
        breach_prevention_value = critical_fixes * (avg_breach_cost * 0.01)  # 1% of breach cost per fix

        # Calculate totals
        total_cost = llm_cost + compute_cost
        total_value = time_savings_value + breach_prevention_value

        # Calculate ROI
        roi_percentage = ((total_value - total_cost) / total_cost * 100) if total_cost > 0 else 0.0

        # Calculate effectiveness scores
        detection_eff = min(1.0, agent_metrics.total_findings / max(1, agent_metrics.total_scans * 2))
        triage_eff = agent_metrics.auto_triage_accuracy
        fix_eff = agent_metrics.fix_success_rate
        overall_eff = (detection_eff + triage_eff + fix_eff) / 3

        return cls(
            period_start=agent_metrics.period_start,
            period_end=agent_metrics.period_end,
            llm_api_cost_usd=llm_cost,
            compute_cost_usd=compute_cost,
            total_operational_cost=total_cost,
            manual_triage_time_hours=manual_triage_hours,
            manual_ticket_creation_hours=manual_ticket_hours,
            manual_fix_time_hours=manual_fix_hours,
            total_time_saved_hours=total_time_saved,
            hourly_rate_usd=hourly_rate,
            time_savings_value_usd=time_savings_value,
            vulnerabilities_prevented=critical_fixes,
            breach_cost_avoided_usd=breach_prevention_value,
            total_value_usd=total_value,
            roi_percentage=roi_percentage,
            detection_effectiveness=detection_eff,
            triage_effectiveness=triage_eff,
            fix_effectiveness=fix_eff,
            overall_effectiveness=overall_eff,
        )


class DashboardSummary(BaseModel):
    """Summary data for dashboard display."""

    # Current status
    agent_status: str = Field(default="running", description="Agent status")
    last_scan_at: datetime | None = Field(default=None, description="Last scan time")
    active_suppressions: int = Field(default=0, description="Active suppression rules")

    # Today's metrics
    scans_today: int = Field(default=0)
    findings_today: int = Field(default=0)
    tickets_today: int = Field(default=0)
    fixes_today: int = Field(default=0)

    # This week's metrics
    scans_this_week: int = Field(default=0)
    findings_this_week: int = Field(default=0)
    tickets_this_week: int = Field(default=0)
    fixes_this_week: int = Field(default=0)

    # All-time metrics
    total_scans: int = Field(default=0)
    total_findings: int = Field(default=0)
    total_tickets: int = Field(default=0)
    total_fixes: int = Field(default=0)
    total_prs_merged: int = Field(default=0)

    # Effectiveness
    overall_effectiveness: float = Field(default=0.0)
    roi_percentage: float = Field(default=0.0)
    time_saved_hours: float = Field(default=0.0)

    # Recent activity
    recent_findings: list[dict[str, Any]] = Field(default_factory=list)
    recent_tickets: list[dict[str, Any]] = Field(default_factory=list)
    recent_fixes: list[dict[str, Any]] = Field(default_factory=list)