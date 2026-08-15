"""Metrics store — SQLite database for tracking agent metrics and effectiveness.

Stores:
- Scan metrics (per commit)
- Finding metrics (lifecycle tracking)
- Agent performance metrics
- ROI calculations
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from src.analytics.models import (
    AgentMetrics,
    CommitMetrics,
    DashboardSummary,
    FindingMetrics,
    ROIMetrics,
    ScanMetrics,
    SeverityDistribution,
)
from src.utils.logger import get_logger

logger = get_logger(__name__)


class MetricsStore:
    """SQLite-backed metrics store for agent performance tracking.

    Tracks:
    - Scan operations and results
    - Finding lifecycle (detection → triage → ticket → fix)
    - Agent effectiveness metrics
    - ROI calculations
    """

    def __init__(self, db_path: Path) -> None:
        """Initialize the metrics store.

        Args:
            db_path: Path to the SQLite database file.
        """
        self.db_path = db_path
        self._ensure_db_exists()

    def _ensure_db_exists(self) -> None:
        """Create the database and tables if they don't exist."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        with sqlite3.connect(self.db_path) as conn:
            # Scans table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    scan_id TEXT PRIMARY KEY,
                    commit_hash TEXT NOT NULL,
                    branch TEXT NOT NULL,
                    started_at TIMESTAMP NOT NULL,
                    completed_at TIMESTAMP,
                    duration_seconds REAL,
                    files_scanned INTEGER DEFAULT 0,
                    findings_count INTEGER DEFAULT 0,
                    suppressed_count INTEGER DEFAULT 0,
                    severity_critical INTEGER DEFAULT 0,
                    severity_high INTEGER DEFAULT 0,
                    severity_medium INTEGER DEFAULT 0,
                    severity_low INTEGER DEFAULT 0,
                    severity_info INTEGER DEFAULT 0,
                    scanners_used TEXT,
                    errors TEXT
                )
            """)

            # Findings table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS findings (
                    finding_id TEXT PRIMARY KEY,
                    scan_id TEXT,
                    vuln_id TEXT,
                    scanner TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    file_path TEXT NOT NULL,
                    detected_at TIMESTAMP NOT NULL,
                    triaged_at TIMESTAMP,
                    ticket_created_at TIMESTAMP,
                    ticket_key TEXT,
                    fix_started_at TIMESTAMP,
                    fix_completed_at TIMESTAMP,
                    pr_url TEXT,
                    suppressed INTEGER DEFAULT 0,
                    suppression_reason TEXT,
                    time_to_triage_seconds REAL,
                    time_to_ticket_seconds REAL,
                    time_to_fix_seconds REAL,
                    FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
                )
            """)

            # Commits table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS commits (
                    commit_hash TEXT PRIMARY KEY,
                    branch TEXT NOT NULL,
                    author TEXT,
                    committed_at TIMESTAMP NOT NULL,
                    scanned_at TIMESTAMP,
                    files_changed INTEGER DEFAULT 0,
                    lines_added INTEGER DEFAULT 0,
                    lines_removed INTEGER DEFAULT 0,
                    findings_introduced INTEGER DEFAULT 0,
                    findings_fixed INTEGER DEFAULT 0
                )
            """)

            # Agent metrics snapshots
            conn.execute("""
                CREATE TABLE IF NOT EXISTS agent_metrics_snapshots (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    period_start TIMESTAMP NOT NULL,
                    period_end TIMESTAMP NOT NULL,
                    metrics_json TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # ROI metrics
            conn.execute("""
                CREATE TABLE IF NOT EXISTS roi_metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    period_start TIMESTAMP NOT NULL,
                    period_end TIMESTAMP NOT NULL,
                    llm_cost_usd REAL DEFAULT 0,
                    compute_cost_usd REAL DEFAULT 0,
                    total_value_usd REAL DEFAULT 0,
                    roi_percentage REAL DEFAULT 0,
                    time_saved_hours REAL DEFAULT 0,
                    effectiveness_score REAL DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # Create indexes
            conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_started ON scans(started_at)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_detected ON findings(detected_at)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_commits_committed ON commits(committed_at)")

            conn.commit()

        logger.info("Metrics store initialized", db_path=str(self.db_path))

    # -------------------------------------------------------------------------
    # Scan Metrics
    # -------------------------------------------------------------------------

    def record_scan(self, metrics: ScanMetrics) -> None:
        """Record a scan operation.

        Args:
            metrics: Scan metrics to record.
        """
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO scans
                (scan_id, commit_hash, branch, started_at, completed_at, duration_seconds,
                 files_scanned, findings_count, suppressed_count,
                 severity_critical, severity_high, severity_medium, severity_low, severity_info,
                 scanners_used, errors)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    metrics.scan_id,
                    metrics.commit_hash,
                    metrics.branch,
                    metrics.started_at.isoformat(),
                    metrics.completed_at.isoformat() if metrics.completed_at else None,
                    metrics.duration_seconds,
                    metrics.files_scanned,
                    metrics.findings_count,
                    metrics.suppressed_count,
                    metrics.severity_distribution.critical,
                    metrics.severity_distribution.high,
                    metrics.severity_distribution.medium,
                    metrics.severity_distribution.low,
                    metrics.severity_distribution.info,
                    json.dumps(metrics.scanners_used),
                    json.dumps(metrics.errors),
                ),
            )
            conn.commit()

        logger.debug("Recorded scan", scan_id=metrics.scan_id, findings=metrics.findings_count)

    def get_scans(
        self,
        start_date: datetime | None = None,
        end_date: datetime | None = None,
        limit: int = 100,
    ) -> list[ScanMetrics]:
        """Get scan metrics within a date range.

        Args:
            start_date: Start of date range.
            end_date: End of date range.
            limit: Maximum results to return.

        Returns:
            List of scan metrics.
        """
        query = "SELECT * FROM scans WHERE 1=1"
        params: list[Any] = []

        if start_date:
            query += " AND started_at >= ?"
            params.append(start_date.isoformat())
        if end_date:
            query += " AND started_at <= ?"
            params.append(end_date.isoformat())

        query += " ORDER BY started_at DESC LIMIT ?"
        params.append(limit)

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(query, params)
            rows = cursor.fetchall()

        scans = []
        for row in rows:
            scans.append(
                ScanMetrics(
                    scan_id=row[0],
                    commit_hash=row[1],
                    branch=row[2],
                    started_at=datetime.fromisoformat(row[3]),
                    completed_at=datetime.fromisoformat(row[4]) if row[4] else None,
                    duration_seconds=row[5],
                    files_scanned=row[6],
                    findings_count=row[7],
                    suppressed_count=row[8],
                    severity_distribution=SeverityDistribution(
                        critical=row[9],
                        high=row[10],
                        medium=row[11],
                        low=row[12],
                        info=row[13],
                    ),
                    scanners_used=json.loads(row[14]) if row[14] else [],
                    errors=json.loads(row[15]) if row[15] else [],
                )
            )

        return scans

    # -------------------------------------------------------------------------
    # Finding Metrics
    # -------------------------------------------------------------------------

    def record_finding(self, metrics: FindingMetrics, scan_id: str | None = None) -> None:
        """Record a finding.

        Args:
            metrics: Finding metrics to record.
            scan_id: Associated scan ID.
        """
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO findings
                (finding_id, scan_id, vuln_id, scanner, severity, file_path,
                 detected_at, triaged_at, ticket_created_at, ticket_key,
                 fix_started_at, fix_completed_at, pr_url,
                 suppressed, suppression_reason,
                 time_to_triage_seconds, time_to_ticket_seconds, time_to_fix_seconds)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    metrics.finding_id,
                    scan_id,
                    metrics.vuln_id,
                    metrics.scanner,
                    metrics.severity,
                    metrics.file_path,
                    metrics.detected_at.isoformat(),
                    metrics.triaged_at.isoformat() if metrics.triaged_at else None,
                    metrics.ticket_created_at.isoformat() if metrics.ticket_created_at else None,
                    metrics.ticket_key,
                    metrics.fix_started_at.isoformat() if metrics.fix_started_at else None,
                    metrics.fix_completed_at.isoformat() if metrics.fix_completed_at else None,
                    metrics.pr_url,
                    1 if metrics.suppressed else 0,
                    metrics.suppression_reason,
                    metrics.time_to_triage_seconds,
                    metrics.time_to_ticket_seconds,
                    metrics.time_to_fix_seconds,
                ),
            )
            conn.commit()

        logger.debug("Recorded finding", finding_id=metrics.finding_id, severity=metrics.severity)

    def update_finding_ticket(self, finding_id: str, ticket_key: str, ticket_created_at: datetime) -> None:
        """Update finding with ticket information.

        Args:
            finding_id: Finding ID.
            ticket_key: Jira ticket key.
            ticket_created_at: When ticket was created.
        """
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                UPDATE findings
                SET ticket_key = ?, ticket_created_at = ?,
                    time_to_ticket_seconds = (julianday(?) - julianday(detected_at)) * 86400
                WHERE finding_id = ?
            """,
                (ticket_key, ticket_created_at.isoformat(), ticket_created_at.isoformat(), finding_id),
            )
            conn.commit()

    def update_finding_fix(
        self,
        finding_id: str,
        fix_started_at: datetime,
        fix_completed_at: datetime | None = None,
        pr_url: str | None = None,
    ) -> None:
        """Update finding with fix information.

        Args:
            finding_id: Finding ID.
            fix_started_at: When fix started.
            fix_completed_at: When fix completed.
            pr_url: Pull request URL.
        """
        with sqlite3.connect(self.db_path) as conn:
            if fix_completed_at:
                conn.execute(
                    """
                    UPDATE findings
                    SET fix_started_at = ?, fix_completed_at = ?, pr_url = ?,
                        time_to_fix_seconds = (julianday(?) - julianday(detected_at)) * 86400
                    WHERE finding_id = ?
                """,
                    (
                        fix_started_at.isoformat(),
                        fix_completed_at.isoformat(),
                        pr_url,
                        fix_completed_at.isoformat(),
                        finding_id,
                    ),
                )
            else:
                conn.execute(
                    """
                    UPDATE findings
                    SET fix_started_at = ?, pr_url = ?
                    WHERE finding_id = ?
                """,
                    (fix_started_at.isoformat(), pr_url, finding_id),
                )
            conn.commit()

    def suppress_finding(self, finding_id: str, reason: str) -> None:
        """Mark a finding as suppressed.

        Args:
            finding_id: Finding ID.
            reason: Suppression reason.
        """
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "UPDATE findings SET suppressed = 1, suppression_reason = ? WHERE finding_id = ?",
                (reason, finding_id),
            )
            conn.commit()

    def get_findings(
        self,
        start_date: datetime | None = None,
        end_date: datetime | None = None,
        severity: str | None = None,
        suppressed: bool | None = None,
        limit: int = 100,
    ) -> list[FindingMetrics]:
        """Get findings within criteria.

        Args:
            start_date: Start of date range.
            end_date: End of date range.
            severity: Filter by severity.
            suppressed: Filter by suppression status.
            limit: Maximum results.

        Returns:
            List of finding metrics.
        """
        query = "SELECT * FROM findings WHERE 1=1"
        params: list[Any] = []

        if start_date:
            query += " AND detected_at >= ?"
            params.append(start_date.isoformat())
        if end_date:
            query += " AND detected_at <= ?"
            params.append(end_date.isoformat())
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        if suppressed is not None:
            query += " AND suppressed = ?"
            params.append(1 if suppressed else 0)

        query += " ORDER BY detected_at DESC LIMIT ?"
        params.append(limit)

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(query, params)
            rows = cursor.fetchall()

        findings = []
        for row in rows:
            findings.append(
                FindingMetrics(
                    finding_id=row[0],
                    vuln_id=row[2],
                    scanner=row[3],
                    severity=row[4],
                    file_path=row[5],
                    detected_at=datetime.fromisoformat(row[6]),
                    triaged_at=datetime.fromisoformat(row[7]) if row[7] else None,
                    ticket_created_at=datetime.fromisoformat(row[8]) if row[8] else None,
                    ticket_key=row[9],
                    fix_started_at=datetime.fromisoformat(row[10]) if row[10] else None,
                    fix_completed_at=datetime.fromisoformat(row[11]) if row[11] else None,
                    pr_url=row[12],
                    suppressed=bool(row[13]),
                    suppression_reason=row[14],
                    time_to_triage_seconds=row[15],
                    time_to_ticket_seconds=row[16],
                    time_to_fix_seconds=row[17],
                )
            )

        return findings

    # -------------------------------------------------------------------------
    # Aggregate Metrics
    # -------------------------------------------------------------------------

    def get_agent_metrics(
        self,
        period_start: datetime,
        period_end: datetime,
    ) -> AgentMetrics:
        """Calculate agent metrics for a period.

        Args:
            period_start: Start of period.
            period_end: End of period.

        Returns:
            Aggregated agent metrics.
        """
        with sqlite3.connect(self.db_path) as conn:
            # Scan metrics
            scan_stats = conn.execute(
                """
                SELECT
                    COUNT(*) as total,
                    SUM(CASE WHEN completed_at IS NOT NULL THEN 1 ELSE 0 END) as successful,
                    SUM(CASE WHEN completed_at IS NULL THEN 1 ELSE 0 END) as failed,
                    AVG(duration_seconds) as avg_duration
                FROM scans
                WHERE started_at >= ? AND started_at <= ?
            """,
                (period_start.isoformat(), period_end.isoformat()),
            ).fetchone()

            # Finding metrics
            finding_stats = conn.execute(
                """
                SELECT
                    COUNT(*) as total,
                    COUNT(DISTINCT vuln_id) as unique_vulns,
                    SUM(CASE WHEN suppressed = 1 THEN 1 ELSE 0 END) as suppressed,
                    SUM(CASE WHEN triaged_at IS NOT NULL THEN 1 ELSE 0 END) as triaged,
                    AVG(time_to_triage_seconds) as avg_triage_time,
                    SUM(CASE WHEN ticket_key IS NOT NULL THEN 1 ELSE 0 END) as ticketed,
                    AVG(time_to_ticket_seconds) as avg_ticket_time,
                    SUM(CASE WHEN fix_started_at IS NOT NULL THEN 1 ELSE 0 END) as fix_attempted,
                    SUM(CASE WHEN fix_completed_at IS NOT NULL THEN 1 ELSE 0 END) as fix_successful,
                    AVG(time_to_fix_seconds) as avg_fix_time,
                    SUM(CASE WHEN pr_url IS NOT NULL THEN 1 ELSE 0 END) as prs_created
                FROM findings
                WHERE detected_at >= ? AND detected_at <= ?
            """,
                (period_start.isoformat(), period_end.isoformat()),
            ).fetchone()

        total_scans = scan_stats[0] or 0
        successful_scans = scan_stats[1] or 0
        failed_scans = scan_stats[2] or 0
        avg_scan_duration = scan_stats[3] or 0.0

        total_findings = finding_stats[0] or 0
        unique_vulns = finding_stats[1] or 0
        suppressed = finding_stats[2] or 0
        triaged = finding_stats[3] or 0
        avg_triage_time = finding_stats[4] or 0.0
        ticketed = finding_stats[5] or 0
        avg_ticket_time = finding_stats[6] or 0.0
        fix_attempted = finding_stats[7] or 0
        fix_successful = finding_stats[8] or 0
        avg_fix_time = finding_stats[9] or 0.0
        prs_created = finding_stats[10] or 0

        fix_success_rate = (fix_successful / fix_attempted) if fix_attempted > 0 else 0.0

        return AgentMetrics(
            period_start=period_start,
            period_end=period_end,
            total_scans=total_scans,
            successful_scans=successful_scans,
            failed_scans=failed_scans,
            avg_scan_duration_seconds=avg_scan_duration,
            total_findings=total_findings,
            unique_vulnerabilities=unique_vulns,
            suppressed_findings=suppressed,
            triaged_findings=triaged,
            avg_triage_time_seconds=avg_triage_time,
            tickets_created=ticketed,
            avg_time_to_ticket_seconds=avg_ticket_time,
            fixes_attempted=fix_attempted,
            fixes_successful=fix_successful,
            fix_success_rate=fix_success_rate,
            avg_time_to_fix_seconds=avg_fix_time,
            prs_created=prs_created,
        )

    def get_dashboard_summary(self) -> DashboardSummary:
        """Get summary data for dashboard display.

        Returns:
            Dashboard summary with current status and metrics.
        """
        now = datetime.utcnow()
        today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        week_start = today_start - timedelta(days=today_start.weekday())

        with sqlite3.connect(self.db_path) as conn:
            # Last scan
            last_scan = conn.execute(
                "SELECT started_at FROM scans ORDER BY started_at DESC LIMIT 1"
            ).fetchone()

            # Today's metrics
            today_scans = conn.execute(
                "SELECT COUNT(*) FROM scans WHERE started_at >= ?",
                (today_start.isoformat(),),
            ).fetchone()[0]

            today_findings = conn.execute(
                "SELECT COUNT(*) FROM findings WHERE detected_at >= ?",
                (today_start.isoformat(),),
            ).fetchone()[0]

            today_tickets = conn.execute(
                "SELECT COUNT(*) FROM findings WHERE ticket_created_at >= ?",
                (today_start.isoformat(),),
            ).fetchone()[0]

            today_fixes = conn.execute(
                "SELECT COUNT(*) FROM findings WHERE fix_completed_at >= ?",
                (today_start.isoformat(),),
            ).fetchone()[0]

            # Week's metrics
            week_scans = conn.execute(
                "SELECT COUNT(*) FROM scans WHERE started_at >= ?",
                (week_start.isoformat(),),
            ).fetchone()[0]

            week_findings = conn.execute(
                "SELECT COUNT(*) FROM findings WHERE detected_at >= ?",
                (week_start.isoformat(),),
            ).fetchone()[0]

            week_tickets = conn.execute(
                "SELECT COUNT(*) FROM findings WHERE ticket_created_at >= ?",
                (week_start.isoformat(),),
            ).fetchone()[0]

            week_fixes = conn.execute(
                "SELECT COUNT(*) FROM findings WHERE fix_completed_at >= ?",
                (week_start.isoformat(),),
            ).fetchone()[0]

            # All-time metrics
            total_scans = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
            total_findings = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
            total_tickets = conn.execute(
                "SELECT COUNT(*) FROM findings WHERE ticket_key IS NOT NULL"
            ).fetchone()[0]
            total_fixes = conn.execute(
                "SELECT COUNT(*) FROM findings WHERE fix_completed_at IS NOT NULL"
            ).fetchone()[0]
            total_prs = conn.execute(
                "SELECT COUNT(*) FROM findings WHERE pr_url IS NOT NULL"
            ).fetchone()[0]

            # Recent findings
            recent_findings_rows = conn.execute(
                """
                SELECT finding_id, vuln_id, severity, file_path, detected_at
                FROM findings
                ORDER BY detected_at DESC
                LIMIT 10
            """
            ).fetchall()

            recent_tickets_rows = conn.execute(
                """
                SELECT finding_id, ticket_key, severity, detected_at, ticket_created_at
                FROM findings
                WHERE ticket_key IS NOT NULL
                ORDER BY ticket_created_at DESC
                LIMIT 10
            """
            ).fetchall()

            recent_fixes_rows = conn.execute(
                """
                SELECT finding_id, pr_url, severity, fix_completed_at
                FROM findings
                WHERE fix_completed_at IS NOT NULL
                ORDER BY fix_completed_at DESC
                LIMIT 10
            """
            ).fetchall()

        # Calculate effectiveness (simplified)
        effectiveness = 0.0
        if total_findings > 0:
            triage_rate = total_tickets / total_findings
            fix_rate = total_fixes / total_findings if total_findings > 0 else 0
            effectiveness = (triage_rate + fix_rate) / 2

        return DashboardSummary(
            agent_status="running",
            last_scan_at=datetime.fromisoformat(last_scan[0]) if last_scan else None,
            scans_today=today_scans,
            findings_today=today_findings,
            tickets_today=today_tickets,
            fixes_today=today_fixes,
            scans_this_week=week_scans,
            findings_this_week=week_findings,
            tickets_this_week=week_tickets,
            fixes_this_week=week_fixes,
            total_scans=total_scans,
            total_findings=total_findings,
            total_tickets=total_tickets,
            total_fixes=total_fixes,
            total_prs_merged=total_prs,
            overall_effectiveness=effectiveness,
            time_saved_hours=(total_tickets * 0.25 + total_fixes * 2) / 60,  # Estimated
            recent_findings=[
                {
                    "id": r[0],
                    "vuln_id": r[1],
                    "severity": r[2],
                    "file": r[3],
                    "detected_at": r[4],
                }
                for r in recent_findings_rows
            ],
            recent_tickets=[
                {
                    "finding_id": r[0],
                    "ticket_key": r[1],
                    "severity": r[2],
                    "detected_at": r[3],
                    "created_at": r[4],
                }
                for r in recent_tickets_rows
            ],
            recent_fixes=[
                {
                    "finding_id": r[0],
                    "pr_url": r[1],
                    "severity": r[2],
                    "completed_at": r[3],
                }
                for r in recent_fixes_rows
            ],
        )

    def record_roi_metrics(self, roi: ROIMetrics) -> None:
        """Record ROI metrics snapshot.

        Args:
            roi: ROI metrics to record.
        """
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO roi_metrics
                (period_start, period_end, llm_cost_usd, compute_cost_usd,
                 total_value_usd, roi_percentage, time_saved_hours, effectiveness_score)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    roi.period_start.isoformat(),
                    roi.period_end.isoformat(),
                    roi.llm_api_cost_usd,
                    roi.compute_cost_usd,
                    roi.total_value_usd,
                    roi.roi_percentage,
                    roi.total_time_saved_hours,
                    roi.overall_effectiveness,
                ),
            )
            conn.commit()

        logger.info(
            "Recorded ROI metrics",
            roi=f"{roi.roi_percentage:.1f}%",
            value=f"${roi.total_value_usd:.2f}",
        )

    def get_roi_history(self, limit: int = 12) -> list[dict[str, Any]]:
        """Get ROI metrics history.

        Args:
            limit: Maximum records to return.

        Returns:
            List of ROI metric records.
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                """
                SELECT period_start, period_end, llm_cost_usd, compute_cost_usd,
                       total_value_usd, roi_percentage, time_saved_hours, effectiveness_score
                FROM roi_metrics
                ORDER BY period_end DESC
                LIMIT ?
            """,
                (limit,),
            )
            rows = cursor.fetchall()

        return [
            {
                "period_start": row[0],
                "period_end": row[1],
                "llm_cost": row[2],
                "compute_cost": row[3],
                "total_value": row[4],
                "roi_percentage": row[5],
                "time_saved_hours": row[6],
                "effectiveness": row[7],
            }
            for row in rows
        ]