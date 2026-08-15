"""Suppression store — manages vulnerability suppression rules.

SQLite-backed store for tracking which vulnerabilities should be
ignored (known issues, false positives, accepted risks).
"""

from __future__ import annotations

import sqlite3
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING

from src.core.models import Finding, Suppression
from src.utils.logger import get_logger

if TYPE_CHECKING:
    pass

logger = get_logger(__name__)


class SuppressionStore:
    """Manages vulnerability suppression rules in SQLite.

    Suppressions allow the agent to:
    - Ignore known/accepted vulnerabilities
    - Track why a vulnerability was suppressed
    - Link suppressions to Jira tickets
    - Set expiry dates for temporary suppressions
    """

    def __init__(self, db_path: Path) -> None:
        """Initialize the suppression store.

        Args:
            db_path: Path to the SQLite database file.
        """
        self.db_path = db_path
        self._ensure_db_exists()

    def _ensure_db_exists(self) -> None:
        """Create the database and tables if they don't exist."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS suppressions (
                    id TEXT PRIMARY KEY,
                    vuln_id TEXT NOT NULL,
                    file_pattern TEXT,
                    reason TEXT NOT NULL,
                    jira_issue_key TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP,
                    created_by TEXT DEFAULT 'agent'
                )
            """)

            # Create index for faster lookups
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_vuln_id
                ON suppressions(vuln_id)
            """)

            conn.commit()

        logger.info("Suppression store initialized", db_path=str(self.db_path))

    def add_suppression(
        self,
        vuln_id: str,
        reason: str,
        file_pattern: str | None = None,
        jira_issue_key: str | None = None,
        expires_days: int | None = None,
        created_by: str = "agent",
    ) -> Suppression:
        """Add a new suppression rule.

        Args:
            vuln_id: Vulnerability ID to suppress (e.g., CVE-2024-1234).
            reason: Reason for suppression.
            file_pattern: Optional file glob pattern.
            jira_issue_key: Linked Jira ticket.
            expires_days: Days until suppression expires (None = never).
            created_by: Who created the suppression.

        Returns:
            The created Suppression object.
        """
        suppression_id = str(uuid.uuid4())
        expires_at = None
        if expires_days:
            expires_at = datetime.utcnow() + timedelta(days=expires_days)

        suppression = Suppression(
            id=suppression_id,
            vuln_id=vuln_id,
            file_pattern=file_pattern,
            reason=reason,
            jira_issue_key=jira_issue_key,
            created_at=datetime.utcnow(),
            expires_at=expires_at,
            created_by=created_by,
        )

        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO suppressions
                (id, vuln_id, file_pattern, reason, jira_issue_key, created_at, expires_at, created_by)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    suppression.id,
                    suppression.vuln_id,
                    suppression.file_pattern,
                    suppression.reason,
                    suppression.jira_issue_key,
                    suppression.created_at.isoformat(),
                    suppression.expires_at.isoformat() if suppression.expires_at else None,
                    suppression.created_by,
                ),
            )
            conn.commit()

        logger.info(
            "Added suppression",
            vuln_id=vuln_id,
            reason=reason,
            jira_issue_key=jira_issue_key,
        )

        return suppression

    def remove_suppression(self, suppression_id: str) -> bool:
        """Remove a suppression rule.

        Args:
            suppression_id: ID of the suppression to remove.

        Returns:
            True if suppression was removed, False if not found.
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                "DELETE FROM suppressions WHERE id = ?",
                (suppression_id,),
            )
            conn.commit()
            removed = cursor.rowcount > 0

        if removed:
            logger.info("Removed suppression", suppression_id=suppression_id)
        else:
            logger.warning("Suppression not found", suppression_id=suppression_id)

        return removed

    def is_suppressed(self, finding: Finding) -> bool:
        """Check if a finding is suppressed.

        Args:
            finding: The finding to check.

        Returns:
            True if the finding should be suppressed.
        """
        suppressions = self.get_suppressions_for_vuln(finding.vuln_id or "")

        for suppression in suppressions:
            if suppression.matches(finding):
                logger.debug(
                    "Finding suppressed",
                    finding_id=finding.id,
                    vuln_id=finding.vuln_id,
                    suppression_id=suppression.id,
                )
                return True

        return False

    def get_suppressions_for_vuln(self, vuln_id: str) -> list[Suppression]:
        """Get all suppressions for a specific vulnerability ID.

        Args:
            vuln_id: The vulnerability ID.

        Returns:
            List of matching suppressions.
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                "SELECT * FROM suppressions WHERE vuln_id = ?",
                (vuln_id,),
            )
            rows = cursor.fetchall()

        suppressions = []
        for row in rows:
            suppression = Suppression(
                id=row[0],
                vuln_id=row[1],
                file_pattern=row[2],
                reason=row[3],
                jira_issue_key=row[4],
                created_at=datetime.fromisoformat(row[5]),
                expires_at=datetime.fromisoformat(row[6]) if row[6] else None,
                created_by=row[7],
            )
            suppressions.append(suppression)

        return suppressions

    def filter_findings(self, findings: list[Finding]) -> list[Finding]:
        """Filter out suppressed findings.

        Args:
            findings: List of findings to filter.

        Returns:
            Findings that are not suppressed.
        """
        filtered = [f for f in findings if not self.is_suppressed(f)]

        suppressed_count = len(findings) - len(filtered)
        if suppressed_count > 0:
            logger.info(
                "Filtered suppressed findings",
                total=len(findings),
                suppressed=suppressed_count,
                remaining=len(filtered),
            )

        return filtered

    def get_all_suppressions(self) -> list[Suppression]:
        """Get all suppression rules.

        Returns:
            List of all suppressions.
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("SELECT * FROM suppressions ORDER BY created_at DESC")
            rows = cursor.fetchall()

        suppressions = []
        for row in rows:
            suppression = Suppression(
                id=row[0],
                vuln_id=row[1],
                file_pattern=row[2],
                reason=row[3],
                jira_issue_key=row[4],
                created_at=datetime.fromisoformat(row[5]),
                expires_at=datetime.fromisoformat(row[6]) if row[6] else None,
                created_by=row[7],
            )
            suppressions.append(suppression)

        return suppressions

    def cleanup_expired(self) -> int:
        """Remove expired suppressions.

        Returns:
            Number of suppressions removed.
        """
        now = datetime.utcnow().isoformat()

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                "DELETE FROM suppressions WHERE expires_at IS NOT NULL AND expires_at < ?",
                (now,),
            )
            conn.commit()
            removed = cursor.rowcount

        if removed > 0:
            logger.info("Cleaned up expired suppressions", count=removed)

        return removed