"""Jira Agent — creates and manages Jira tickets for vulnerabilities.

This agent:
- Creates Jira tickets for triaged findings
- Attaches scan evidence and context
- Sets appropriate priority, labels, and components
- Updates tickets based on agent actions
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from src.core.models import JiraTicket, TriagedFinding
from src.utils.logger import get_logger

if TYPE_CHECKING:
    from src.integrations.jira_client import JiraClient

logger = get_logger(__name__)


class JiraAgent:
    """Creates and manages Jira tickets for vulnerability findings.

    Responsibilities:
    - Create tickets with structured descriptions
    - Attach scan evidence (JSON + human-readable)
    - Set priority, labels, and components
    - Update tickets with fix status
    """

    def __init__(
        self,
        jira_client: JiraClient,
        project_key: str = "CRA",
        issue_type: str = "Bug",
        default_labels: list[str] | None = None,
        component: str = "Security",
    ) -> None:
        """Initialize the Jira agent.

        Args:
            jira_client: Jira API client.
            project_key: Jira project key.
            issue_type: Default issue type.
            default_labels: Default labels to apply.
            component: Default component.
        """
        self.jira_client = jira_client
        self.project_key = project_key
        self.issue_type = issue_type
        self.default_labels = default_labels or ["cra-agent", "security", "vulnerability"]
        self.component = component
        logger.info("Jira agent initialized", project=project_key)

    async def create_ticket(self, finding: TriagedFinding) -> JiraTicket:
        """Create a Jira ticket for a single finding.

        Args:
            finding: The triaged finding to create a ticket for.

        Returns:
            Created JiraTicket object.
        """
        logger.info(
            "Creating Jira ticket",
            finding_id=finding.id,
            vuln_id=finding.vuln_id,
            severity=finding.triage.severity.value,
        )

        # Build ticket content
        summary = self._build_summary(finding)
        description = self._build_description(finding)
        priority = self._map_severity_to_priority(finding.triage.severity.value)
        labels = self._build_labels(finding)

        try:
            # Create the issue
            issue = await self.jira_client.create_issue(
                project_key=self.project_key,
                issue_type=self.issue_type,
                summary=summary,
                description=description,
                priority=priority,
                labels=labels,
                component=self.component,
            )

            # Attach evidence
            await self._attach_evidence(issue["key"], finding)

            ticket = JiraTicket(
                key=issue["key"],
                finding_id=finding.id,
                title=summary,
                status=issue.get("status", "Open"),
                url=issue["url"],
                priority=priority,
                labels=labels,
            )

            logger.info(
                "Jira ticket created",
                key=ticket.key,
                url=ticket.url,
            )

            return ticket

        except Exception as e:
            logger.error("Failed to create Jira ticket", finding_id=finding.id, error=str(e))
            # Return a placeholder ticket
            return JiraTicket(
                key="FAILED",
                finding_id=finding.id,
                title=summary,
                status="Error",
                url="",
                priority=priority,
                labels=labels,
            )

    async def create_tickets(self, findings: list[TriagedFinding]) -> list[JiraTicket]:
        """Create Jira tickets for multiple findings.

        Args:
            findings: List of triaged findings.

        Returns:
            List of created JiraTicket objects.
        """
        logger.info("Creating Jira tickets", count=len(findings))

        tickets: list[JiraTicket] = []

        for finding in findings:
            ticket = await self.create_ticket(finding)
            tickets.append(ticket)

        successful = sum(1 for t in tickets if t.key != "FAILED")
        logger.info(
            "Ticket creation completed",
            total=len(tickets),
            successful=successful,
            failed=len(tickets) - successful,
        )

        return tickets

    async def update_ticket(
        self,
        ticket_key: str,
        comment: str | None = None,
        status: str | None = None,
        labels: list[str] | None = None,
    ) -> bool:
        """Update an existing Jira ticket.

        Args:
            ticket_key: Jira issue key.
            comment: Comment to add.
            status: New status to transition to.
            labels: Labels to add.

        Returns:
            True if update succeeded.
        """
        logger.info("Updating Jira ticket", key=ticket_key)

        try:
            if comment:
                await self.jira_client.add_comment(ticket_key, comment)

            if status:
                await self.jira_client.transition_issue(ticket_key, status)

            if labels:
                await self.jira_client.add_labels(ticket_key, labels)

            logger.info("Jira ticket updated", key=ticket_key)
            return True

        except Exception as e:
            logger.error("Failed to update Jira ticket", key=ticket_key, error=str(e))
            return False

    def _build_summary(self, finding: TriagedFinding) -> str:
        """Build ticket summary.

        Args:
            finding: The finding.

        Returns:
            Ticket summary string.
        """
        vuln_id = finding.vuln_id or finding.id[:8]
        return f"[{finding.triage.severity.value.upper()}] {vuln_id}: {finding.title[:80]}"

    def _build_description(self, finding: TriagedFinding) -> str:
        """Build ticket description in Jira markup.

        Args:
            finding: The finding.

        Returns:
            Formatted description string.
        """
        lines = [
            f"h2. Vulnerability: {finding.vuln_id or finding.id}",
            "",
            f"*Severity*: {finding.triage.severity.value}",
            f"*Exploitability*: {finding.triage.exploitability.value}",
            f"*Scanner*: {finding.scanner}",
            f"*File*: {{code}}{finding.file_path}{{code}}",
            f"*Lines*: {finding.line_start}-{finding.line_end}",
            "",
            "h3. Description",
            finding.description,
            "",
            "h3. Code Snippet",
            "{code}",
            finding.code_snippet or "N/A",
            "{code}",
            "",
            "h3. Triage Assessment",
            f"*Recommended Action*: {finding.triage.recommended_action.value}",
            f"*Reasoning*: {finding.triage.reasoning}",
            "",
        ]

        if finding.triage.fix_suggestion:
            lines.extend([
                "h3. Suggested Fix",
                finding.triage.fix_suggestion,
                "",
            ])

        if finding.cra_mapping:
            lines.extend([
                "h3. CRA Compliance Mapping",
                ", ".join(finding.cra_mapping),
                "",
            ])

        lines.extend([
            "----",
            "_Created by CRA-AGENT_",
        ])

        return "\n".join(lines)

    def _map_severity_to_priority(self, severity: str) -> str:
        """Map severity level to Jira priority.

        Args:
            severity: Severity level string.

        Returns:
            Jira priority string.
        """
        priority_map = {
            "critical": "Highest",
            "high": "High",
            "medium": "Medium",
            "low": "Low",
            "info": "Lowest",
        }
        return priority_map.get(severity, "Medium")

    def _build_labels(self, finding: TriagedFinding) -> list[str]:
        """Build labels for the ticket.

        Args:
            finding: The finding.

        Returns:
            List of labels.
        """
        labels = list(self.default_labels)
        labels.append(f"severity-{finding.triage.severity.value}")
        labels.append(f"scanner-{finding.scanner}")

        if finding.vuln_id:
            labels.append(finding.vuln_id.lower())

        # Add CRA mapping labels
        for cra in finding.cra_mapping:
            if cra != "none":
                labels.append(f"cra-{cra}")

        return labels

    async def _attach_evidence(self, ticket_key: str, finding: TriagedFinding) -> None:
        """Attach scan evidence to a ticket.

        Args:
            ticket_key: Jira issue key.
            finding: The finding with evidence.
        """
        try:
            # Attach JSON evidence
            import json

            evidence = finding.model_dump_json(indent=2)
            await self.jira_client.attach_file(
                ticket_key,
                filename=f"finding-{finding.id}.json",
                content=evidence,
            )

            logger.debug("Attached evidence", ticket=ticket_key, finding_id=finding.id)

        except Exception as e:
            logger.warning("Failed to attach evidence", ticket=ticket_key, error=str(e))