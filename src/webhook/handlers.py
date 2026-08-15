"""Jira webhook event handlers.

Processes Jira webhook events and routes them to appropriate actions:
- Issue transitions (Ignore → suppress, Fix Required → fix)
- Comments (parse commands)
- Status changes
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from src.core.models import JiraWebhookEvent
from src.utils.logger import get_logger

if TYPE_CHECKING:
    from src.integrations.git_client import GitClient
    from src.integrations.jira_client import JiraClient
    from src.integrations.llm_client import LLMClient
    from src.scanners.suppression_store import SuppressionStore

logger = get_logger(__name__)


# Transition names that trigger suppression
SUPPRESS_TRANSITIONS = {
    "won't fix",
    "ignore",
    "known issue",
    "duplicate",
    "rejected",
    "false positive",
    "accepted risk",
}

# Transition names that trigger fix workflow
FIX_TRANSITIONS = {
    "fix required",
    "to do",
    "in progress",
    "start fix",
}

# Transition names that trigger re-scan
RESCAN_TRANSITIONS = {
    "reopened",
    "reopen",
}


class JiraWebhookHandler:
    """Handles Jira webhook events and routes to appropriate actions.

    Responsibilities:
    - Parse webhook payloads
    - Route transitions to suppress/fix/rescan actions
    - Update suppression store based on Jira decisions
    - Trigger fix workflows
    """

    def __init__(
        self,
        jira_client: JiraClient,
        llm_client: LLMClient,
        git_client: GitClient,
        suppression_store: SuppressionStore,
    ) -> None:
        """Initialize the webhook handler.

        Args:
            jira_client: Jira API client.
            llm_client: LLM client.
            git_client: Git operations client.
            suppression_store: Suppression rules store.
        """
        self.jira_client = jira_client
        self.llm_client = llm_client
        self.git_client = git_client
        self.suppression_store = suppression_store

        logger.info("Jira webhook handler initialized")

    async def handle_event(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Handle a Jira webhook event.

        Args:
            payload: Raw webhook payload.

        Returns:
            Result dict with action taken.
        """
        # Parse the webhook event
        event = self._parse_event(payload)

        logger.info(
            "Processing webhook event",
            event=event.webhook_event,
            issue_key=event.issue_key,
            transition=event.transition_name,
        )

        # Route based on event type
        if event.webhook_event == "jira:issue_updated":
            return await self._handle_issue_updated(event)
        elif event.webhook_event == "comment_created":
            return await self._handle_comment_created(event)
        elif event.webhook_event == "jira:issue_created":
            return await self._handle_issue_created(event)
        else:
            logger.debug("Ignoring webhook event", event=event.webhook_event)
            return {"action": "ignored", "reason": "unsupported event type"}

    def _parse_event(self, payload: dict[str, Any]) -> JiraWebhookEvent:
        """Parse webhook payload into JiraWebhookEvent.

        Args:
            payload: Raw webhook payload.

        Returns:
            Parsed JiraWebhookEvent.
        """
        webhook_event = payload.get("webhookEvent", "")

        # Extract issue information
        issue = payload.get("issue", {})
        issue_key = issue.get("key", "")
        issue_id = issue.get("id", "")

        # Extract transition information
        transition_name = None
        changelog = payload.get("changelog", {})
        items = changelog.get("items", [])

        for item in items:
            if item.get("field") == "status":
                transition_name = item.get("toString", "")
                break

        # Extract comment information
        comment_body = None
        comment = payload.get("comment", {})
        if comment:
            comment_body = comment.get("body", "")

        # Extract user information
        user = payload.get("user", {})
        user_name = user.get("displayName", "")
        user_email = user.get("emailAddress", "")

        return JiraWebhookEvent(
            webhook_event=webhook_event,
            issue_key=issue_key,
            issue_id=issue_id,
            transition_name=transition_name,
            comment_body=comment_body,
            user_name=user_name,
            user_email=user_email,
            changelog_items=items,
            raw_payload=payload,
        )

    async def _handle_issue_updated(self, event: JiraWebhookEvent) -> dict[str, Any]:
        """Handle issue update events.

        Routes to suppress/fix/rescan based on transition.

        Args:
            event: Parsed webhook event.

        Returns:
            Result dict.
        """
        if not event.transition_name:
            return {"action": "ignored", "reason": "no transition"}

        transition_lower = event.transition_name.lower()

        # Check for suppress transitions
        if any(t in transition_lower for t in SUPPRESS_TRANSITIONS):
            return await self._handle_suppress(event)

        # Check for fix transitions
        if any(t in transition_lower for t in FIX_TRANSITIONS):
            return await self._handle_fix(event)

        # Check for rescan transitions
        if any(t in transition_lower for t in RESCAN_TRANSITIONS):
            return await self._handle_rescan(event)

        return {"action": "ignored", "reason": "unrecognized transition"}

    async def _handle_suppress(self, event: JiraWebhookEvent) -> dict[str, Any]:
        """Handle suppression transition.

        Adds a suppression rule for the vulnerability.

        Args:
            event: Parsed webhook event.

        Returns:
            Result dict.
        """
        logger.info(
            "Processing suppress transition",
            issue_key=event.issue_key,
            transition=event.transition_name,
        )

        # Get issue details to extract vulnerability ID
        try:
            issue = await self.jira_client.get_issue(event.issue_key)
            vuln_id = self._extract_vuln_id_from_issue(issue)

            if not vuln_id:
                logger.warning("Could not extract vuln_id from issue", issue_key=event.issue_key)
                return {"action": "suppress", "status": "failed", "reason": "no vuln_id"}

            # Add suppression
            suppression = self.suppression_store.add_suppression(
                vuln_id=vuln_id,
                reason=f"Suppressed via Jira: {event.transition_name}",
                jira_issue_key=event.issue_key,
                created_by=event.user_name or "jira-webhook",
            )

            # Add comment to Jira confirming suppression
            await self.jira_client.add_comment(
                event.issue_key,
                f"CRA-AGENT: Suppression rule added for {vuln_id}. Future scans will ignore this vulnerability.",
            )

            logger.info(
                "Suppression added via webhook",
                vuln_id=vuln_id,
                issue_key=event.issue_key,
            )

            return {
                "action": "suppress",
                "status": "success",
                "vuln_id": vuln_id,
                "suppression_id": suppression.id,
            }

        except Exception as e:
            logger.error("Suppress handling failed", error=str(e))
            return {"action": "suppress", "status": "error", "error": str(e)}

    async def _handle_fix(self, event: JiraWebhookEvent) -> dict[str, Any]:
        """Handle fix transition.

        Triggers the fix workflow for the vulnerability.

        Args:
            event: Parsed webhook event.

        Returns:
            Result dict.
        """
        logger.info(
            "Processing fix transition",
            issue_key=event.issue_key,
            transition=event.transition_name,
        )

        try:
            # Get issue details
            issue = await self.jira_client.get_issue(event.issue_key)
            vuln_id = self._extract_vuln_id_from_issue(issue)

            if not vuln_id:
                return {"action": "fix", "status": "failed", "reason": "no vuln_id"}

            # Add comment acknowledging fix request
            await self.jira_client.add_comment(
                event.issue_key,
                f"CRA-AGENT: Fix workflow initiated for {vuln_id}. A pull request will be created shortly.",
            )

            # TODO: Trigger actual fix workflow
            # This would involve:
            # 1. Finding the original finding
            # 2. Running FixerAgent
            # 3. Creating PR
            # 4. Updating Jira with PR link

            logger.info("Fix workflow triggered", vuln_id=vuln_id, issue_key=event.issue_key)

            return {
                "action": "fix",
                "status": "initiated",
                "vuln_id": vuln_id,
                "issue_key": event.issue_key,
            }

        except Exception as e:
            logger.error("Fix handling failed", error=str(e))
            return {"action": "fix", "status": "error", "error": str(e)}

    async def _handle_rescan(self, event: JiraWebhookEvent) -> dict[str, Any]:
        """Handle rescan transition.

        Triggers a re-scan for the vulnerability.

        Args:
            event: Parsed webhook event.

        Returns:
            Result dict.
        """
        logger.info(
            "Processing rescan transition",
            issue_key=event.issue_key,
            transition=event.transition_name,
        )

        try:
            issue = await self.jira_client.get_issue(event.issue_key)
            vuln_id = self._extract_vuln_id_from_issue(issue)

            # Remove any existing suppressions for this vuln
            suppressions = self.suppression_store.get_suppressions_for_vuln(vuln_id or "")
            for suppression in suppressions:
                if suppression.jira_issue_key == event.issue_key:
                    self.suppression_store.remove_suppression(suppression.id)

            await self.jira_client.add_comment(
                event.issue_key,
                f"CRA-AGENT: Suppression removed for {vuln_id}. Vulnerability will be re-scanned on next commit.",
            )

            return {
                "action": "rescan",
                "status": "success",
                "vuln_id": vuln_id,
            }

        except Exception as e:
            logger.error("Rescan handling failed", error=str(e))
            return {"action": "rescan", "status": "error", "error": str(e)}

    async def _handle_comment_created(self, event: JiraWebhookEvent) -> dict[str, Any]:
        """Handle comment created events.

        Parses commands from comments (e.g., @cra-agent suppress).

        Args:
            event: Parsed webhook event.

        Returns:
            Result dict.
        """
        if not event.comment_body:
            return {"action": "ignored", "reason": "no comment body"}

        comment_lower = event.comment_body.lower()

        # Check for @cra-agent commands
        if "@cra-agent" not in comment_lower:
            return {"action": "ignored", "reason": "no command"}

        # Parse command
        if "suppress" in comment_lower:
            return await self._handle_suppress(event)
        elif "fix" in comment_lower:
            return await self._handle_fix(event)
        elif "rescan" in comment_lower:
            return await self._handle_rescan(event)

        return {"action": "ignored", "reason": "unrecognized command"}

    async def _handle_issue_created(self, event: JiraWebhookEvent) -> dict[str, Any]:
        """Handle issue created events.

        Currently just logs the creation.

        Args:
            event: Parsed webhook event.

        Returns:
            Result dict.
        """
        logger.info("Issue created", issue_key=event.issue_key)
        return {"action": "logged", "issue_key": event.issue_key}

    def _extract_vuln_id_from_issue(self, issue: dict[str, Any]) -> str | None:
        """Extract vulnerability ID from Jira issue.

        Looks in:
        - Issue summary (e.g., "[HIGH] CVE-2024-1234: ...")
        - Labels
        - Description

        Args:
            issue: Jira issue data.

        Returns:
            Vulnerability ID or None.
        """
        fields = issue.get("fields", {})

        # Check summary
        summary = fields.get("summary", "")
        if "CVE-" in summary or "CWE-" in summary:
            # Extract CVE/CWE pattern
            import re

            match = re.search(r"(CVE-\d{4}-\d+|CWE-\d+)", summary)
            if match:
                return match.group(1)

        # Check labels
        labels = fields.get("labels", [])
        for label in labels:
            if label.startswith("cve-") or label.startswith("cwe-"):
                return label.upper()

        # Check description
        description = fields.get("description", "")
        if isinstance(description, str):
            import re

            match = re.search(r"(CVE-\d{4}-\d+|CWE-\d+)", description)
            if match:
                return match.group(1)

        return None
