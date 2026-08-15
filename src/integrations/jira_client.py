"""Jira API client — async HTTP client for Jira Cloud/Server.

Provides methods for:
- Creating and updating issues
- Adding comments and attachments
- Transitioning issues
- Searching issues
"""

from __future__ import annotations

import base64
from typing import Any

import httpx

from src.utils.logger import get_logger

logger = get_logger(__name__)


class JiraClient:
    """Async Jira REST API client.

    Supports both Jira Cloud and Jira Server with basic authentication.
    """

    def __init__(
        self,
        base_url: str,
        email: str,
        api_token: str,
        timeout: float = 30.0,
    ) -> None:
        """Initialize the Jira client.

        Args:
            base_url: Jira instance URL (e.g., https://org.atlassian.net).
            email: User email for authentication.
            api_token: API token for authentication.
            timeout: Request timeout in seconds.
        """
        self.base_url = base_url.rstrip("/")
        self.email = email
        self.api_token = api_token
        self.timeout = timeout

        # Build auth header
        auth_string = f"{email}:{api_token}"
        auth_bytes = base64.b64encode(auth_string.encode()).decode()
        self._auth_header = f"Basic {auth_bytes}"

        self._client: httpx.AsyncClient | None = None

        logger.info("Jira client initialized", base_url=base_url)

    @property
    def client(self) -> httpx.AsyncClient:
        """Get or create HTTP client."""
        if self._client is None:
            self._client = httpx.AsyncClient(
                base_url=self.base_url,
                headers={
                    "Authorization": self._auth_header,
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                },
                timeout=self.timeout,
            )
        return self._client

    async def close(self) -> None:
        """Close the HTTP client."""
        if self._client:
            await self._client.aclose()
            self._client = None

    async def create_issue(
        self,
        project_key: str,
        issue_type: str,
        summary: str,
        description: str,
        priority: str = "Medium",
        labels: list[str] | None = None,
        component: str | None = None,
        custom_fields: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Create a new Jira issue.

        Args:
            project_key: Project key (e.g., "CRA").
            issue_type: Issue type (e.g., "Bug", "Task").
            summary: Issue summary.
            description: Issue description.
            priority: Priority level.
            labels: List of labels.
            component: Component name.
            custom_fields: Additional custom fields.

        Returns:
            Dict with issue key and URL.
        """
        fields: dict[str, Any] = {
            "project": {"key": project_key},
            "issuetype": {"name": issue_type},
            "summary": summary,
            "description": description,
            "priority": {"name": priority},
        }

        if labels:
            fields["labels"] = labels

        if component:
            fields["components"] = [{"name": component}]

        if custom_fields:
            fields.update(custom_fields)

        payload = {"fields": fields}

        try:
            response = await self.client.post("/rest/api/3/issue", json=payload)
            response.raise_for_status()

            data = response.json()
            issue_key = data["key"]
            issue_url = f"{self.base_url}/browse/{issue_key}"

            logger.info("Created Jira issue", key=issue_key, url=issue_url)

            return {
                "key": issue_key,
                "id": data["id"],
                "url": issue_url,
                "status": "Open",
            }

        except httpx.HTTPStatusError as e:
            logger.error(
                "Failed to create Jira issue",
                status=e.response.status_code,
                error=e.response.text,
            )
            raise

    async def add_comment(self, issue_key: str, comment: str) -> dict[str, Any]:
        """Add a comment to an issue.

        Args:
            issue_key: Issue key.
            comment: Comment text.

        Returns:
            Comment data.
        """
        payload = {
            "body": {
                "type": "doc",
                "version": 1,
                "content": [
                    {
                        "type": "paragraph",
                        "content": [{"type": "text", "text": comment}],
                    }
                ],
            }
        }

        try:
            response = await self.client.post(
                f"/rest/api/3/issue/{issue_key}/comment",
                json=payload,
            )
            response.raise_for_status()

            logger.debug("Added comment", issue=issue_key)
            return response.json()

        except httpx.HTTPStatusError as e:
            logger.error("Failed to add comment", issue=issue_key, error=str(e))
            raise

    async def transition_issue(self, issue_key: str, transition_name: str) -> bool:
        """Transition an issue to a new status.

        Args:
            issue_key: Issue key.
            transition_name: Target status name.

        Returns:
            True if transition succeeded.
        """
        # First, get available transitions
        try:
            response = await self.client.get(f"/rest/api/3/issue/{issue_key}/transitions")
            response.raise_for_status()
            transitions = response.json().get("transitions", [])

            # Find matching transition
            transition_id = None
            for t in transitions:
                if t["name"].lower() == transition_name.lower():
                    transition_id = t["id"]
                    break

            if not transition_id:
                logger.warning(
                    "Transition not found",
                    issue=issue_key,
                    transition=transition_name,
                )
                return False

            # Execute transition
            payload = {"transition": {"id": transition_id}}
            response = await self.client.post(
                f"/rest/api/3/issue/{issue_key}/transitions",
                json=payload,
            )
            response.raise_for_status()

            logger.info("Transitioned issue", issue=issue_key, transition=transition_name)
            return True

        except httpx.HTTPStatusError as e:
            logger.error("Failed to transition issue", issue=issue_key, error=str(e))
            return False

    async def add_labels(self, issue_key: str, labels: list[str]) -> bool:
        """Add labels to an issue.

        Args:
            issue_key: Issue key.
            labels: Labels to add.

        Returns:
            True if labels were added.
        """
        payload = {"update": {"labels": [{"add": label} for label in labels]}}

        try:
            response = await self.client.put(
                f"/rest/api/3/issue/{issue_key}",
                json=payload,
            )
            response.raise_for_status()

            logger.debug("Added labels", issue=issue_key, labels=labels)
            return True

        except httpx.HTTPStatusError as e:
            logger.error("Failed to add labels", issue=issue_key, error=str(e))
            return False

    async def attach_file(
        self,
        issue_key: str,
        filename: str,
        content: str | bytes,
    ) -> dict[str, Any]:
        """Attach a file to an issue.

        Args:
            issue_key: Issue key.
            filename: Attachment filename.
            content: File content (string or bytes).

        Returns:
            Attachment data.
        """
        if isinstance(content, str):
            content = content.encode()

        try:
            response = await self.client.post(
                f"/rest/api/3/issue/{issue_key}/attachments",
                headers={"X-Atlassian-Token": "no-check"},
                files={"file": (filename, content)},
            )
            response.raise_for_status()

            logger.debug("Attached file", issue=issue_key, filename=filename)
            return response.json()

        except httpx.HTTPStatusError as e:
            logger.error("Failed to attach file", issue=issue_key, error=str(e))
            raise

    async def get_issue(self, issue_key: str) -> dict[str, Any]:
        """Get issue details.

        Args:
            issue_key: Issue key.

        Returns:
            Issue data.
        """
        try:
            response = await self.client.get(f"/rest/api/3/issue/{issue_key}")
            response.raise_for_status()
            return response.json()

        except httpx.HTTPStatusError as e:
            logger.error("Failed to get issue", issue=issue_key, error=str(e))
            raise

    async def search_issues(
        self,
        jql: str,
        max_results: int = 50,
    ) -> list[dict[str, Any]]:
        """Search for issues using JQL.

        Args:
            jql: JQL query string.
            max_results: Maximum results to return.

        Returns:
            List of issue data.
        """
        payload = {
            "jql": jql,
            "maxResults": max_results,
        }

        try:
            response = await self.client.post("/rest/api/3/search", json=payload)
            response.raise_for_status()

            data = response.json()
            return data.get("issues", [])

        except httpx.HTTPStatusError as e:
            logger.error("Failed to search issues", jql=jql, error=str(e))
            raise
