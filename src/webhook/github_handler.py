"""GitHub webhook handler — processes GitHub push and PR events.

Handles:
- Push events: Triggers scan on new commits
- Pull request events: Scans PR changes
- Webhook signature verification
"""

from __future__ import annotations

import asyncio
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from src.core.diff_analyzer import DiffAnalyzer
from src.core.models import ChangeType, CommitInfo, FileChange
from src.utils.logger import get_logger

if TYPE_CHECKING:
    from src.integrations.github_client import GitHubClient

logger = get_logger(__name__)


class GitHubWebhookHandler:
    """Handler for GitHub webhook events.

    Processes:
    - push events → trigger scan workflow
    - pull_request events → scan PR changes
    """

    def __init__(
        self,
        github_client: GitHubClient,
        webhook_secret: str = "",
        repos_dir: Path | None = None,
        scan_callback: Any = None,
    ) -> None:
        """Initialize the GitHub webhook handler.

        Args:
            github_client: GitHub API client.
            webhook_secret: Webhook secret for signature verification.
            repos_dir: Directory to clone repos into.
            scan_callback: Async function to call when scan is needed.
        """
        self.github_client = github_client
        self.webhook_secret = webhook_secret
        self.repos_dir = repos_dir or Path("./repos")
        self.scan_callback = scan_callback

        self.repos_dir.mkdir(parents=True, exist_ok=True)

        logger.info("GitHub webhook handler initialized")

    def verify_signature(self, payload: bytes, signature: str) -> bool:
        """Verify GitHub webhook signature.

        Args:
            payload: Raw request body.
            signature: X-Hub-Signature-256 header.

        Returns:
            True if signature is valid.
        """
        if not self.webhook_secret:
            logger.warning("No webhook secret configured, skipping verification")
            return True

        return self.github_client.verify_webhook_signature(
            payload, signature, self.webhook_secret
        )

    async def handle_event(
        self,
        event_type: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        """Route webhook event to appropriate handler.

        Args:
            event_type: GitHub event type (X-GitHub-Event header).
            payload: Parsed webhook payload.

        Returns:
            Result dictionary.
        """
        logger.info("Processing GitHub webhook", event_type=event_type)

        handlers = {
            "push": self._handle_push,
            "pull_request": self._handle_pull_request,
            "ping": self._handle_ping,
            "installation": self._handle_installation,
        }

        handler = handlers.get(event_type)
        if handler:
            return await handler(payload)

        logger.debug("Ignoring unhandled event type", event_type=event_type)
        return {"status": "ignored", "reason": f"Unhandled event: {event_type}"}

    async def _handle_ping(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Handle ping event (webhook test).

        Args:
            payload: Webhook payload.

        Returns:
            Result dictionary.
        """
        zen = payload.get("zen", "")
        logger.info("GitHub ping received", zen=zen)
        return {"status": "ok", "zen": zen}

    async def _handle_installation(
        self, payload: dict[str, Any]
    ) -> dict[str, Any]:
        """Handle installation events (app installed/removed).

        Args:
            payload: Webhook payload.

        Returns:
            Result dictionary.
        """
        action = payload.get("action", "")
        installation = payload.get("installation", {})
        installation_id = installation.get("id", "")

        logger.info(
            "GitHub App installation event",
            action=action,
            installation_id=installation_id,
        )

        if action == "created":
            # App was installed on new repos
            repositories = payload.get("repositories", [])
            logger.info(
                "App installed on repositories",
                count=len(repositories),
                repos=[r.get("full_name") for r in repositories],
            )

        return {"status": "ok", "action": action}

    async def _handle_push(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Handle push event (new commits).

        Args:
            payload: Webhook payload.

        Returns:
            Result dictionary.
        """
        # Extract push information
        ref = payload.get("ref", "")
        before = payload.get("before", "")
        after = payload.get("after", "")
        repository = payload.get("repository", {})
        commits = payload.get("commits", [])
        pusher = payload.get("pusher", {})

        # Parse ref to get branch name
        branch = ref.replace("refs/heads/", "") if ref.startswith("refs/heads/") else ref

        repo_full_name = repository.get("full_name", "")
        owner = repository.get("owner", {}).get("login", "")
        repo_name = repository.get("name", "")

        logger.info(
            "Push event received",
            repo=repo_full_name,
            branch=branch,
            commits=len(commits),
            pusher=pusher.get("name", ""),
        )

        # Skip if this is a branch deletion
        if after == "0" * 40:
            logger.info("Branch deletion detected, skipping scan")
            return {"status": "skipped", "reason": "branch_deleted"}

        # Process each commit
        results = []
        for commit in commits:
            commit_sha = commit.get("id", "")
            commit_message = commit.get("message", "")
            commit_author = commit.get("author", {})

            # Build commit info
            commit_info = CommitInfo(
                sha=commit_sha,
                message=commit_message,
                author=commit_author.get("name", ""),
                author_email=commit_author.get("email", ""),
                timestamp=datetime.fromisoformat(
                    commit.get("timestamp", datetime.utcnow().isoformat())
                ),
                branch=branch,
            )

            # Get changed files from commit
            added = commit.get("added", [])
            modified = commit.get("modified", [])
            removed = commit.get("removed", [])

            file_changes: list[FileChange] = []

            for file_path in added:
                file_changes.append(
                    FileChange(
                        file_path=file_path,
                        change_type=ChangeType.ADDED,
                        file_extension=Path(file_path).suffix,
                        language=self._detect_language(file_path),
                    )
                )

            for file_path in modified:
                file_changes.append(
                    FileChange(
                        file_path=file_path,
                        change_type=ChangeType.MODIFIED,
                        file_extension=Path(file_path).suffix,
                        language=self._detect_language(file_path),
                    )
                )

            for file_path in removed:
                file_changes.append(
                    FileChange(
                        file_path=file_path,
                        change_type=ChangeType.DELETED,
                        file_extension=Path(file_path).suffix,
                        language=self._detect_language(file_path),
                    )
                )

            logger.info(
                "Commit processed",
                sha=commit_sha[:7],
                files_changed=len(file_changes),
            )

            # Set pending status
            await self.github_client.set_commit_status(
                owner=owner,
                repo=repo_name,
                sha=commit_sha,
                state="pending",
                description="CRA-AGENT scan in progress...",
                context="cra-agent/security",
            )

            # Trigger scan callback if configured
            if self.scan_callback and file_changes:
                try:
                    # Clone/update repo locally
                    repo_path = self.github_client.clone_repo(
                        owner=owner,
                        repo=repo_name,
                        target_dir=self.repos_dir,
                        branch=branch,
                    )

                    # Call scan callback
                    scan_result = await self.scan_callback(
                        repo_path=repo_path,
                        commit_info=commit_info,
                        file_changes=file_changes,
                    )

                    # Set success status
                    findings_count = scan_result.get("findings_count", 0)
                    await self.github_client.set_commit_status(
                        owner=owner,
                        repo=repo_name,
                        sha=commit_sha,
                        state="success" if findings_count == 0 else "failure",
                        description=f"Found {findings_count} issues" if findings_count else "No issues found",
                        context="cra-agent/security",
                        target_url=scan_result.get("dashboard_url", ""),
                    )

                    results.append({
                        "commit": commit_sha[:7],
                        "status": "scanned",
                        "findings": findings_count,
                    })

                except Exception as e:
                    logger.error(
                        "Scan failed for commit",
                        commit=commit_sha[:7],
                        error=str(e),
                    )

                    await self.github_client.set_commit_status(
                        owner=owner,
                        repo=repo_name,
                        sha=commit_sha,
                        state="error",
                        description=f"Scan error: {str(e)[:100]}",
                        context="cra-agent/security",
                    )

                    results.append({
                        "commit": commit_sha[:7],
                        "status": "error",
                        "error": str(e),
                    })

        return {
            "status": "processed",
            "repo": repo_full_name,
            "branch": branch,
            "commits_scanned": len(results),
            "results": results,
        }

    async def _handle_pull_request(
        self, payload: dict[str, Any]
    ) -> dict[str, Any]:
        """Handle pull request events.

        Args:
            payload: Webhook payload.

        Returns:
            Result dictionary.
        """
        action = payload.get("action", "")
        pr = payload.get("pull_request", {})
        repository = payload.get("repository", {})

        pr_number = pr.get("number", 0)
        pr_title = pr.get("title", "")
        head_sha = pr.get("head", {}).get("sha", "")
        head_ref = pr.get("head", {}).get("ref", "")
        base_ref = pr.get("base", {}).get("ref", "")

        owner = repository.get("owner", {}).get("login", "")
        repo_name = repository.get("name", "")

        logger.info(
            "Pull request event",
            action=action,
            pr_number=pr_number,
            title=pr_title[:50],
        )

        # Only process opened and synchronize events
        if action not in ("opened", "synchronize", "reopened"):
            return {"status": "ignored", "reason": f"action_{action}"}

        # Set pending status
        await self.github_client.set_commit_status(
            owner=owner,
            repo=repo_name,
            sha=head_sha,
            state="pending",
            description="CRA-AGENT scanning PR changes...",
            context="cra-agent/security",
        )

        # Get changed files in PR
        try:
            files = await self.github_client.get_commit_diff(
                owner=owner, repo=repo_name, sha=head_sha
            )

            file_changes: list[FileChange] = []
            for f in files:
                status = f.get("status", "modified")
                change_type = {
                    "added": ChangeType.ADDED,
                    "modified": ChangeType.MODIFIED,
                    "removed": ChangeType.DELETED,
                    "renamed": ChangeType.RENAMED,
                }.get(status, ChangeType.MODIFIED)

                file_changes.append(
                    FileChange(
                        file_path=f.get("filename", ""),
                        change_type=change_type,
                        file_extension=Path(f.get("filename", "")).suffix,
                        language=self._detect_language(f.get("filename", "")),
                        patch=f.get("patch", ""),
                    )
                )

            # Trigger scan if callback configured
            if self.scan_callback and file_changes:
                repo_path = self.github_client.clone_repo(
                    owner=owner,
                    repo=repo_name,
                    target_dir=self.repos_dir,
                    branch=head_ref,
                )

                commit_info = CommitInfo(
                    sha=head_sha,
                    message=f"PR #{pr_number}: {pr_title}",
                    author=pr.get("user", {}).get("login", ""),
                    author_email="",
                    timestamp=datetime.utcnow(),
                    branch=head_ref,
                )

                scan_result = await self.scan_callback(
                    repo_path=repo_path,
                    commit_info=commit_info,
                    file_changes=file_changes,
                )

                findings_count = scan_result.get("findings_count", 0)

                # Set status
                await self.github_client.set_commit_status(
                    owner=owner,
                    repo=repo_name,
                    sha=head_sha,
                    state="success" if findings_count == 0 else "failure",
                    description=f"Found {findings_count} issues" if findings_count else "No issues found",
                    context="cra-agent/security",
                )

                # Add comment to PR if findings
                if findings_count > 0:
                    comment = (
                        f"## CRA-AGENT Security Scan Results\n\n"
                        f"Found **{findings_count}** potential issues in this PR.\n\n"
                        f"Check the [dashboard]({scan_result.get('dashboard_url', '')}) for details."
                    )
                    await self.github_client.create_issue_comment(
                        owner=owner,
                        repo=repo_name,
                        issue_number=pr_number,
                        body=comment,
                    )

                return {
                    "status": "scanned",
                    "pr_number": pr_number,
                    "findings": findings_count,
                }

        except Exception as e:
            logger.error("PR scan failed", pr_number=pr_number, error=str(e))

            await self.github_client.set_commit_status(
                owner=owner,
                repo=repo_name,
                sha=head_sha,
                state="error",
                description=f"Scan error: {str(e)[:100]}",
                context="cra-agent/security",
            )

            return {"status": "error", "error": str(e)}

        return {"status": "no_files_to_scan"}

    def _detect_language(self, file_path: str) -> str:
        """Detect programming language from file extension.

        Args:
            file_path: Path to the file.

        Returns:
            Language name.
        """
        ext_map = {
            ".py": "python",
            ".js": "javascript",
            ".ts": "typescript",
            ".jsx": "javascript",
            ".tsx": "typescript",
            ".go": "go",
            ".java": "java",
            ".rb": "ruby",
            ".php": "php",
            ".rs": "rust",
            ".c": "c",
            ".cpp": "cpp",
            ".h": "c",
            ".hpp": "cpp",
            ".cs": "csharp",
            ".swift": "swift",
            ".kt": "kotlin",
            ".scala": "scala",
            ".tf": "terraform",
            ".yaml": "yaml",
            ".yml": "yaml",
            ".json": "json",
            ".xml": "xml",
            ".html": "html",
            ".css": "css",
            ".scss": "scss",
            ".sh": "shell",
            ".bash": "shell",
            ".dockerfile": "dockerfile",
        }

        ext = Path(file_path).suffix.lower()
        return ext_map.get(ext, "unknown")