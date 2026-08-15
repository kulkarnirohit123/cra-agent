"""GitHub repository poller — monitors repositories for new commits.

This module provides a polling-based approach to monitor GitHub repositories
without requiring webhooks or incoming connections. The agent periodically
checks for new commits and triggers scans.
"""

from __future__ import annotations

import asyncio
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable

import yaml

from src.utils.logger import get_logger

if TYPE_CHECKING:
    from src.integrations.github_client import GitHubClient

logger = get_logger(__name__)


class GitHubPoller:
    """Polls GitHub repositories for new commits.

    This class monitors configured repositories for new commits and
    triggers scan callbacks when changes are detected. No webhooks
    or incoming connections required.
    """

    def __init__(
        self,
        github_client: GitHubClient,
        repos_config_path: Path,
        poll_interval_seconds: int = 60,
        scan_callback: Callable | None = None,
    ) -> None:
        """Initialize the GitHub poller.

        Args:
            github_client: GitHub API client.
            repos_config_path: Path to repos.yaml configuration.
            poll_interval_seconds: How often to poll for new commits.
            scan_callback: Async function to call when new commits found.
        """
        self.github_client = github_client
        self.repos_config_path = repos_config_path
        self.poll_interval_seconds = poll_interval_seconds
        self.scan_callback = scan_callback

        # Track last scanned commit per repo
        self._last_scanned: dict[str, str] = {}
        self._running = False
        self._repos_config: dict[str, Any] = {}

        logger.info(
            "GitHub poller initialized",
            config_path=str(repos_config_path),
            poll_interval=poll_interval_seconds,
        )

    def load_config(self) -> dict[str, Any]:
        """Load repository configuration from YAML file.

        Returns:
            Parsed configuration dictionary.
        """
        if not self.repos_config_path.exists():
            logger.warning("Repos config not found", path=str(self.repos_config_path))
            return {"repositories": []}

        with open(self.repos_config_path) as f:
            config = yaml.safe_load(f) or {}

        self._repos_config = config
        logger.info(
            "Loaded repos config",
            repo_count=len(config.get("repositories", [])),
        )
        return config

    def get_repositories(self) -> list[dict[str, Any]]:
        """Get list of configured repositories.

        Returns:
            List of repository configurations.
        """
        if not self._repos_config:
            self.load_config()

        return self._repos_config.get("repositories", [])

    async def check_for_new_commits(
        self, owner: str, repo: str, branch: str
    ) -> list[dict[str, Any]]:
        """Check for new commits since last scan.

        Args:
            owner: Repository owner.
            repo: Repository name.
            branch: Branch to check.

        Returns:
            List of new commits since last scan.
        """
        repo_key = f"{owner}/{repo}:{branch}"

        try:
            # Get recent commits
            commits = await self.github_client.list_recent_commits(
                owner=owner,
                repo=repo,
                branch=branch,
                limit=10,
            )

            if not commits:
                return []

            latest_sha = commits[0]["sha"]
            last_sha = self._last_scanned.get(repo_key)

            # First time scanning this repo
            if not last_sha:
                self._last_scanned[repo_key] = latest_sha
                logger.info(
                    "First scan for repo",
                    repo=f"{owner}/{repo}",
                    branch=branch,
                    latest_commit=latest_sha[:7],
                )
                # Return only the latest commit on first scan
                return [commits[0]]

            # No new commits
            if latest_sha == last_sha:
                return []

            # Find new commits
            new_commits = []
            for commit in commits:
                if commit["sha"] == last_sha:
                    break
                new_commits.append(commit)

            # Update last scanned
            self._last_scanned[repo_key] = latest_sha

            logger.info(
                "Found new commits",
                repo=f"{owner}/{repo}",
                branch=branch,
                count=len(new_commits),
            )

            return new_commits

        except Exception as e:
            logger.error(
                "Failed to check commits",
                repo=f"{owner}/{repo}",
                error=str(e),
            )
            return []

    async def poll_repository(self, repo_config: dict[str, Any]) -> None:
        """Poll a single repository for new commits.

        Args:
            repo_config: Repository configuration from repos.yaml.
        """
        name = repo_config.get("name", "")
        if "/" not in name:
            logger.warning("Invalid repo name format", name=name)
            return

        owner, repo = name.split("/", 1)
        branches = repo_config.get("branches", ["main"])

        for branch in branches:
            # Handle wildcard branches (e.g., "release/*")
            if "*" in branch:
                # For now, skip wildcard branches in polling mode
                logger.debug("Skipping wildcard branch", branch=branch)
                continue

            new_commits = await self.check_for_new_commits(owner, repo, branch)

            if new_commits and self.scan_callback:
                for commit in new_commits:
                    try:
                        await self.scan_callback(
                            owner=owner,
                            repo=repo,
                            branch=branch,
                            commit=commit,
                            repo_config=repo_config,
                        )
                    except Exception as e:
                        logger.error(
                            "Scan callback failed",
                            commit=commit.get("sha", "")[:7],
                            error=str(e),
                        )

    async def poll_all_repositories(self) -> None:
        """Poll all configured repositories once."""
        repos = self.get_repositories()

        for repo_config in repos:
            if not repo_config.get("enabled", True):
                continue

            await self.poll_repository(repo_config)

    async def start(self) -> None:
        """Start the polling loop.

        This runs indefinitely, polling all configured repositories
        at the specified interval.
        """
        self._running = True
        logger.info(
            "Starting GitHub poller",
            interval_seconds=self.poll_interval_seconds,
        )

        # Load config
        self.load_config()

        while self._running:
            try:
                await self.poll_all_repositories()
            except Exception as e:
                logger.error("Polling cycle failed", error=str(e))

            # Wait for next poll
            await asyncio.sleep(self.poll_interval_seconds)

    def stop(self) -> None:
        """Stop the polling loop."""
        self._running = False
        logger.info("GitHub poller stopped")

    def get_status(self) -> dict[str, Any]:
        """Get current poller status.

        Returns:
            Status dictionary with last scanned commits.
        """
        return {
            "running": self._running,
            "poll_interval_seconds": self.poll_interval_seconds,
            "repositories_count": len(self.get_repositories()),
            "last_scanned": self._last_scanned,
        }