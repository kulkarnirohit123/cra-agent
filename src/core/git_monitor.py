"""Git commit monitor — watches for new commits on configured branches.

Supports two modes:
- Polling: Periodically checks for new commits
- Webhook: Receives push events from GitHub/GitLab/Bitbucket
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from datetime import datetime
from pathlib import Path

import git
from git import Repo

from src.core.models import CommitInfo
from src.utils.logger import get_logger

logger = get_logger(__name__)


class GitMonitor:
    """Monitors a git repository for new commits.

    Tracks the last-seen commit hash per branch and yields new commits
    as they are detected.
    """

    def __init__(
        self,
        repo_path: Path,
        branches: list[str],
        poll_interval_seconds: int = 60,
    ) -> None:
        """Initialize the git monitor.

        Args:
            repo_path: Path to the git repository.
            branches: List of branches to monitor.
            poll_interval_seconds: How often to poll for new commits.
        """
        self.repo_path = repo_path
        self.branches = branches
        self.poll_interval_seconds = poll_interval_seconds
        self._repo: Repo | None = None
        self._last_seen: dict[str, str] = {}  # branch -> commit hash
        self._running = False

    @property
    def repo(self) -> Repo:
        """Get or initialize the git repository."""
        if self._repo is None:
            self._repo = Repo(self.repo_path)
        return self._repo

    def initialize(self) -> None:
        """Initialize the monitor by recording current HEAD for each branch."""
        logger.info("Initializing git monitor", repo_path=str(self.repo_path))

        for branch in self.branches:
            try:
                ref = self.repo.refs[branch]
                self._last_seen[branch] = ref.commit.hexsha
                logger.info(
                    "Tracking branch",
                    branch=branch,
                    head=self._last_seen[branch][:7],
                )
            except (IndexError, KeyError):
                logger.warning("Branch not found, skipping", branch=branch)

    def get_new_commits(self, branch: str) -> list[CommitInfo]:
        """Get new commits on a branch since last check.

        Args:
            branch: Branch name to check.

        Returns:
            List of new commits (oldest first).
        """
        if branch not in self._last_seen:
            logger.warning("Branch not tracked", branch=branch)
            return []

        try:
            ref = self.repo.refs[branch]
            current_head = ref.commit.hexsha
            last_seen = self._last_seen[branch]

            if current_head == last_seen:
                return []

            # Get commits between last_seen and current HEAD
            commits: list[CommitInfo] = []
            for commit in self.repo.iter_commits(f"{last_seen}..{current_head}"):
                commit_info = CommitInfo(
                    hash=commit.hexsha,
                    short_hash=commit.hexsha[:7],
                    author=str(commit.author),
                    author_email=commit.author.email,
                    message=commit.message.strip(),
                    timestamp=datetime.fromtimestamp(commit.committed_date),
                    branch=branch,
                    parent_hash=commit.parents[0].hexsha if commit.parents else None,
                )
                commits.append(commit_info)

            # Update last seen
            self._last_seen[branch] = current_head

            # Return oldest first (for processing order)
            commits.reverse()
            logger.info(
                "Found new commits",
                branch=branch,
                count=len(commits),
                from_commit=last_seen[:7],
                to_commit=current_head[:7],
            )
            return commits

        except Exception as e:
            logger.error("Error getting new commits", branch=branch, error=str(e))
            return []

    async def poll_loop(self) -> AsyncIterator[tuple[str, CommitInfo]]:
        """Async generator that yields (branch, commit) tuples as they are detected.

        This is the main polling loop that runs continuously.
        """
        self._running = True
        self.initialize()

        logger.info(
            "Starting poll loop",
            branches=self.branches,
            interval=self.poll_interval_seconds,
        )

        while self._running:
            for branch in self.branches:
                if not self._running:
                    break

                new_commits = self.get_new_commits(branch)
                for commit in new_commits:
                    yield (branch, commit)

            await asyncio.sleep(self.poll_interval_seconds)

    def stop(self) -> None:
        """Stop the polling loop."""
        self._running = False
        logger.info("Git monitor stopped")

    def get_commit_diff(self, commit_hash: str) -> str:
        """Get the diff for a specific commit.

        Args:
            commit_hash: The commit hash to get diff for.

        Returns:
            The diff as a string.
        """
        try:
            commit = self.repo.commit(commit_hash)
            if commit.parents:
                diff = commit.diff(commit.parents[0], create_patch=True)
            else:
                # Initial commit
                diff = commit.diff(git.NULL_TREE, create_patch=True)

            return "\n".join(d.diff.decode("utf-8", errors="replace") for d in diff)
        except Exception as e:
            logger.error("Error getting commit diff", commit=commit_hash[:7], error=str(e))
            return ""

    def get_changed_files(self, commit_hash: str) -> list[str]:
        """Get list of files changed in a commit.

        Args:
            commit_hash: The commit hash.

        Returns:
            List of changed file paths.
        """
        try:
            commit = self.repo.commit(commit_hash)
            if commit.parents:
                diffs = commit.diff(commit.parents[0])
            else:
                diffs = commit.diff(git.NULL_TREE)

            changed_files = set()
            for diff in diffs:
                if diff.a_path:
                    changed_files.add(diff.a_path)
                if diff.b_path:
                    changed_files.add(diff.b_path)

            return sorted(changed_files)
        except Exception as e:
            logger.error("Error getting changed files", commit=commit_hash[:7], error=str(e))
            return []
