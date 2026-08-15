"""Git client — wrapper for git operations.

Provides high-level methods for:
- Creating branches
- Applying code changes
- Committing changes
- Creating pull requests
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from git import Repo

from src.utils.logger import get_logger

if TYPE_CHECKING:
    pass

logger = get_logger(__name__)


class GitClient:
    """High-level git operations client.

    Wraps GitPython to provide async-friendly methods for
    branch management, committing, and PR creation.
    """

    def __init__(
        self,
        repo_path: Path,
        remote_name: str = "origin",
        default_branch: str = "main",
    ) -> None:
        """Initialize the git client.

        Args:
            repo_path: Path to the git repository.
            remote_name: Name of the remote.
            default_branch: Default branch name.
        """
        self.repo_path = repo_path
        self.remote_name = remote_name
        self.default_branch = default_branch
        self._repo: Repo | None = None

        logger.info("Git client initialized", repo_path=str(repo_path))

    @property
    def repo(self) -> Repo:
        """Get or initialize the git repository."""
        if self._repo is None:
            self._repo = Repo(self.repo_path)
        return self._repo

    async def create_branch(self, branch_name: str, base_branch: str | None = None) -> str:
        """Create a new branch.

        Args:
            branch_name: Name of the new branch.
            base_branch: Base branch to create from (default: default_branch).

        Returns:
            The created branch name.
        """
        base = base_branch or self.default_branch

        try:
            # Checkout base branch
            self.repo.git.checkout(base)

            # Create and checkout new branch
            self.repo.git.checkout("-b", branch_name)

            logger.info("Created branch", branch=branch_name, base=base)
            return branch_name

        except Exception as e:
            logger.error("Failed to create branch", branch=branch_name, error=str(e))
            raise

    async def apply_fix(
        self,
        file_path: str,
        old_code: str,
        new_code: str,
    ) -> bool:
        """Apply a code fix to a file.

        Args:
            file_path: Path to the file (relative to repo root).
            old_code: Code to replace.
            new_code: Replacement code.

        Returns:
            True if fix was applied.
        """
        full_path = self.repo_path / file_path

        try:
            content = full_path.read_text()

            if old_code not in content:
                logger.warning(
                    "Old code not found in file",
                    file=file_path,
                )
                return False

            new_content = content.replace(old_code, new_code, 1)
            full_path.write_text(new_content)

            logger.info("Applied fix", file=file_path)
            return True

        except Exception as e:
            logger.error("Failed to apply fix", file=file_path, error=str(e))
            return False

    async def commit(self, message: str, author: str | None = None) -> str:
        """Commit staged changes.

        Args:
            message: Commit message.
            author: Author name (optional).

        Returns:
            Commit hash.
        """
        try:
            # Stage all changes
            self.repo.git.add("-A")

            # Commit
            if author:
                self.repo.git.commit("-m", message, "--author", author)
            else:
                self.repo.git.commit("-m", message)

            commit_hash = self.repo.head.commit.hexsha
            logger.info("Committed changes", hash=commit_hash[:7], message=message[:50])

            return commit_hash

        except Exception as e:
            logger.error("Failed to commit", error=str(e))
            raise

    async def push(self, branch_name: str | None = None) -> bool:
        """Push branch to remote.

        Args:
            branch_name: Branch to push (default: current branch).

        Returns:
            True if push succeeded.
        """
        branch = branch_name or self.repo.active_branch.name

        try:
            self.repo.git.push(self.remote_name, branch)
            logger.info("Pushed branch", branch=branch)
            return True

        except Exception as e:
            logger.error("Failed to push", branch=branch, error=str(e))
            return False

    async def create_pull_request(
        self,
        branch_name: str,
        title: str,
        body: str,
        base_branch: str | None = None,
    ) -> str:
        """Create a pull request (placeholder implementation).

        In production, this would integrate with GitHub/GitLab/Bitbucket APIs.

        Args:
            branch_name: Source branch.
            title: PR title.
            body: PR description.
            base_branch: Target branch (default: default_branch).

        Returns:
            PR URL (placeholder).
        """
        base = base_branch or self.default_branch

        # Push the branch first
        await self.push(branch_name)

        # Placeholder: In production, call GitHub/GitLab API
        pr_url = f"https://github.com/org/repo/pull/new?head={branch_name}&base={base}"

        logger.info(
            "Created pull request",
            branch=branch_name,
            base=base,
            title=title,
        )

        return pr_url

    async def checkout(self, branch_name: str) -> bool:
        """Checkout a branch.

        Args:
            branch_name: Branch to checkout.

        Returns:
            True if checkout succeeded.
        """
        try:
            self.repo.git.checkout(branch_name)
            logger.debug("Checked out branch", branch=branch_name)
            return True

        except Exception as e:
            logger.error("Failed to checkout", branch=branch_name, error=str(e))
            return False

    async def get_current_branch(self) -> str:
        """Get the current branch name.

        Returns:
            Current branch name.
        """
        return self.repo.active_branch.name

    async def get_file_content(self, file_path: str, ref: str = "HEAD") -> str | None:
        """Get file content at a specific ref.

        Args:
            file_path: Path to the file.
            ref: Git ref (default: HEAD).

        Returns:
            File content or None if not found.
        """
        try:
            blob = self.repo.commit(ref).tree / file_path
            return blob.data_stream.read().decode("utf-8", errors="replace")
        except (KeyError, TypeError):
            return None

    async def diff(self, ref1: str = "HEAD", ref2: str | None = None) -> str:
        """Get diff between two refs.

        Args:
            ref1: First ref (default: HEAD).
            ref2: Second ref (default: working directory).

        Returns:
            Diff as string.
        """
        try:
            if ref2:
                return self.repo.git.diff(ref1, ref2)
            else:
                return self.repo.git.diff(ref1)
        except Exception as e:
            logger.error("Failed to get diff", error=str(e))
            return ""
