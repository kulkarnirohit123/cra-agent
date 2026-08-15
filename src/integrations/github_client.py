"""GitHub App client — integration with GitHub API for repository scanning.

This client handles:
- GitHub App authentication (JWT + installation tokens)
- Fetching commits and diffs
- Creating pull requests
- Setting commit statuses
- Cloning/fetching repositories
"""

from __future__ import annotations

import shutil
import subprocess
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import jwt

from src.utils.logger import get_logger

logger = get_logger(__name__)


GITHUB_API_URL = "https://api.github.com"


class GitHubClient:
    """Client for GitHub App API integration.

    Handles authentication and API calls for:
    - Fetching repository data
    - Getting commit diffs
    - Creating pull requests
    - Setting commit statuses
    """

    def __init__(
        self,
        app_id: str,
        private_key: str,
        installation_id: str = "",
        api_url: str = GITHUB_API_URL,
    ) -> None:
        """Initialize the GitHub client.

        Args:
            app_id: GitHub App ID.
            private_key: GitHub App private key (PEM format).
            installation_id: GitHub App installation ID.
            api_url: GitHub API base URL.
        """
        self.app_id = app_id
        self.private_key = private_key
        self.installation_id = installation_id
        self.api_url = api_url.rstrip("/")

        self._installation_token: str | None = None
        self._token_expires_at: datetime | None = None
        self._client: httpx.AsyncClient | None = None

        logger.info(
            "GitHub client initialized",
            app_id=app_id,
            installation_id=installation_id,
        )

    def _generate_jwt(self) -> str:
        """Generate a JWT for GitHub App authentication.

        Returns:
            JWT token string.
        """
        now = int(time.time())
        payload = {
            "iat": now - 60,  # Issued at time (60 seconds in the past)
            "exp": now + (10 * 60),  # Expiration time (10 minutes)
            "iss": self.app_id,
        }

        return jwt.encode(payload, self.private_key, algorithm="RS256")

    async def _get_installation_token(self) -> str:
        """Get or refresh the installation access token.

        Returns:
            Installation access token.
        """
        # Check if we have a valid token
        if self._installation_token and self._token_expires_at and datetime.utcnow() < self._token_expires_at:
            return self._installation_token

        # Generate new token
        jwt_token = self._generate_jwt()

        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.api_url}/app/installations/{self.installation_id}/access_tokens",
                headers={
                    "Authorization": f"Bearer {jwt_token}",
                    "Accept": "application/vnd.github+json",
                },
            )
            response.raise_for_status()
            data = response.json()

        self._installation_token = data["token"]
        # Token expires in 1 hour, refresh 5 minutes early
        self._token_expires_at = datetime.utcnow() + timedelta(minutes=55)

        logger.debug("GitHub installation token refreshed")
        return self._installation_token

    @property
    async def client(self) -> httpx.AsyncClient:
        """Get or create authenticated HTTP client."""
        if self._client is None:
            token = await self._get_installation_token()
            self._client = httpx.AsyncClient(
                base_url=self.api_url,
                headers={
                    "Authorization": f"Bearer {token}",
                    "Accept": "application/vnd.github+json",
                    "X-GitHub-Api-Version": "2022-11-28",
                },
                timeout=30.0,
            )
        return self._client

    async def close(self) -> None:
        """Close the HTTP client."""
        if self._client:
            await self._client.aclose()
            self._client = None

    async def get_repo(self, owner: str, repo: str) -> dict[str, Any]:
        """Get repository information.

        Args:
            owner: Repository owner.
            repo: Repository name.

        Returns:
            Repository data.
        """
        client = await self.client
        response = await client.get(f"/repos/{owner}/{repo}")
        response.raise_for_status()
        return response.json()

    async def get_commit(self, owner: str, repo: str, sha: str) -> dict[str, Any]:
        """Get commit details.

        Args:
            owner: Repository owner.
            repo: Repository name.
            sha: Commit SHA.

        Returns:
            Commit data.
        """
        client = await self.client
        response = await client.get(f"/repos/{owner}/{repo}/commits/{sha}")
        response.raise_for_status()
        return response.json()

    async def get_commit_diff(self, owner: str, repo: str, sha: str) -> list[dict[str, Any]]:
        """Get files changed in a commit.

        Args:
            owner: Repository owner.
            repo: Repository name.
            sha: Commit SHA.

        Returns:
            List of changed files with patches.
        """
        client = await self.client
        response = await client.get(
            f"/repos/{owner}/{repo}/commits/{sha}",
            headers={"Accept": "application/vnd.github.v3.diff"},
        )
        response.raise_for_status()

        # Parse the diff response
        commit_data = await self.get_commit(owner, repo, sha)
        return commit_data.get("files", [])

    async def get_file_content(self, owner: str, repo: str, path: str, ref: str = "main") -> str:
        """Get file content from repository.

        Args:
            owner: Repository owner.
            repo: Repository name.
            path: File path.
            ref: Git reference (branch, tag, or SHA).

        Returns:
            File content as string.
        """
        client = await self.client
        response = await client.get(
            f"/repos/{owner}/{repo}/contents/{path}",
            params={"ref": ref},
        )
        response.raise_for_status()
        data = response.json()

        # Decode base64 content
        import base64

        return base64.b64decode(data["content"]).decode("utf-8")

    async def create_pull_request(
        self,
        owner: str,
        repo: str,
        title: str,
        body: str,
        head: str,
        base: str = "main",
    ) -> dict[str, Any]:
        """Create a pull request.

        Args:
            owner: Repository owner.
            repo: Repository name.
            title: PR title.
            body: PR description.
            head: Source branch.
            base: Target branch.

        Returns:
            Pull request data.
        """
        client = await self.client
        response = await client.post(
            f"/repos/{owner}/{repo}/pulls",
            json={
                "title": title,
                "body": body,
                "head": head,
                "base": base,
            },
        )
        response.raise_for_status()
        pr_data = response.json()

        logger.info(
            "Pull request created",
            owner=owner,
            repo=repo,
            pr_number=pr_data["number"],
            url=pr_data["html_url"],
        )

        return pr_data

    async def set_commit_status(
        self,
        owner: str,
        repo: str,
        sha: str,
        state: str,
        description: str = "",
        context: str = "cra-agent",
        target_url: str = "",
    ) -> dict[str, Any]:
        """Set commit status (for CI/CD integration).

        Args:
            owner: Repository owner.
            repo: Repository name.
            sha: Commit SHA.
            state: Status state (pending, success, failure, error).
            description: Status description.
            context: Status context (e.g., "cra-agent/security").
            target_url: URL for more details.

        Returns:
            Status data.
        """
        client = await self.client
        payload: dict[str, Any] = {
            "state": state,
            "context": context,
        }
        if description:
            payload["description"] = description[:140]  # GitHub limit
        if target_url:
            payload["target_url"] = target_url

        response = await client.post(
            f"/repos/{owner}/{repo}/statuses/{sha}",
            json=payload,
        )
        response.raise_for_status()

        logger.debug(
            "Commit status set",
            owner=owner,
            repo=repo,
            sha=sha[:7],
            state=state,
            context=context,
        )

        return response.json()

    async def create_issue_comment(
        self,
        owner: str,
        repo: str,
        issue_number: int,
        body: str,
    ) -> dict[str, Any]:
        """Add a comment to an issue or pull request.

        Args:
            owner: Repository owner.
            repo: Repository name.
            issue_number: Issue or PR number.
            body: Comment body.

        Returns:
            Comment data.
        """
        client = await self.client
        response = await client.post(
            f"/repos/{owner}/{repo}/issues/{issue_number}/comments",
            json={"body": body},
        )
        response.raise_for_status()
        return response.json()

    async def list_recent_commits(
        self,
        owner: str,
        repo: str,
        branch: str = "main",
        limit: int = 10,
    ) -> list[dict[str, Any]]:
        """List recent commits on a branch.

        Args:
            owner: Repository owner.
            repo: Repository name.
            branch: Branch name.
            limit: Maximum commits to return.

        Returns:
            List of commit data.
        """
        client = await self.client
        response = await client.get(
            f"/repos/{owner}/{repo}/commits",
            params={"sha": branch, "per_page": limit},
        )
        response.raise_for_status()
        return response.json()

    def clone_repo(
        self,
        owner: str,
        repo: str,
        target_dir: Path,
        branch: str = "main",
    ) -> Path:
        """Clone a repository locally.

        Args:
            owner: Repository owner.
            repo: Repository name.
            target_dir: Directory to clone into.
            branch: Branch to clone.

        Returns:
            Path to cloned repository.
        """
        repo_url = f"https://github.com/{owner}/{repo}.git"
        repo_path = target_dir / repo
        git_path = shutil.which("git") or "git"

        if repo_path.exists():
            # Pull latest changes
            subprocess.run(
                [git_path, "pull", "origin", branch],
                cwd=repo_path,
                capture_output=True,
                check=True,
            )
        else:
            # Clone fresh
            subprocess.run(
                [git_path, "clone", "--branch", branch, "--depth", "50", repo_url, str(repo_path)],
                capture_output=True,
                check=True,
            )

        logger.info("Repository cloned/updated", owner=owner, repo=repo, path=str(repo_path))
        return repo_path

    async def create_branch(
        self,
        owner: str,
        repo: str,
        branch_name: str,
        from_sha: str,
    ) -> dict[str, Any]:
        """Create a new branch.

        Args:
            owner: Repository owner.
            repo: Repository name.
            branch_name: New branch name.
            from_sha: SHA to branch from.

        Returns:
            Reference data.
        """
        client = await self.client
        response = await client.post(
            f"/repos/{owner}/{repo}/git/refs",
            json={
                "ref": f"refs/heads/{branch_name}",
                "sha": from_sha,
            },
        )
        response.raise_for_status()
        return response.json()

    async def create_or_update_file(
        self,
        owner: str,
        repo: str,
        path: str,
        content: str,
        message: str,
        branch: str,
        sha: str | None = None,
    ) -> dict[str, Any]:
        """Create or update a file in the repository.

        Args:
            owner: Repository owner.
            repo: Repository name.
            path: File path.
            content: File content.
            message: Commit message.
            branch: Branch name.
            sha: File SHA (required for updates).

        Returns:
            Commit data.
        """
        import base64

        client = await self.client
        payload: dict[str, Any] = {
            "message": message,
            "content": base64.b64encode(content.encode()).decode(),
            "branch": branch,
        }
        if sha:
            payload["sha"] = sha

        response = await client.put(
            f"/repos/{owner}/{repo}/contents/{path}",
            json=payload,
        )
        response.raise_for_status()
        return response.json()

    def verify_webhook_signature(
        self,
        payload: bytes,
        signature: str,
        secret: str,
    ) -> bool:
        """Verify GitHub webhook signature.

        Args:
            payload: Raw request body.
            signature: X-Hub-Signature-256 header value.
            secret: Webhook secret.

        Returns:
            True if signature is valid.
        """
        import hashlib
        import hmac

        if not signature.startswith("sha256="):
            return False

        expected = hmac.new(
            secret.encode(),
            payload,
            hashlib.sha256,
        ).hexdigest()

        return hmac.compare_digest(f"sha256={expected}", signature)
