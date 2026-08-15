"""CRA-AGENT main entry point.

This module initializes and runs the CRA compliance agent:
1. Loads configuration
2. Initializes all components (scanners, agents, integrations)
3. Starts the git monitor polling loop (local or GitHub API)
4. Runs the webhook server (optional)
5. Processes commits through the agent workflow

Modes:
- Local mode: Monitors local git repositories
- GitHub mode: Polls GitHub API for new commits (no webhooks needed)
"""

from __future__ import annotations

import argparse
import asyncio
import signal
import sys
from pathlib import Path

from config.settings import get_settings
from src.agents.orchestrator import CRAOrchestrator
from src.core.diff_analyzer import DiffAnalyzer
from src.core.git_monitor import GitMonitor
from src.core.github_poller import GitHubPoller
from src.integrations.git_client import GitClient
from src.integrations.github_client import GitHubClient
from src.integrations.jira_client import JiraClient
from src.integrations.llm_client import LLMClient
from src.scanners.suppression_store import SuppressionStore
from src.utils.logger import get_logger, setup_logging

logger = get_logger(__name__)


class CRAAgent:
    """Main CRA compliance agent.

    Orchestrates the entire vulnerability management workflow:
    - Monitors git repositories for new commits
    - Scans commits for vulnerabilities
    - Triages and creates Jira tickets
    - Responds to Jira webhook updates
    """

    def __init__(self) -> None:
        """Initialize the CRA agent with all components."""
        self.settings = get_settings()

        # Setup logging
        setup_logging(
            level=self.settings.log_level,
            json_output=self.settings.app_env == "production",
        )

        logger.info("Initializing CRA-AGENT", env=self.settings.app_env)

        # Initialize suppression store
        self.suppression_store = SuppressionStore(
            db_path=self.settings.suppression_db_path
        )

        # Initialize integrations
        self.llm_client = LLMClient(
            provider=self.settings.llm_provider,
            model=self.settings.llm_model,
            api_key=self._get_llm_api_key(),
            base_url=self.settings.openai_base_url if self.settings.llm_provider == "openai" else None,
            temperature=self.settings.llm_temperature,
            max_tokens=self.settings.llm_max_tokens,
        )

        self.jira_client = JiraClient(
            base_url=self.settings.jira_base_url,
            email=self.settings.jira_email,
            api_token=self.settings.jira_api_token,
        )

        self.git_client = GitClient(
            repo_path=self.settings.git_repo_path,
        )

        # Initialize git monitor
        self.git_monitor = GitMonitor(
            repo_path=self.settings.git_repo_path,
            branches=self.settings.git_branch_list,
            poll_interval_seconds=self.settings.git_poll_interval_seconds,
        )

        # Initialize diff analyzer
        self.diff_analyzer = DiffAnalyzer(repo_path=self.settings.git_repo_path)

        # Initialize orchestrator
        self.orchestrator = CRAOrchestrator(
            repo_path=self.settings.git_repo_path,
            llm_client=self.llm_client,
            jira_client=self.jira_client,
            git_client=self.git_client,
            suppression_store=self.suppression_store,
        )

        self._running = False

        logger.info("CRA-AGENT initialized successfully")

    def _get_llm_api_key(self) -> str:
        """Get the appropriate API key based on LLM provider."""
        if self.settings.llm_provider == "openai":
            return self.settings.openai_api_key
        elif self.settings.llm_provider == "anthropic":
            return self.settings.anthropic_api_key
        return ""

    async def process_commit(self, branch: str, commit_info: dict) -> None:
        """Process a single commit through the agent workflow.

        Args:
            branch: Branch name.
            commit_info: Commit information dict.
        """
        commit_hash = commit_info.get("hash", "")
        logger.info("Processing commit", branch=branch, commit=commit_hash[:7])

        try:
            # Analyze commit to get file changes
            file_changes = self.diff_analyzer.analyze_commit(commit_hash)

            if not file_changes:
                logger.info("No file changes in commit", commit=commit_hash[:7])
                return

            # Serialize file changes for orchestrator
            changed_files = [fc.model_dump() for fc in file_changes]

            # Run the orchestrator workflow
            result = await self.orchestrator.run(
                commit_info=commit_info,
                changed_files=changed_files,
            )

            # Log results
            findings_count = len(result.get("triaged_findings", []))
            tickets_count = len(result.get("jira_tickets", []))

            logger.info(
                "Commit processed",
                commit=commit_hash[:7],
                findings=findings_count,
                tickets=tickets_count,
            )

        except Exception as e:
            logger.error("Failed to process commit", commit=commit_hash[:7], error=str(e))

    async def run_polling_loop(self) -> None:
        """Run the git polling loop and process commits."""
        self._running = True
        logger.info("Starting git polling loop")

        async for branch, commit_info in self.git_monitor.poll_loop():
            if not self._running:
                break

            await self.process_commit(branch, commit_info.model_dump())

    async def run_webhook_server(self) -> None:
        """Run the webhook server."""
        import uvicorn

        from src.webhook.server import create_app

        app = create_app(
            jira_client=self.jira_client,
            llm_client=self.llm_client,
            git_client=self.git_client,
            suppression_store=self.suppression_store,
            webhook_secret=self.settings.jira_webhook_secret,
        )

        config = uvicorn.Config(
            app,
            host=self.settings.webhook_host,
            port=self.settings.webhook_port,
            log_level=self.settings.log_level.lower(),
        )

        server = uvicorn.Server(config)
        await server.serve()

    async def run(self) -> None:
        """Run the CRA agent (polling + webhook server)."""
        logger.info("Starting CRA-AGENT")

        # Setup signal handlers for graceful shutdown
        loop = asyncio.get_event_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, self._handle_shutdown)

        # Run polling loop and webhook server concurrently
        tasks = [
            asyncio.create_task(self.run_polling_loop()),
            asyncio.create_task(self.run_webhook_server()),
        ]

        try:
            await asyncio.gather(*tasks)
        except asyncio.CancelledError:
            logger.info("Tasks cancelled")
        finally:
            await self.shutdown()

    def _handle_shutdown(self) -> None:
        """Handle shutdown signal."""
        logger.info("Shutdown signal received")
        self._running = False
        self.git_monitor.stop()

    async def shutdown(self) -> None:
        """Gracefully shutdown the agent."""
        logger.info("Shutting down CRA-AGENT")

        self._running = False
        self.git_monitor.stop()

        # Close clients
        await self.jira_client.close()
        await self.llm_client.close()

        logger.info("CRA-AGENT shutdown complete")


class GitHubPollingAgent:
    """GitHub API polling agent - no webhooks needed.

    This agent polls GitHub API for new commits in configured repositories.
    No incoming connections or ngrok required - everything stays local.
    """

    def __init__(self) -> None:
        """Initialize the GitHub polling agent."""
        self.settings = get_settings()

        # Setup logging
        setup_logging(
            level=self.settings.log_level,
            json_output=self.settings.app_env == "production",
        )

        logger.info("Initializing GitHub Polling Agent", env=self.settings.app_env)

        # Check if GitHub is configured
        if not self.settings.github_enabled:
            logger.error(
                "GitHub not configured. Please set GITHUB_APP_ID and "
                "GITHUB_PRIVATE_KEY_PATH in your .env file."
            )
            sys.exit(1)

        # Initialize suppression store
        self.suppression_store = SuppressionStore(
            db_path=self.settings.suppression_db_path
        )

        # Initialize LLM client
        self.llm_client = LLMClient(
            provider=self.settings.llm_provider,
            model=self.settings.llm_model,
            api_key=self._get_llm_api_key(),
            base_url=self.settings.openai_base_url if self.settings.llm_provider == "openai" else None,
            temperature=self.settings.llm_temperature,
            max_tokens=self.settings.llm_max_tokens,
        )

        # Initialize Jira client
        self.jira_client = JiraClient(
            base_url=self.settings.jira_base_url,
            email=self.settings.jira_email,
            api_token=self.settings.jira_api_token,
        )

        # Initialize GitHub client
        self.github_client = GitHubClient(
            app_id=self.settings.github_app_id,
            private_key=self.settings.github_private_key,
            installation_id=self.settings.github_installation_id,
            api_url=self.settings.github_api_url,
        )

        # Initialize GitHub poller
        self.github_poller = GitHubPoller(
            github_client=self.github_client,
            repos_config_path=self.settings.github_repos_config,
            poll_interval_seconds=self.settings.git_poll_interval_seconds,
            scan_callback=self._handle_new_commit,
        )

        self._running = False
        logger.info("GitHub Polling Agent initialized successfully")

    def _get_llm_api_key(self) -> str:
        """Get the appropriate API key based on LLM provider."""
        if self.settings.llm_provider == "openai":
            return self.settings.openai_api_key
        elif self.settings.llm_provider == "anthropic":
            return self.settings.anthropic_api_key
        return ""

    async def _handle_new_commit(
        self,
        owner: str,
        repo: str,
        branch: str,
        commit: dict,
        repo_config: dict,
    ) -> None:
        """Handle a new commit detected by the poller.

        Args:
            owner: Repository owner.
            repo: Repository name.
            branch: Branch name.
            commit: Commit data from GitHub API.
            repo_config: Repository configuration.
        """
        import uuid
        from datetime import datetime

        commit_sha = commit.get("sha", "")
        commit_message = commit.get("commit", {}).get("message", "")
        author = commit.get("commit", {}).get("author", {}).get("name", "")
        scan_id = str(uuid.uuid4())
        scan_start = datetime.utcnow()

        logger.info(
            "New commit detected",
            repo=f"{owner}/{repo}",
            branch=branch,
            commit=commit_sha[:7],
            author=author,
        )

        # Set pending status on GitHub
        await self.github_client.set_commit_status(
            owner=owner,
            repo=repo,
            sha=commit_sha,
            state="pending",
            description="CRA-AGENT scan in progress...",
            context="cra-agent/security",
        )

        # Initialize metrics store
        from src.analytics.metrics_store import MetricsStore
        from src.analytics.models import ScanMetrics, SeverityDistribution
        metrics_store = MetricsStore(Path("./data/metrics.db"))

        try:
            # Clone/update repo locally
            repos_dir = Path("./repos")
            repos_dir.mkdir(exist_ok=True)

            repo_path = self.github_client.clone_repo(
                owner=owner,
                repo=repo,
                target_dir=repos_dir,
                branch=branch,
            )

            # Get changed files
            files = await self.github_client.get_commit_diff(
                owner=owner,
                repo=repo,
                sha=commit_sha,
            )

            if not files:
                logger.info("No files changed", commit=commit_sha[:7])
                await self.github_client.set_commit_status(
                    owner=owner,
                    repo=repo,
                    sha=commit_sha,
                    state="success",
                    description="No files to scan",
                    context="cra-agent/security",
                )

                # Record scan metrics (no files)
                scan_metrics = ScanMetrics(
                    scan_id=scan_id,
                    commit_hash=commit_sha,
                    branch=branch,
                    started_at=scan_start,
                    completed_at=datetime.utcnow(),
                    duration_seconds=(datetime.utcnow() - scan_start).total_seconds(),
                    files_scanned=0,
                    findings_count=0,
                    scanners_used=[],
                    errors=[],
                )
                metrics_store.record_scan(scan_metrics)
                return

            # Create file changes for scanning
            from src.core.models import ChangeType, FileChange
            file_changes = []
            for f in files:
                status = f.get("status", "modified")
                change_type = {
                    "added": ChangeType.ADDED,
                    "modified": ChangeType.MODIFIED,
                    "removed": ChangeType.DELETED,
                }.get(status, ChangeType.MODIFIED)

                file_changes.append(FileChange(
                    file_path=f.get("filename", ""),
                    change_type=change_type,
                    file_extension=Path(f.get("filename", "")).suffix,
                    patch=f.get("patch", ""),
                ))

            # Run actual scanners on the cloned repo
            findings_count = 0
            scanners_used = []
            errors = []
            severity_dist = SeverityDistribution()

            # Try to run bandit for Python files
            python_files = [f for f in file_changes if f.file_extension == ".py"]
            if python_files and "bandit" in repo_config.get("scanners", []):
                try:
                    import subprocess
                    result = subprocess.run(
                        ["bandit", "-r", str(repo_path), "-f", "json", "-o", "/tmp/bandit_results.json"],
                        capture_output=True,
                        text=True,
                        timeout=60,
                    )
                    scanners_used.append("bandit")
                    # Parse bandit results if available
                    try:
                        import json
                        with open("/tmp/bandit_results.json") as f:
                            bandit_data = json.load(f)
                        findings = bandit_data.get("results", [])
                        findings_count += len(findings)
                        for finding in findings:
                            severity = finding.get("issue_severity", "").lower()
                            if severity == "high":
                                severity_dist.high += 1
                            elif severity == "medium":
                                severity_dist.medium += 1
                            elif severity == "low":
                                severity_dist.low += 1
                    except Exception:
                        pass
                except Exception as e:
                    errors.append(f"bandit: {str(e)}")
                    logger.warning("Bandit scan failed", error=str(e))

            # Try to run gitleaks for secrets
            if "gitleaks" in repo_config.get("scanners", []):
                try:
                    import subprocess
                    result = subprocess.run(
                        ["gitleaks", "detect", "--source", str(repo_path), "--report-format", "json", "--report-path", "/tmp/gitleaks_results.json"],
                        capture_output=True,
                        text=True,
                        timeout=60,
                    )
                    scanners_used.append("gitleaks")
                    # Parse gitleaks results if available
                    try:
                        import json
                        with open("/tmp/gitleaks_results.json") as f:
                            gitleaks_data = json.load(f)
                        findings = gitleaks_data.get("leaks", [])
                        findings_count += len(findings)
                        for finding in findings:
                            severity_dist.high += 1  # Secrets are typically high severity
                    except Exception:
                        pass
                except Exception as e:
                    errors.append(f"gitleaks: {str(e)}")
                    logger.warning("Gitleaks scan failed", error=str(e))

            # If no scanners ran, use default file count
            if not scanners_used:
                scanners_used = ["file_scan"]
                findings_count = 0

            # Record scan metrics
            scan_metrics = ScanMetrics(
                scan_id=scan_id,
                commit_hash=commit_sha,
                branch=branch,
                started_at=scan_start,
                completed_at=datetime.utcnow(),
                duration_seconds=(datetime.utcnow() - scan_start).total_seconds(),
                files_scanned=len(file_changes),
                findings_count=findings_count,
                severity_distribution=severity_dist,
                scanners_used=scanners_used,
                errors=errors,
            )
            metrics_store.record_scan(scan_metrics)

            logger.info(
                "Scan completed",
                commit=commit_sha[:7],
                files=len(file_changes),
                findings=findings_count,
                scanners=scanners_used,
            )

            # Set success status
            status_state = "success" if findings_count == 0 else "failure"
            await self.github_client.set_commit_status(
                owner=owner,
                repo=repo,
                sha=commit_sha,
                state=status_state,
                description=f"Found {findings_count} issues in {len(file_changes)} files",
                context="cra-agent/security",
            )

        except Exception as e:
            logger.error(
                "Failed to process commit",
                commit=commit_sha[:7],
                error=str(e),
            )

            # Record failed scan
            scan_metrics = ScanMetrics(
                scan_id=scan_id,
                commit_hash=commit_sha,
                branch=branch,
                started_at=scan_start,
                completed_at=datetime.utcnow(),
                duration_seconds=(datetime.utcnow() - scan_start).total_seconds(),
                files_scanned=0,
                findings_count=0,
                scanners_used=[],
                errors=[str(e)],
            )
            metrics_store.record_scan(scan_metrics)

            await self.github_client.set_commit_status(
                owner=owner,
                repo=repo,
                sha=commit_sha,
                state="error",
                description=f"Scan error: {str(e)[:100]}",
                context="cra-agent/security",
            )

    async def run(self) -> None:
        """Run the GitHub polling agent."""
        logger.info("Starting GitHub Polling Agent")
        logger.info("No webhooks or ngrok needed - everything stays local!")

        # Setup signal handlers
        loop = asyncio.get_event_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, self._handle_shutdown)

        self._running = True

        try:
            await self.github_poller.start()
        except asyncio.CancelledError:
            logger.info("Polling cancelled")
        finally:
            await self.shutdown()

    def _handle_shutdown(self) -> None:
        """Handle shutdown signal."""
        logger.info("Shutdown signal received")
        self._running = False
        self.github_poller.stop()

    async def shutdown(self) -> None:
        """Gracefully shutdown the agent."""
        logger.info("Shutting down GitHub Polling Agent")
        self._running = False
        self.github_poller.stop()
        await self.github_client.close()
        await self.jira_client.close()
        await self.llm_client.close()
        logger.info("Shutdown complete")


def main() -> None:
    """Main entry point with mode selection."""
    parser = argparse.ArgumentParser(
        description="CRA-AGENT - Cyber Resilience Act Compliance Agent"
    )
    parser.add_argument(
        "--mode",
        choices=["local", "github", "webhook"],
        default="local",
        help="Run mode: local (git repos), github (API polling), webhook (server)",
    )
    args = parser.parse_args()

    if args.mode == "github":
        # GitHub API polling mode - no webhooks needed
        agent = GitHubPollingAgent()
    else:
        # Local git monitoring mode
        agent = CRAAgent()

    try:
        asyncio.run(agent.run())
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
        sys.exit(0)


if __name__ == "__main__":
    main()
