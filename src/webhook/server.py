"""FastAPI webhook server for receiving Jira and GitHub events.

Provides endpoints for:
- Jira webhook events (issue updates, transitions)
- GitHub webhook events (push, pull_request)
- Health checks
- Metrics
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

from src.utils.logger import get_logger
from src.webhook.github_handler import GitHubWebhookHandler
from src.webhook.handlers import JiraWebhookHandler

if TYPE_CHECKING:
    from src.integrations.git_client import GitClient
    from src.integrations.github_client import GitHubClient
    from src.integrations.jira_client import JiraClient
    from src.integrations.llm_client import LLMClient
    from src.scanners.suppression_store import SuppressionStore

logger = get_logger(__name__)


def create_app(
    jira_client: JiraClient,
    llm_client: LLMClient,
    git_client: GitClient,
    suppression_store: SuppressionStore,
    github_client: GitHubClient | None = None,
    webhook_secret: str = "",
    github_webhook_secret: str = "",
    scan_callback: Any = None,
) -> FastAPI:
    """Create the FastAPI application.

    Args:
        jira_client: Jira API client.
        llm_client: LLM client.
        git_client: Git operations client.
        suppression_store: Suppression rules store.
        github_client: GitHub API client (optional).
        webhook_secret: Secret for Jira webhook signature validation.
        github_webhook_secret: Secret for GitHub webhook signature validation.
        scan_callback: Async function to call when scan is needed.

    Returns:
        Configured FastAPI application.
    """
    app = FastAPI(
        title="CRA-AGENT Webhook Server",
        description="Webhook server for CRA compliance agent",
        version="0.1.0",
    )

    # Initialize Jira webhook handler
    webhook_handler = JiraWebhookHandler(
        jira_client=jira_client,
        llm_client=llm_client,
        git_client=git_client,
        suppression_store=suppression_store,
    )

    # Initialize GitHub webhook handler if client provided
    github_handler: GitHubWebhookHandler | None = None
    if github_client:
        github_handler = GitHubWebhookHandler(
            github_client=github_client,
            webhook_secret=github_webhook_secret,
            scan_callback=scan_callback,
        )

    # -------------------------------------------------------------------------
    # Health check endpoints
    # -------------------------------------------------------------------------

    @app.get("/health")
    async def health_check() -> dict[str, str]:
        """Health check endpoint."""
        return {"status": "healthy", "service": "cra-agent-webhook"}

    @app.get("/ready")
    async def readiness_check() -> dict[str, str]:
        """Readiness check endpoint."""
        return {"status": "ready"}

    # -------------------------------------------------------------------------
    # Jira webhook endpoint
    # -------------------------------------------------------------------------

    @app.post("/webhook/jira")
    async def jira_webhook(request: Request) -> JSONResponse:
        """Receive Jira webhook events.

        Handles:
        - jira:issue_updated
        - jira:issue_created
        - comment_created
        """
        try:
            # Validate webhook signature (if secret configured)
            if webhook_secret:
                signature = request.headers.get("X-Hub-Signature", "")
                if not _validate_signature(request, signature, webhook_secret):
                    raise HTTPException(status_code=401, detail="Invalid signature")

            # Parse webhook payload
            payload = await request.json()
            webhook_event = payload.get("webhookEvent", "")

            logger.info("Received Jira webhook", event=webhook_event)

            # Route to appropriate handler
            result = await webhook_handler.handle_event(payload)

            return JSONResponse(
                status_code=200,
                content={"status": "processed", "result": result},
            )

        except HTTPException:
            raise
        except Exception as e:
            logger.error("Webhook processing failed", error=str(e))
            return JSONResponse(
                status_code=500,
                content={"status": "error", "error": str(e)},
            )

    # -------------------------------------------------------------------------
    # GitHub webhook endpoint
    # -------------------------------------------------------------------------

    @app.post("/webhook/github")
    async def github_webhook(request: Request) -> JSONResponse:
        """Receive GitHub webhook events.

        Handles:
        - push (new commits)
        - pull_request (PR opened/updated)
        - ping (webhook test)
        - installation (app installed)
        """
        if not github_handler:
            return JSONResponse(
                status_code=503,
                content={"status": "error", "error": "GitHub integration not configured"},
            )

        try:
            # Get event type from header
            event_type = request.headers.get("X-GitHub-Event", "")
            delivery_id = request.headers.get("X-GitHub-Delivery", "")

            # Verify webhook signature if secret configured
            if github_webhook_secret:
                signature = request.headers.get("X-Hub-Signature-256", "")
                body = await request.body()
                if not github_handler.verify_signature(body, signature):
                    raise HTTPException(status_code=401, detail="Invalid signature")

            # Parse webhook payload
            payload = await request.json()

            logger.info(
                "Received GitHub webhook",
                event=event_type,
                delivery=delivery_id[:8] if delivery_id else "",
            )

            # Route to appropriate handler
            result = await github_handler.handle_event(event_type, payload)

            return JSONResponse(
                status_code=200,
                content={"status": "processed", "result": result},
            )

        except HTTPException:
            raise
        except Exception as e:
            logger.error("GitHub webhook processing failed", error=str(e))
            return JSONResponse(
                status_code=500,
                content={"status": "error", "error": str(e)},
            )

    # -------------------------------------------------------------------------
    # Manual trigger endpoints
    # -------------------------------------------------------------------------

    @app.post("/trigger/scan")
    async def trigger_scan(request: Request) -> JSONResponse:
        """Manually trigger a scan for a specific commit.

        Request body:
        {
            "commit_hash": "abc123...",
            "branch": "main"
        }
        """
        try:
            payload = await request.json()
            commit_hash = payload.get("commit_hash")
            branch = payload.get("branch", "main")

            if not commit_hash:
                raise HTTPException(status_code=400, detail="commit_hash required")

            logger.info("Manual scan triggered", commit=commit_hash[:7], branch=branch)

            # TODO: Trigger scan workflow
            return JSONResponse(
                status_code=202,
                content={"status": "accepted", "commit": commit_hash[:7]},
            )

        except HTTPException:
            raise
        except Exception as e:
            logger.error("Manual scan trigger failed", error=str(e))
            return JSONResponse(
                status_code=500,
                content={"status": "error", "error": str(e)},
            )

    @app.post("/trigger/suppress")
    async def trigger_suppress(request: Request) -> JSONResponse:
        """Manually add a suppression rule.

        Request body:
        {
            "vuln_id": "CVE-2024-1234",
            "reason": "False positive",
            "jira_issue_key": "CRA-123"
        }
        """
        try:
            payload = await request.json()
            vuln_id = payload.get("vuln_id")
            reason = payload.get("reason", "Manual suppression")
            jira_key = payload.get("jira_issue_key")

            if not vuln_id:
                raise HTTPException(status_code=400, detail="vuln_id required")

            suppression = suppression_store.add_suppression(
                vuln_id=vuln_id,
                reason=reason,
                jira_issue_key=jira_key,
                created_by="manual",
            )

            logger.info("Manual suppression added", vuln_id=vuln_id)

            return JSONResponse(
                status_code=201,
                content={"status": "created", "suppression_id": suppression.id},
            )

        except HTTPException:
            raise
        except Exception as e:
            logger.error("Manual suppression failed", error=str(e))
            return JSONResponse(
                status_code=500,
                content={"status": "error", "error": str(e)},
            )

    # -------------------------------------------------------------------------
    # Metrics endpoint
    # -------------------------------------------------------------------------

    @app.get("/metrics")
    async def get_metrics() -> JSONResponse:
        """Get agent metrics."""
        suppressions = suppression_store.get_all_suppressions()

        metrics = {
            "total_suppressions": len(suppressions),
            "active_suppressions": sum(1 for s in suppressions if not s.is_expired),
            "expired_suppressions": sum(1 for s in suppressions if s.is_expired),
        }

        return JSONResponse(status_code=200, content=metrics)

    return app


def _validate_signature(request: Request, signature: str, secret: str) -> bool:
    """Validate webhook signature.

    Args:
        request: FastAPI request.
        signature: Signature from header.
        secret: Webhook secret.

    Returns:
        True if signature is valid.
    """
    # TODO: Implement proper signature validation
    # For Jira, this would validate the webhook secret
    return True
