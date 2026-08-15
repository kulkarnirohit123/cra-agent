"""Fixer Agent — auto-generates and applies vulnerability fixes.

This agent uses LLM to:
- Generate code fixes for vulnerabilities
- Create git branches for fixes
- Apply patches to the codebase
- Open pull requests with fix descriptions
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from src.core.models import Action, ActionType, JiraTicket, TriagedFinding
from src.utils.logger import get_logger

if TYPE_CHECKING:
    from pathlib import Path

    from src.integrations.git_client import GitClient
    from src.integrations.llm_client import LLMClient

logger = get_logger(__name__)


FIX_PROMPT_TEMPLATE = """You are a security expert fixing a vulnerability in code.

## Vulnerability Details
- **Type**: {vuln_type}
- **Severity**: {severity}
- **File**: {file_path}
- **Lines**: {line_start}-{line_end}
- **Description**: {description}
- **Fix Suggestion**: {fix_suggestion}

## Current Code
```{language}
{code_snippet}
```

## Your Task
Provide a JSON response with the fixed code:

```json
{{
  "fixed_code": "The complete fixed code block",
  "explanation": "Explanation of what was changed and why",
  "confidence": 0.0-1.0
}}
```

Respond ONLY with the JSON object, no additional text.
"""


class FixerAgent:
    """Auto-generates and applies vulnerability fixes.

    Uses LLM to generate code fixes, creates branches, applies patches,
    and opens pull requests.
    """

    def __init__(
        self,
        repo_path: Path,
        llm_client: LLMClient,
        git_client: GitClient,
        branch_prefix: str = "cra-agent/fix-",
    ) -> None:
        """Initialize the fixer agent.

        Args:
            repo_path: Path to the git repository.
            llm_client: LLM client for code generation.
            git_client: Git operations client.
            branch_prefix: Prefix for fix branches.
        """
        self.repo_path = repo_path
        self.llm_client = llm_client
        self.git_client = git_client
        self.branch_prefix = branch_prefix
        logger.info("Fixer agent initialized")

    async def fix_finding(
        self,
        finding: TriagedFinding,
        jira_ticket: JiraTicket | None = None,
    ) -> Action:
        """Generate and apply a fix for a single finding.

        Args:
            finding: The triaged finding to fix.
            jira_ticket: Associated Jira ticket (optional).

        Returns:
            Action describing the fix attempt.
        """
        logger.info(
            "Fixing finding",
            finding_id=finding.id,
            vuln_id=finding.vuln_id,
            file=finding.file_path,
        )

        try:
            # Generate fix using LLM
            fix_result = await self._generate_fix(finding)

            if not fix_result.get("fixed_code"):
                return Action(
                    action_type=ActionType.FIX,
                    description=f"Failed to generate fix for {finding.id}",
                    details={"finding_id": finding.id, "error": "No fix generated"},
                    success=False,
                    error="LLM did not generate a fix",
                )

            # Create branch and apply fix
            branch_name = f"{self.branch_prefix}{finding.id[:8]}"
            await self.git_client.create_branch(branch_name)

            # Apply the fix
            await self.git_client.apply_fix(
                file_path=finding.file_path,
                old_code=finding.code_snippet,
                new_code=fix_result["fixed_code"],
            )

            # Commit the fix
            commit_message = f"fix: {finding.title}\n\nFixes: {finding.vuln_id or finding.id}"
            if jira_ticket:
                commit_message += f"\nJira: {jira_ticket.key}"

            await self.git_client.commit(commit_message)

            # Push and create PR
            pr_url = await self.git_client.create_pull_request(
                branch_name=branch_name,
                title=f"Fix: {finding.title}",
                body=self._build_pr_description(finding, fix_result, jira_ticket),
            )

            logger.info(
                "Fix applied successfully",
                finding_id=finding.id,
                branch=branch_name,
                pr_url=pr_url,
            )

            return Action(
                action_type=ActionType.FIX,
                description=f"Fixed {finding.vuln_id or finding.id} in {finding.file_path}",
                details={
                    "finding_id": finding.id,
                    "branch": branch_name,
                    "pr_url": pr_url,
                    "explanation": fix_result.get("explanation", ""),
                },
                success=True,
            )

        except Exception as e:
            logger.error("Fix failed", finding_id=finding.id, error=str(e))
            return Action(
                action_type=ActionType.FIX,
                description=f"Failed to fix {finding.id}",
                details={"finding_id": finding.id},
                success=False,
                error=str(e),
            )

    async def fix_findings(
        self,
        findings: list[TriagedFinding],
        jira_tickets: list[JiraTicket],
    ) -> list[Action]:
        """Fix multiple findings.

        Args:
            findings: List of triaged findings to fix.
            jira_tickets: List of associated Jira tickets.

        Returns:
            List of actions describing fix attempts.
        """
        logger.info("Fixing findings", count=len(findings))

        # Create ticket lookup
        ticket_lookup = {t.finding_id: t for t in jira_tickets}

        actions: list[Action] = []

        for finding in findings:
            ticket = ticket_lookup.get(finding.id)
            action = await self.fix_finding(finding, ticket)
            actions.append(action)

        successful = sum(1 for a in actions if a.success)
        logger.info(
            "Fix batch completed",
            total=len(actions),
            successful=successful,
            failed=len(actions) - successful,
        )

        return actions

    async def _generate_fix(self, finding: TriagedFinding) -> dict:
        """Generate a fix using LLM.

        Args:
            finding: The finding to fix.

        Returns:
            Dict with fixed_code and explanation.
        """
        prompt = FIX_PROMPT_TEMPLATE.format(
            vuln_type=finding.scanner,
            severity=finding.triage.severity.value,
            file_path=finding.file_path,
            line_start=finding.line_start,
            line_end=finding.line_end,
            description=finding.description,
            fix_suggestion=finding.triage.fix_suggestion or "Use best practices",
            language=finding.file_extension.lstrip(".") or "text",
            code_snippet=finding.code_snippet or "# Code not available",
        )

        try:
            response = await self.llm_client.generate_json(prompt)
            return response
        except Exception as e:
            logger.error("LLM fix generation failed", error=str(e))
            return {}

    def _build_pr_description(
        self,
        finding: TriagedFinding,
        fix_result: dict,
        jira_ticket: JiraTicket | None,
    ) -> str:
        """Build pull request description.

        Args:
            finding: The finding being fixed.
            fix_result: The fix result from LLM.
            jira_ticket: Associated Jira ticket.

        Returns:
            PR description markdown.
        """
        lines = [
            f"# Fix: {finding.title}",
            "",
            f"**Vulnerability**: {finding.vuln_id or finding.id}",
            f"**Severity**: {finding.triage.severity.value}",
            f"**File**: `{finding.file_path}`",
            "",
            "## Description",
            finding.description,
            "",
            "## Fix Applied",
            fix_result.get("explanation", "No explanation provided"),
            "",
        ]

        if jira_ticket:
            lines.extend(
                [
                    "## Related Ticket",
                    f"[{jira_ticket.key}]({jira_ticket.url})",
                    "",
                ]
            )

        lines.extend(
            [
                "## CRA Compliance",
                f"This fix addresses CRA requirements: {', '.join(finding.cra_mapping)}",
                "",
                "---",
                "*Automated fix generated by CRA-AGENT*",
            ]
        )

        return "\n".join(lines)
