"""CRA Orchestrator — LangGraph state machine for agent coordination.

This module defines the main workflow that coordinates all agents:
1. Scanner Agent: Scans commit diffs for vulnerabilities
2. Suppression Filter: Removes known/ignored vulnerabilities
3. Triage Agent: Classifies and prioritizes findings
4. Jira Agent: Creates tickets with recommendations
5. Fixer Agent: (Optional) Auto-fixes critical vulnerabilities
"""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Any

from langgraph.graph import END, StateGraph

from src.agents.fixer_agent import FixerAgent
from src.agents.jira_agent import JiraAgent
from src.agents.scanner_agent import ScannerAgent
from src.agents.triage_agent import TriageAgent
from src.core.models import AgentState
from src.scanners.suppression_store import SuppressionStore
from src.utils.logger import get_logger

if TYPE_CHECKING:
    from pathlib import Path

    from src.integrations.git_client import GitClient
    from src.integrations.jira_client import JiraClient
    from src.integrations.llm_client import LLMClient

logger = get_logger(__name__)


class CRAOrchestrator:
    """Orchestrates the CRA compliance workflow using LangGraph.

    The workflow follows this state machine:

    START
      ↓
    [scan_commit] → Scanner Agent runs all scanners
      ↓
    [filter_suppressed] → Remove known/ignored findings
      ↓
    [should_triage?] → Check if there are findings to triage
      ├─ No → END
      └─ Yes ↓
    [triage_findings] → Triage Agent classifies findings
      ↓
    [create_jira_tickets] → Jira Agent creates tickets
      ↓
    [should_fix?] → Check if any findings need auto-fix
      ├─ No → END
      └─ Yes ↓
    [auto_fix] → Fixer Agent generates fixes
      ↓
    END
    """

    def __init__(
        self,
        repo_path: Path,
        llm_client: LLMClient,
        jira_client: JiraClient,
        git_client: GitClient,
        suppression_store: SuppressionStore,
    ) -> None:
        """Initialize the orchestrator.

        Args:
            repo_path: Path to the git repository.
            llm_client: LLM client for agent reasoning.
            jira_client: Jira API client.
            git_client: Git operations client.
            suppression_store: Suppression rules store.
        """
        self.repo_path = repo_path
        self.llm_client = llm_client
        self.jira_client = jira_client
        self.git_client = git_client
        self.suppression_store = suppression_store

        # Initialize agents
        self.scanner_agent = ScannerAgent(
            repo_path=repo_path,
            suppression_store=suppression_store,
        )
        self.triage_agent = TriageAgent(llm_client=llm_client)
        self.jira_agent = JiraAgent(jira_client=jira_client)
        self.fixer_agent = FixerAgent(
            repo_path=repo_path,
            llm_client=llm_client,
            git_client=git_client,
        )

        # Build the state graph
        self.graph = self._build_graph()

    def _build_graph(self) -> StateGraph:
        """Build the LangGraph state machine.

        Returns:
            Compiled StateGraph.
        """
        # Create the graph with AgentState schema
        workflow = StateGraph(AgentState)

        # Add nodes (agent steps)
        workflow.add_node("scan_commit", self._scan_commit_node)
        workflow.add_node("filter_suppressed", self._filter_suppressed_node)
        workflow.add_node("triage_findings", self._triage_findings_node)
        workflow.add_node("create_jira_tickets", self._create_jira_tickets_node)
        workflow.add_node("auto_fix", self._auto_fix_node)

        # Define edges (transitions)
        workflow.set_entry_point("scan_commit")

        workflow.add_edge("scan_commit", "filter_suppressed")
        workflow.add_edge("filter_suppressed", "should_triage")
        workflow.add_conditional_edges(
            "should_triage",
            self._should_triage_condition,
            {
                "triage": "triage_findings",
                "end": END,
            },
        )

        workflow.add_edge("triage_findings", "create_jira_tickets")
        workflow.add_edge("create_jira_tickets", "should_fix")
        workflow.add_conditional_edges(
            "should_fix",
            self._should_fix_condition,
            {
                "fix": "auto_fix",
                "end": END,
            },
        )

        workflow.add_edge("auto_fix", END)

        # Compile the graph
        return workflow.compile()

    # -------------------------------------------------------------------------
    # Node implementations
    # -------------------------------------------------------------------------

    async def _scan_commit_node(self, state: AgentState) -> dict[str, Any]:
        """Run all scanners on the commit.

        Args:
            state: Current agent state.

        Returns:
            Updated state with raw findings.
        """
        logger.info("Scanning commit", commit=state["commit_info"].get("hash", "")[:7])

        # Run scanner agent
        raw_findings = await self.scanner_agent.scan_commit(
            commit_info=state["commit_info"],
            changed_files=state["changed_files"],
        )

        return {
            "raw_findings": [f.model_dump() for f in raw_findings],
            "scan_started_at": datetime.utcnow().isoformat(),
        }

    async def _filter_suppressed_node(self, state: AgentState) -> dict[str, Any]:
        """Filter out suppressed findings.

        Args:
            state: Current agent state.

        Returns:
            Updated state with filtered findings.
        """
        from src.core.models import Finding

        raw_findings = [Finding(**f) for f in state["raw_findings"]]
        filtered_findings = self.suppression_store.filter_findings(raw_findings)

        logger.info(
            "Filtered findings",
            total=len(raw_findings),
            suppressed=len(raw_findings) - len(filtered_findings),
            remaining=len(filtered_findings),
        )

        return {
            "filtered_findings": [f.model_dump() for f in filtered_findings],
        }

    async def _triage_findings_node(self, state: AgentState) -> dict[str, Any]:
        """Run triage agent on filtered findings.

        Args:
            state: Current agent state.

        Returns:
            Updated state with triaged findings.
        """
        from src.core.models import Finding

        filtered_findings = [Finding(**f) for f in state["filtered_findings"]]

        logger.info("Triaging findings", count=len(filtered_findings))

        triaged_findings = await self.triage_agent.triage_findings(filtered_findings)

        return {
            "triaged_findings": [f.model_dump() for f in triaged_findings],
        }

    async def _create_jira_tickets_node(self, state: AgentState) -> dict[str, Any]:
        """Create Jira tickets for triaged findings.

        Args:
            state: Current agent state.

        Returns:
            Updated state with Jira tickets.
        """
        from src.core.models import TriagedFinding

        triaged_findings = [TriagedFinding(**f) for f in state["triaged_findings"]]

        logger.info("Creating Jira tickets", count=len(triaged_findings))

        jira_tickets = await self.jira_agent.create_tickets(triaged_findings)

        return {
            "jira_tickets": [t.model_dump() for t in jira_tickets],
        }

    async def _auto_fix_node(self, state: AgentState) -> dict[str, Any]:
        """Auto-fix critical vulnerabilities.

        Args:
            state: Current agent state.

        Returns:
            Updated state with fix actions.
        """
        from src.core.models import JiraTicket, TriagedFinding

        triaged_findings = [TriagedFinding(**f) for f in state["triaged_findings"]]
        jira_tickets = [JiraTicket(**t) for t in state["jira_tickets"]]

        # Filter to findings that need auto-fix
        fixable_findings = [f for f in triaged_findings if f.triage.recommended_action.value == "fix_now"]

        logger.info("Auto-fixing findings", count=len(fixable_findings))

        actions = await self.fixer_agent.fix_findings(fixable_findings, jira_tickets)

        return {
            "actions": [a.model_dump() for a in actions],
            "scan_completed_at": datetime.utcnow().isoformat(),
        }

    # -------------------------------------------------------------------------
    # Conditional edge functions
    # -------------------------------------------------------------------------

    def _should_triage_condition(self, state: AgentState) -> str:
        """Determine if we should proceed to triage.

        Args:
            state: Current agent state.

        Returns:
            "triage" if there are findings, "end" otherwise.
        """
        filtered_findings = state.get("filtered_findings", [])
        if not filtered_findings:
            logger.info("No findings to triage, ending workflow")
            return "end"
        return "triage"

    def _should_fix_condition(self, state: AgentState) -> str:
        """Determine if we should proceed to auto-fix.

        Args:
            state: Current agent state.

        Returns:
            "fix" if there are fixable findings, "end" otherwise.
        """
        from src.core.models import TriagedFinding

        triaged_findings = [TriagedFinding(**f) for f in state.get("triaged_findings", [])]

        # Check if any findings need auto-fix
        fixable = [f for f in triaged_findings if f.triage.recommended_action.value == "fix_now"]

        if not fixable:
            logger.info("No findings need auto-fix, ending workflow")
            return "end"
        return "fix"

    # -------------------------------------------------------------------------
    # Public API
    # -------------------------------------------------------------------------

    async def run(self, commit_info: dict[str, Any], changed_files: list[dict[str, Any]]) -> AgentState:
        """Run the full CRA compliance workflow.

        Args:
            commit_info: Commit information.
            changed_files: List of file changes.

        Returns:
            Final agent state with all results.
        """
        # Initialize state
        initial_state: AgentState = {
            "commit_info": commit_info,
            "changed_files": changed_files,
            "raw_findings": [],
            "filtered_findings": [],
            "triaged_findings": [],
            "jira_tickets": [],
            "actions": [],
            "errors": [],
            "scan_started_at": "",
            "scan_completed_at": None,
        }

        logger.info(
            "Starting CRA workflow",
            commit=commit_info.get("hash", "")[:7],
            files=len(changed_files),
        )

        # Run the graph
        final_state = await self.graph.ainvoke(initial_state)

        logger.info(
            "CRA workflow completed",
            commit=commit_info.get("hash", "")[:7],
            findings=len(final_state.get("triaged_findings", [])),
            tickets=len(final_state.get("jira_tickets", [])),
        )

        return final_state
