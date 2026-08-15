"""Triage Agent — LLM-powered vulnerability classification and prioritization.

This agent uses LLM reasoning to:
- Assess severity and exploitability
- Map findings to CRA articles/annexes
- Recommend triage actions (fix now, fix soon, suppress, investigate)
- Generate fix suggestions
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from src.core.models import (
    CRARelevance,
    Exploitability,
    Finding,
    RecommendedAction,
    Severity,
    TriagedFinding,
    TriageResult,
)
from src.utils.logger import get_logger

if TYPE_CHECKING:
    from src.integrations.llm_client import LLMClient

logger = get_logger(__name__)


TRIAGE_PROMPT_TEMPLATE = """You are a security expert performing triage on vulnerability findings \
for CRA (Cyber Resilience Act) compliance.

Analyze the following vulnerability finding and provide a structured assessment:

## Finding Details
- **Scanner**: {scanner}
- **Vulnerability ID**: {vuln_id}
- **Title**: {title}
- **Description**: {description}
- **Severity (raw)**: {severity}
- **File**: {file_path}
- **Lines**: {line_start}-{line_end}
- **Code Snippet**:
```
{code_snippet}
```

## Your Task
Provide a JSON response with the following structure:

```json
{{
  "severity": "critical|high|medium|low|info",
  "exploitability": "confirmed|likely|possible|unlikely",
  "cra_relevance": ["annex_i_section_1", "annex_i_section_2", "annex_ii", "article_13", "none"],
  "recommended_action": "fix_now|fix_soon|suppress|investigate",
  "reasoning": "Your detailed reasoning here...",
  "fix_suggestion": "Specific fix approach or null if not applicable",
  "confidence": 0.0-1.0
}}
```

## CRA Mapping Guidelines
- **annex_i_section_1**: Security requirements (hardcoded credentials, insecure defaults, weak crypto)
- **annex_i_section_2**: Vulnerability handling process (known CVEs, dependency vulns, code vulns)
- **annex_ii**: SBOM/software component transparency (missing SBOM, outdated deps, unmaintained deps)
- **article_13**: Reporting obligations (actively exploited vulns, zero-days, critical CVEs)

## Action Guidelines
- **fix_now**: Critical/high severity with confirmed exploitability
- **fix_soon**: Medium/high severity with possible exploitability
- **suppress**: False positive, accepted risk, or known issue
- **investigate**: Needs more information to determine action

Respond ONLY with the JSON object, no additional text.
"""


class TriageAgent:
    """LLM-powered vulnerability triage agent.

    Uses LLM reasoning to classify and prioritize vulnerability findings,
    map them to CRA requirements, and recommend actions.
    """

    def __init__(self, llm_client: LLMClient) -> None:
        """Initialize the triage agent.

        Args:
            llm_client: LLM client for reasoning.
        """
        self.llm_client = llm_client
        logger.info("Triage agent initialized")

    async def triage_finding(self, finding: Finding) -> TriagedFinding:
        """Triage a single finding using LLM.

        Args:
            finding: The finding to triage.

        Returns:
            TriagedFinding with LLM assessment.
        """
        logger.debug("Triaging finding", finding_id=finding.id, vuln_id=finding.vuln_id)

        # Build prompt
        prompt = TRIAGE_PROMPT_TEMPLATE.format(
            scanner=finding.scanner,
            vuln_id=finding.vuln_id or "N/A",
            title=finding.title,
            description=finding.description,
            severity=finding.severity.value,
            file_path=finding.file_path,
            line_start=finding.line_start,
            line_end=finding.line_end,
            code_snippet=finding.code_snippet or "N/A",
        )

        # Get LLM response
        try:
            response = await self.llm_client.generate_json(prompt)
            triage_result = self._parse_triage_response(response)
        except Exception as e:
            logger.error("LLM triage failed", finding_id=finding.id, error=str(e))
            # Fallback to default triage
            triage_result = self._default_triage(finding)

        # Create TriagedFinding
        triaged = TriagedFinding(
            **finding.model_dump(),
            triage=triage_result,
            cra_mapping=[cr.value for cr in triage_result.cra_relevance],
            sbom_component=self._extract_sbom_component(finding),
        )

        return triaged

    async def triage_findings(self, findings: list[Finding]) -> list[TriagedFinding]:
        """Triage multiple findings.

        Args:
            findings: List of findings to triage.

        Returns:
            List of triaged findings.
        """
        logger.info("Triaging findings", count=len(findings))

        triaged_findings: list[TriagedFinding] = []

        for finding in findings:
            triaged = await self.triage_finding(finding)
            triaged_findings.append(triaged)

        # Sort by severity (critical first)
        triaged_findings.sort(key=lambda f: f.triage.severity.weight, reverse=True)

        logger.info(
            "Triage completed",
            total=len(triaged_findings),
            critical=sum(1 for f in triaged_findings if f.triage.severity == Severity.CRITICAL),
            high=sum(1 for f in triaged_findings if f.triage.severity == Severity.HIGH),
        )

        return triaged_findings

    def _parse_triage_response(self, response: dict) -> TriageResult:
        """Parse LLM response into TriageResult.

        Args:
            response: LLM JSON response.

        Returns:
            Parsed TriageResult.
        """
        try:
            severity = Severity(response.get("severity", "medium"))
            exploitability = Exploitability(response.get("exploitability", "possible"))

            cra_relevance_raw = response.get("cra_relevance", ["none"])
            if isinstance(cra_relevance_raw, str):
                cra_relevance_raw = [cra_relevance_raw]
            cra_relevance = [CRARelevance(cr) for cr in cra_relevance_raw]

            recommended_action = RecommendedAction(response.get("recommended_action", "investigate"))
            reasoning = response.get("reasoning", "No reasoning provided")
            fix_suggestion = response.get("fix_suggestion")
            confidence = float(response.get("confidence", 0.5))

            return TriageResult(
                severity=severity,
                exploitability=exploitability,
                cra_relevance=cra_relevance,
                recommended_action=recommended_action,
                reasoning=reasoning,
                fix_suggestion=fix_suggestion,
                confidence=confidence,
            )

        except Exception as e:
            logger.warning("Failed to parse triage response", error=str(e))
            return self._default_triage_result()

    def _default_triage(self, finding: Finding) -> TriageResult:
        """Generate default triage when LLM fails.

        Args:
            finding: The finding.

        Returns:
            Default TriageResult based on raw severity.
        """
        return TriageResult(
            severity=finding.severity,
            exploitability=Exploitability.POSSIBLE,
            cra_relevance=[CRARelevance.ANNEX_I_SECTION_2],
            recommended_action=RecommendedAction.INVESTIGATE,
            reasoning="Default triage - LLM assessment failed",
            fix_suggestion=None,
            confidence=0.3,
        )

    def _default_triage_result(self) -> TriageResult:
        """Generate default triage result.

        Returns:
            Default TriageResult.
        """
        return TriageResult(
            severity=Severity.MEDIUM,
            exploitability=Exploitability.POSSIBLE,
            cra_relevance=[CRARelevance.NONE],
            recommended_action=RecommendedAction.INVESTIGATE,
            reasoning="Default triage - parsing failed",
            fix_suggestion=None,
            confidence=0.2,
        )

    def _extract_sbom_component(self, finding: Finding) -> str | None:
        """Extract SBOM component identifier from finding.

        Args:
            finding: The finding.

        Returns:
            SBOM component identifier or None.
        """
        # For dependency findings, extract package info
        if finding.scanner == "dependency":
            package = finding.metadata.get("package")
            version = finding.metadata.get("version")
            if package and version:
                return f"pkg:{package}@{version}"

        return None
