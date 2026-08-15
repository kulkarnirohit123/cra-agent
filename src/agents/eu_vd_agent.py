"""EU VD (Vulnerability Database) Reporting Agent.

This agent handles reporting vulnerabilities to the EU Vulnerability Database
as required by the Cyber Resilience Act (CRA).

CRA Reporting Requirements:
- Actively exploited vulnerabilities: Report within 24 hours
- Critical vulnerabilities: Report within 72 hours
- Other reportable vulnerabilities: Report within 14 days
- Use CSAF format for security advisories
"""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Any

from src.core.models import (
    Action,
    ActionType,
    Severity,
    TriagedFinding,
)
from src.utils.logger import get_logger

if TYPE_CHECKING:
    from src.integrations.eu_vd_client import EUVDClient

logger = get_logger(__name__)


class EUVDReportingAgent:
    """Agent for reporting vulnerabilities to the EU Vulnerability Database.

    This agent:
    - Evaluates which findings require EU VD reporting
    - Formats findings according to EU VD requirements
    - Submits reports to ENISA's EU VD API
    - Tracks reporting deadlines and compliance status
    """

    def __init__(
        self,
        eu_vd_client: EUVDClient,
        organization_info: dict[str, str] | None = None,
    ) -> None:
        """Initialize the EU VD reporting agent.

        Args:
            eu_vd_client: EU VD API client.
            organization_info: Organization details for reports.
        """
        self.eu_vd_client = eu_vd_client
        self.organization_info = organization_info or {
            "name": "Your Organization",
            "vendor": "Your Vendor Name",
            "product": "Your Product",
            "version": "1.0.0",
            "contact": "security@your-organization.com",
            "namespace": "https://your-organization.com",
        }

        logger.info("EU VD Reporting Agent initialized")

    def should_report(self, finding: TriagedFinding) -> bool:
        """Determine if a finding should be reported to EU VD.

        CRA requires reporting of:
        - Actively exploited vulnerabilities
        - Critical vulnerabilities
        - High severity with likely exploitability
        - Vulnerabilities with CRA article_13 relevance

        Args:
            finding: The triaged finding to evaluate.

        Returns:
            True if the finding should be reported.
        """
        # Always report actively exploited vulnerabilities
        if finding.triage.exploitability.value == "confirmed":
            return True

        # Report critical vulnerabilities
        if finding.triage.severity == Severity.CRITICAL:
            return True

        # Report high severity with likely exploitability
        if finding.triage.severity == Severity.HIGH and finding.triage.exploitability.value == "likely":
            return True

        # Report if CRA article 13 applies (reporting obligations)
        if "article_13" in finding.cra_mapping:
            return True

        return False

    def get_reporting_deadline(self, finding: TriagedFinding) -> datetime:
        """Get the reporting deadline for a finding.

        Args:
            finding: The triaged finding.

        Returns:
            Reporting deadline datetime.
        """
        from datetime import timedelta

        now = datetime.utcnow()

        # 24 hours for actively exploited
        if finding.triage.exploitability.value == "confirmed":
            return now + timedelta(hours=24)

        # 72 hours for critical
        if finding.triage.severity == Severity.CRITICAL:
            return now + timedelta(hours=72)

        # 14 days for others
        return now + timedelta(days=14)

    def format_eu_vd_report(self, finding: TriagedFinding) -> dict[str, Any]:
        """Format a finding as an EU VD report.

        Args:
            finding: The triaged finding to format.

        Returns:
            EU VD formatted report dictionary.
        """
        is_exploited = finding.triage.exploitability.value == "confirmed"

        # Map severity to CVSS-like score
        severity_scores = {
            Severity.CRITICAL: 9.5,
            Severity.HIGH: 7.5,
            Severity.MEDIUM: 5.0,
            Severity.LOW: 2.5,
            Severity.INFO: 0.0,
        }

        return {
            "vulnerability_id": finding.vuln_id or f"CRA-{finding.id[:8]}",
            "title": finding.title,
            "description": finding.description,
            "severity": finding.triage.severity.value,
            "cvss_score": severity_scores.get(finding.triage.severity, 5.0),
            "exploitability": finding.triage.exploitability.value,
            "actively_exploited": is_exploited,
            "affected_product": {
                "vendor": self.organization_info.get("vendor", "Unknown"),
                "product": self.organization_info.get("product", "Unknown Product"),
                "version": self.organization_info.get("version", "unknown"),
            },
            "affected_file": finding.file_path,
            "discovery_date": finding.timestamp.isoformat(),
            "report_date": datetime.utcnow().isoformat(),
            "reporter": {
                "organization": self.organization_info.get("name", "CRA-AGENT"),
                "contact": self.organization_info.get("contact", "security@example.com"),
            },
            "cra_relevance": finding.cra_mapping,
            "mitigation": finding.triage.fix_suggestion,
            "references": [
                {"url": finding.metadata.get("advisory_url", "")},
            ],
        }

    def format_csaf_advisory(self, finding: TriagedFinding) -> dict[str, Any]:
        """Format a finding as a CSAF advisory.

        CSAF (Common Security Advisory Framework) is the standard format
        for security advisories used by EU VD.

        Args:
            finding: The triaged finding to format.

        Returns:
            CSAF-formatted advisory dictionary.
        """
        severity_scores = {
            Severity.CRITICAL: 9.5,
            Severity.HIGH: 7.5,
            Severity.MEDIUM: 5.0,
            Severity.LOW: 2.5,
            Severity.INFO: 0.0,
        }

        is_exploited = finding.triage.exploitability.value == "confirmed"

        return {
            "document": {
                "category": "csaf_security_advisory",
                "csaf_version": "2.0",
                "title": f"CRA-AGENT: {finding.title}",
                "publisher": {
                    "category": "vendor",
                    "name": self.organization_info.get("name", "CRA-AGENT"),
                    "namespace": self.organization_info.get("namespace", "https://cra-agent.local"),
                    "contact_details": self.organization_info.get("contact", "security@cra-agent.local"),
                },
                "tracking": {
                    "id": f"CRA-{finding.id[:8]}",
                    "status": "final",
                    "version": "1.0.0",
                    "initial_release_date": finding.timestamp.isoformat(),
                    "current_release_date": datetime.utcnow().isoformat(),
                    "revision_history": [
                        {
                            "date": datetime.utcnow().isoformat(),
                            "number": "1.0.0",
                            "summary": "Initial report from CRA-AGENT automated scanning",
                        }
                    ],
                },
                "notes": [
                    {
                        "category": "summary",
                        "text": finding.description,
                        "title": "Vulnerability Summary",
                    },
                    {
                        "category": "other",
                        "text": f"CRA Relevance: {', '.join(finding.cra_mapping)}",
                        "title": "CRA Compliance",
                    },
                ],
            },
            "product_tree": {
                "branches": [
                    {
                        "category": "vendor",
                        "name": self.organization_info.get("vendor", "Unknown"),
                        "branches": [
                            {
                                "category": "product_name",
                                "name": self.organization_info.get("product", "Unknown Product"),
                                "branches": [
                                    {
                                        "category": "product_version",
                                        "name": self.organization_info.get("version", "unknown"),
                                        "product": {
                                            "product_id": "CSAFPID-0001",
                                            "name": f"{self.organization_info.get('product', 'Unknown')} "
                                            f"{self.organization_info.get('version', '')}",
                                        },
                                    }
                                ],
                            }
                        ],
                    }
                ]
            },
            "vulnerabilities": [
                {
                    "cve": finding.vuln_id or f"CRA-{finding.id[:8]}",
                    "cwe": {
                        "id": finding.metadata.get("cwe", "CWE-0"),
                        "name": finding.metadata.get("cwe_name", "Unknown"),
                    },
                    "title": finding.title,
                    "notes": [
                        {
                            "category": "description",
                            "text": finding.description,
                        }
                    ],
                    "product_status": {
                        "known_affected": ["CSAFPID-0001"],
                    },
                    "scores": [
                        {
                            "cvss_v3": {
                                "version": "3.1",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                "baseScore": severity_scores.get(finding.triage.severity, 5.0),
                                "baseSeverity": finding.triage.severity.value.upper(),
                            },
                            "products": ["CSAFPID-0001"],
                        }
                    ],
                    "remediations": [
                        {
                            "category": "vendor_fix",
                            "details": finding.triage.fix_suggestion or "Apply security patch when available",
                            "url": finding.metadata.get("advisory_url", ""),
                        }
                    ],
                    "threats": [
                        {
                            "category": "exploit_status",
                            "details": "Actively exploited" if is_exploited else "No known exploitation",
                        }
                    ],
                }
            ],
        }

    async def report_finding(self, finding: TriagedFinding) -> Action:
        """Report a single finding to EU VD.

        Args:
            finding: The triaged finding to report.

        Returns:
            Action describing the report attempt.
        """
        if not self.should_report(finding):
            return Action(
                action_type=ActionType.NOTIFY,
                description=f"Finding {finding.id} does not require EU VD reporting",
                details={"finding_id": finding.id, "reason": "not_reportable"},
                success=True,
            )

        logger.info(
            "Reporting finding to EU VD",
            finding_id=finding.id,
            vuln_id=finding.vuln_id,
            severity=finding.triage.severity.value,
        )

        # Format the report
        report = self.format_eu_vd_report(finding)
        deadline = self.get_reporting_deadline(finding)

        # Check deadline status
        hours_remaining = (deadline - datetime.utcnow()).total_seconds() / 3600
        logger.info(
            "Reporting deadline",
            hours_remaining=f"{hours_remaining:.1f}",
            deadline=deadline.isoformat(),
        )

        try:
            # Submit to EU VD
            result = await self.eu_vd_client.submit_vulnerability(report)

            # Also submit CSAF advisory
            csaf = self.format_csaf_advisory(finding)
            await self.eu_vd_client.submit_csaf_advisory(csaf)

            logger.info(
                "EU VD report submitted",
                finding_id=finding.id,
                result=result,
            )

            return Action(
                action_type=ActionType.NOTIFY,
                description=f"EU VD report submitted for {finding.vuln_id or finding.id}",
                details={
                    "finding_id": finding.id,
                    "vuln_id": finding.vuln_id,
                    "result": result,
                    "deadline": deadline.isoformat(),
                },
                success=True,
            )

        except Exception as e:
            logger.error(
                "EU VD submission failed",
                finding_id=finding.id,
                error=str(e),
            )
            return Action(
                action_type=ActionType.NOTIFY,
                description=f"EU VD submission failed: {str(e)}",
                details={"finding_id": finding.id},
                success=False,
                error=str(e),
            )

    async def report_findings(self, findings: list[TriagedFinding]) -> list[Action]:
        """Report multiple findings to EU VD.

        Args:
            findings: List of triaged findings to evaluate and report.

        Returns:
            List of actions describing report attempts.
        """
        logger.info("Evaluating findings for EU VD reporting", count=len(findings))

        # Filter to reportable findings
        reportable = [f for f in findings if self.should_report(f)]

        logger.info(
            "Findings requiring EU VD reporting",
            total=len(findings),
            reportable=len(reportable),
        )

        actions: list[Action] = []

        for finding in reportable:
            action = await self.report_finding(finding)
            actions.append(action)

        successful = sum(1 for a in actions if a.success)
        logger.info(
            "EU VD reporting completed",
            attempted=len(actions),
            successful=successful,
        )

        return actions

    async def update_report(
        self,
        vuln_id: str,
        status: str | None = None,
        mitigation: str | None = None,
    ) -> Action:
        """Update an existing EU VD report.

        Args:
            vuln_id: The vulnerability identifier.
            status: New status (e.g., "mitigated", "patched").
            mitigation: Mitigation details.

        Returns:
            Action describing the update attempt.
        """
        updates: dict[str, Any] = {}
        if status:
            updates["status"] = status
        if mitigation:
            updates["mitigation"] = mitigation

        try:
            result = await self.eu_vd_client.update_vulnerability(vuln_id, updates)

            logger.info("EU VD report updated", vuln_id=vuln_id)

            return Action(
                action_type=ActionType.UPDATE_TICKET,
                description=f"EU VD report {vuln_id} updated",
                details={"vuln_id": vuln_id, "updates": updates, "result": result},
                success=True,
            )

        except Exception as e:
            logger.error("EU VD update failed", vuln_id=vuln_id, error=str(e))
            return Action(
                action_type=ActionType.UPDATE_TICKET,
                description=f"EU VD update failed: {str(e)}",
                details={"vuln_id": vuln_id},
                success=False,
                error=str(e),
            )

    def generate_compliance_report(
        self,
        findings: list[TriagedFinding],
    ) -> dict[str, Any]:
        """Generate a CRA compliance report summary.

        Args:
            findings: List of triaged findings.

        Returns:
            Compliance report summary.
        """
        reportable = [f for f in findings if self.should_report(f)]
        exploited = [f for f in reportable if f.triage.exploitability.value == "confirmed"]
        critical = [f for f in reportable if f.triage.severity == Severity.CRITICAL]

        return {
            "total_findings": len(findings),
            "reportable_findings": len(reportable),
            "actively_exploited": len(exploited),
            "critical_vulnerabilities": len(critical),
            "reporting_deadlines": {
                "within_24_hours": len(exploited),
                "within_72_hours": len(critical),
                "within_14_days": len(reportable) - len(exploited) - len(critical),
            },
            "cra_article_mapping": {
                "annex_i_section_1": sum(1 for f in findings if "annex_i_section_1" in f.cra_mapping),
                "annex_i_section_2": sum(1 for f in findings if "annex_i_section_2" in f.cra_mapping),
                "annex_ii": sum(1 for f in findings if "annex_ii" in f.cra_mapping),
                "article_13": sum(1 for f in findings if "article_13" in f.cra_mapping),
            },
        }
