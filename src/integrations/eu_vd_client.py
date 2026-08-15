"""EU VD (Vulnerability Database) client — integration with ENISA's EU VD API.

The EU Vulnerability Database is maintained by ENISA (European Union Agency
for Cybersecurity) as part of the Cyber Resilience Act (CRA) requirements.

This client handles:
- Submitting vulnerability reports
- Updating existing reports
- Querying vulnerability information
- Managing reporting deadlines
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

import httpx

from src.utils.logger import get_logger

logger = get_logger(__name__)


# EU VD API endpoints (ENISA)
# Note: These are placeholder URLs - update with actual ENISA endpoints when available
EU_VD_BASE_URL = "https://eu-vd.enisa.europa.eu/api/v1"
EU_VD_SANDBOX_URL = "https://sandbox.eu-vd.enisa.europa.eu/api/v1"


class EUVDClient:
    """Client for the EU Vulnerability Database API.

    The EU VD is the central vulnerability reporting system mandated by
    the Cyber Resilience Act (CRA). Manufacturers must report:
    - Actively exploited vulnerabilities within 24 hours
    - Critical vulnerabilities within 72 hours
    - Other reportable vulnerabilities within 14 days
    """

    def __init__(
        self,
        api_key: str = "",
        base_url: str = EU_VD_BASE_URL,
        organization_id: str = "",
        timeout: float = 30.0,
        dry_run: bool = True,
    ) -> None:
        """Initialize the EU VD client.

        Args:
            api_key: API authentication key from ENISA.
            base_url: EU VD API base URL.
            organization_id: Organization identifier in EU VD.
            timeout: Request timeout in seconds.
            dry_run: If True, don't actually submit reports.
        """
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.organization_id = organization_id
        self.timeout = timeout
        self.dry_run = dry_run

        self._client: httpx.AsyncClient | None = None

        logger.info(
            "EU VD client initialized",
            base_url=base_url,
            organization_id=organization_id,
            dry_run=dry_run,
        )

    @property
    def client(self) -> httpx.AsyncClient:
        """Get or create HTTP client."""
        if self._client is None:
            headers = {
                "Content-Type": "application/json",
                "Accept": "application/json",
            }
            if self.api_key:
                headers["Authorization"] = f"Bearer {self.api_key}"
            if self.organization_id:
                headers["X-Organization-ID"] = self.organization_id

            self._client = httpx.AsyncClient(
                base_url=self.base_url,
                headers=headers,
                timeout=self.timeout,
            )
        return self._client

    async def close(self) -> None:
        """Close the HTTP client."""
        if self._client:
            await self._client.aclose()
            self._client = None

    async def submit_vulnerability(
        self,
        report: dict[str, Any],
    ) -> dict[str, Any]:
        """Submit a vulnerability report to EU VD.

        Args:
            report: Vulnerability report in EU VD format.

        Returns:
            Response with submission confirmation.
        """
        vuln_id = report.get("vulnerability_id", "unknown")

        if self.dry_run:
            logger.info(
                "DRY RUN: Would submit vulnerability to EU VD",
                vuln_id=vuln_id,
                title=report.get("title", ""),
            )
            return {
                "status": "dry_run",
                "vulnerability_id": vuln_id,
                "message": "Report would be submitted in production mode",
                "timestamp": datetime.utcnow().isoformat(),
            }

        try:
            response = await self.client.post(
                "/vulnerabilities",
                json=report,
            )
            response.raise_for_status()

            result = response.json()
            logger.info(
                "Vulnerability submitted to EU VD",
                vuln_id=vuln_id,
                tracking_id=result.get("tracking_id"),
            )

            return result

        except httpx.HTTPStatusError as e:
            logger.error(
                "EU VD submission failed",
                vuln_id=vuln_id,
                status=e.response.status_code,
                error=e.response.text,
            )
            raise

    async def update_vulnerability(
        self,
        vuln_id: str,
        updates: dict[str, Any],
    ) -> dict[str, Any]:
        """Update an existing vulnerability report.

        Args:
            vuln_id: Vulnerability identifier.
            updates: Fields to update.

        Returns:
            Response with update confirmation.
        """
        if self.dry_run:
            logger.info(
                "DRY RUN: Would update vulnerability in EU VD",
                vuln_id=vuln_id,
                updates=list(updates.keys()),
            )
            return {
                "status": "dry_run",
                "vulnerability_id": vuln_id,
                "message": "Update would be applied in production mode",
                "timestamp": datetime.utcnow().isoformat(),
            }

        try:
            response = await self.client.patch(
                f"/vulnerabilities/{vuln_id}",
                json=updates,
            )
            response.raise_for_status()

            result = response.json()
            logger.info("Vulnerability updated in EU VD", vuln_id=vuln_id)

            return result

        except httpx.HTTPStatusError as e:
            logger.error(
                "EU VD update failed",
                vuln_id=vuln_id,
                status=e.response.status_code,
                error=e.response.text,
            )
            raise

    async def get_vulnerability(self, vuln_id: str) -> dict[str, Any] | None:
        """Get vulnerability information from EU VD.

        Args:
            vuln_id: Vulnerability identifier (CVE or EU VD ID).

        Returns:
            Vulnerability information or None if not found.
        """
        try:
            response = await self.client.get(f"/vulnerabilities/{vuln_id}")

            if response.status_code == 404:
                return None

            response.raise_for_status()
            return response.json()

        except httpx.HTTPStatusError as e:
            logger.error(
                "EU VD query failed",
                vuln_id=vuln_id,
                status=e.response.status_code,
            )
            return None

    async def search_vulnerabilities(
        self,
        query: str | None = None,
        severity: str | None = None,
        product: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Search for vulnerabilities in EU VD.

        Args:
            query: Search query string.
            severity: Filter by severity.
            product: Filter by affected product.
            limit: Maximum results to return.

        Returns:
            List of matching vulnerabilities.
        """
        params: dict[str, Any] = {"limit": limit}
        if query:
            params["q"] = query
        if severity:
            params["severity"] = severity
        if product:
            params["product"] = product

        try:
            response = await self.client.get("/vulnerabilities", params=params)
            response.raise_for_status()

            result = response.json()
            return result.get("results", [])

        except httpx.HTTPStatusError as e:
            logger.error(
                "EU VD search failed",
                status=e.response.status_code,
            )
            return []

    async def submit_csaf_advisory(
        self,
        advisory: dict[str, Any],
    ) -> dict[str, Any]:
        """Submit a CSAF (Common Security Advisory Framework) advisory.

        CSAF is the standard format for security advisories.

        Args:
            advisory: CSAF-formatted advisory.

        Returns:
            Response with submission confirmation.
        """
        if self.dry_run:
            tracking = advisory.get("document", {}).get("tracking", {})
            logger.info(
                "DRY RUN: Would submit CSAF advisory to EU VD",
                tracking_id=tracking.get("id"),
                title=advisory.get("document", {}).get("title", ""),
            )
            return {
                "status": "dry_run",
                "tracking_id": tracking.get("id"),
                "message": "CSAF advisory would be submitted in production mode",
                "timestamp": datetime.utcnow().isoformat(),
            }

        try:
            response = await self.client.post(
                "/advisories",
                json=advisory,
            )
            response.raise_for_status()

            result = response.json()
            logger.info(
                "CSAF advisory submitted to EU VD",
                tracking_id=advisory.get("document", {}).get("tracking", {}).get("id"),
            )

            return result

        except httpx.HTTPStatusError as e:
            logger.error(
                "CSAF submission failed",
                status=e.response.status_code,
                error=e.response.text,
            )
            raise

    async def check_reporting_deadline(
        self,
        vuln_id: str,
        discovery_date: datetime,
        severity: str,
        is_exploited: bool = False,
    ) -> dict[str, Any]:
        """Check reporting deadline status for a vulnerability.

        CRA reporting deadlines:
        - 24 hours: Actively exploited vulnerabilities
        - 72 hours: Critical vulnerabilities
        - 14 days: Other reportable vulnerabilities

        Args:
            vuln_id: Vulnerability identifier.
            discovery_date: When the vulnerability was discovered.
            severity: Vulnerability severity.
            is_exploited: Whether actively exploited.

        Returns:
            Deadline status information.
        """
        from datetime import timedelta

        now = datetime.utcnow()

        # Determine deadline based on CRA requirements
        if is_exploited:
            deadline = discovery_date + timedelta(hours=24)
            deadline_type = "24_hours_exploited"
        elif severity.lower() == "critical":
            deadline = discovery_date + timedelta(hours=72)
            deadline_type = "72_hours_critical"
        else:
            deadline = discovery_date + timedelta(days=14)
            deadline_type = "14_days_standard"

        # Calculate time remaining
        time_remaining = deadline - now
        hours_remaining = time_remaining.total_seconds() / 3600

        # Determine status
        if hours_remaining < 0:
            status = "overdue"
        elif hours_remaining < 4:
            status = "urgent"
        elif hours_remaining < 24:
            status = "approaching"
        else:
            status = "on_track"

        return {
            "vulnerability_id": vuln_id,
            "deadline_type": deadline_type,
            "deadline": deadline.isoformat(),
            "hours_remaining": round(hours_remaining, 1),
            "status": status,
            "is_overdue": hours_remaining < 0,
        }

    async def get_organization_reports(
        self,
        status: str | None = None,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """Get vulnerability reports for the organization.

        Args:
            status: Filter by report status.
            limit: Maximum results to return.

        Returns:
            List of organization's vulnerability reports.
        """
        params: dict[str, Any] = {"limit": limit}
        if status:
            params["status"] = status

        try:
            response = await self.client.get(
                f"/organizations/{self.organization_id}/reports",
                params=params,
            )
            response.raise_for_status()

            result = response.json()
            return result.get("reports", [])

        except httpx.HTTPStatusError as e:
            logger.error(
                "Failed to get organization reports",
                status=e.response.status_code,
            )
            return []

    async def acknowledge_report(
        self,
        report_id: str,
        acknowledgment: dict[str, Any],
    ) -> dict[str, Any]:
        """Acknowledge receipt of a vulnerability report.

        Args:
            report_id: Report identifier.
            acknowledgment: Acknowledgment details.

        Returns:
            Response confirmation.
        """
        if self.dry_run:
            logger.info(
                "DRY RUN: Would acknowledge report",
                report_id=report_id,
            )
            return {
                "status": "dry_run",
                "report_id": report_id,
                "timestamp": datetime.utcnow().isoformat(),
            }

        try:
            response = await self.client.post(
                f"/reports/{report_id}/acknowledge",
                json=acknowledgment,
            )
            response.raise_for_status()

            return response.json()

        except httpx.HTTPStatusError as e:
            logger.error(
                "Acknowledgment failed",
                report_id=report_id,
                status=e.response.status_code,
            )
            raise
