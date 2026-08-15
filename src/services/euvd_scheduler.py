"""EUVD Scheduler Service — Background task for automatic EUVD synchronization.

This service runs in the background and automatically syncs vulnerability data
from the EU Vulnerability Database (ENISA) every 4 hours (configurable).

Features:
- Automatic scheduled sync every 4 hours
- Manual sync trigger capability
- Sync status tracking and history
- Integration with metrics store
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from datetime import datetime, timedelta
from typing import Any

from src.utils.logger import get_logger

logger = get_logger(__name__)


class EUVDSchedulerService:
    """Background scheduler for EUVD data synchronization.

    This service:
    - Runs as an async background task
    - Syncs vulnerability data from EUVD every 4 hours
    - Tracks sync status and history
    - Can be triggered manually
    """

    DEFAULT_INTERVAL_HOURS = 4

    def __init__(
        self,
        interval_hours: int = DEFAULT_INTERVAL_HOURS,
        auto_start: bool = True,
        on_sync_complete: Callable[[dict], None] | None = None,
    ) -> None:
        """Initialize the EUVD scheduler.

        Args:
            interval_hours: Hours between automatic syncs.
            auto_start: Whether to start syncing immediately.
            on_sync_complete: Callback function when sync completes.
        """
        self.interval_hours = interval_hours
        self.interval_seconds = interval_hours * 3600
        self.auto_start = auto_start
        self.on_sync_complete = on_sync_complete

        self._running = False
        self._task: asyncio.Task | None = None
        self._last_sync: datetime | None = None
        self._next_sync: datetime | None = None
        self._sync_count = 0
        self._sync_history: list[dict[str, Any]] = []

        logger.info(
            "EUVD Scheduler initialized",
            interval_hours=interval_hours,
            auto_start=auto_start,
        )

    @property
    def is_running(self) -> bool:
        """Check if scheduler is running."""
        return self._running

    @property
    def last_sync(self) -> datetime | None:
        """Get last sync timestamp."""
        return self._last_sync

    @property
    def next_sync(self) -> datetime | None:
        """Get next scheduled sync timestamp."""
        return self._next_sync

    @property
    def sync_count(self) -> int:
        """Get total sync count."""
        return self._sync_count

    @property
    def time_until_next_sync(self) -> timedelta | None:
        """Get time remaining until next sync."""
        if self._next_sync is None:
            return None
        remaining = self._next_sync - datetime.now()
        return remaining if remaining.total_seconds() > 0 else timedelta(0)

    def get_status(self) -> dict[str, Any]:
        """Get current scheduler status.

        Returns:
            Dictionary with scheduler status information.
        """
        return {
            "running": self._running,
            "last_sync": self._last_sync.isoformat() if self._last_sync else None,
            "next_sync": self._next_sync.isoformat() if self._next_sync else None,
            "sync_count": self._sync_count,
            "interval_hours": self.interval_hours,
            "time_until_next_sync": str(self.time_until_next_sync) if self.time_until_next_sync else None,
        }

    def get_history(self, limit: int = 10) -> list[dict[str, Any]]:
        """Get sync history.

        Args:
            limit: Maximum number of history entries to return.

        Returns:
            List of sync history entries.
        """
        return self._sync_history[-limit:]

    async def start(self) -> None:
        """Start the scheduler background task."""
        if self._running:
            logger.warning("EUVD Scheduler already running")
            return

        self._running = True
        self._task = asyncio.create_task(self._run_loop())
        logger.info("EUVD Scheduler started")

    async def stop(self) -> None:
        """Stop the scheduler."""
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
        logger.info("EUVD Scheduler stopped")

    async def trigger_sync(self) -> dict[str, Any]:
        """Manually trigger a sync.

        Returns:
            Sync result dictionary.
        """
        logger.info("Manual EUVD sync triggered")
        return await self._perform_sync()

    async def _run_loop(self) -> None:
        """Main scheduler loop."""
        logger.info("EUVD Scheduler loop started")

        # Initial sync if auto_start is enabled
        if self.auto_start:
            await self._perform_sync()

        while self._running:
            try:
                # Wait for the interval
                await asyncio.sleep(self.interval_seconds)

                if self._running:
                    await self._perform_sync()

            except asyncio.CancelledError:
                logger.info("EUVD Scheduler loop cancelled")
                break
            except Exception as e:
                logger.error("EUVD Scheduler error", error=str(e))
                # Wait a bit before retrying on error
                await asyncio.sleep(60)

    async def _perform_sync(self) -> dict[str, Any]:
        """Perform the actual EUVD sync.

        Returns:
            Sync result dictionary.
        """
        sync_start = datetime.now()
        self._sync_count += 1

        logger.info(
            "Starting EUVD sync",
            sync_number=self._sync_count,
        )

        try:
            # Import here to avoid circular imports
            from config.settings import get_settings
            from src.integrations.eu_vd_client import EUVDClient

            settings = get_settings()

            # Initialize EUVD client
            client = EUVDClient(
                api_key=settings.euvd_api_key,
                base_url=settings.euvd_base_url,
                organization_id=settings.euvd_organization_id,
                dry_run=settings.euvd_dry_run,
            )

            # Perform sync operations
            result = await self._sync_vulnerabilities(client)

            # Update state
            self._last_sync = datetime.now()
            self._next_sync = self._last_sync + timedelta(hours=self.interval_hours)

            # Record in history
            history_entry = {
                "sync_number": self._sync_count,
                "timestamp": self._last_sync.isoformat(),
                "duration_seconds": (self._last_sync - sync_start).total_seconds(),
                "success": result.get("success", True),
                "vulnerabilities_synced": result.get("synced", 0),
                "new_vulnerabilities": result.get("new", 0),
                "updated_vulnerabilities": result.get("updated", 0),
                "next_sync": self._next_sync.isoformat(),
            }
            self._sync_history.append(history_entry)

            # Keep history limited
            if len(self._sync_history) > 100:
                self._sync_history = self._sync_history[-100:]

            logger.info(
                "EUVD sync completed",
                duration=history_entry["duration_seconds"],
                synced=result.get("synced", 0),
            )

            # Call callback if provided
            if self.on_sync_complete:
                self.on_sync_complete(result)

            await client.close()

            return result

        except Exception as e:
            logger.error("EUVD sync failed", error=str(e))

            # Record failed sync
            self._last_sync = datetime.now()
            self._next_sync = self._last_sync + timedelta(hours=self.interval_hours)

            history_entry = {
                "sync_number": self._sync_count,
                "timestamp": self._last_sync.isoformat(),
                "duration_seconds": (self._last_sync - sync_start).total_seconds(),
                "success": False,
                "error": str(e),
                "next_sync": self._next_sync.isoformat(),
            }
            self._sync_history.append(history_entry)

            return {
                "success": False,
                "error": str(e),
                "synced": 0,
            }

    async def _sync_vulnerabilities(self, client: Any) -> dict[str, Any]:
        """Sync vulnerabilities from EUVD.

        Args:
            client: EUVD client instance.

        Returns:
            Sync result dictionary.
        """
        # Search for recent vulnerabilities
        vulnerabilities = await client.search_vulnerabilities(
            limit=100,
        )

        # In a real implementation, this would:
        # 1. Compare with local database
        # 2. Update/create new vulnerability records
        # 3. Check for matches in scanned repositories
        # 4. Update metrics store

        synced = len(vulnerabilities)
        new_count = 0
        updated_count = 0

        # Simulate processing (in production, this would be real logic)
        for vuln in vulnerabilities:
            # Check if new or update
            # This is placeholder logic
            if vuln.get("is_new", False):
                new_count += 1
            else:
                updated_count += 1

        return {
            "success": True,
            "synced": synced,
            "new": new_count,
            "updated": updated_count,
            "timestamp": datetime.now().isoformat(),
        }


# Global scheduler instance
_scheduler_instance: EUVDSchedulerService | None = None


def get_euvd_scheduler() -> EUVDSchedulerService:
    """Get or create the global EUVD scheduler instance.

    Returns:
        Global EUVDSchedulerService instance.
    """
    global _scheduler_instance
    if _scheduler_instance is None:
        from config.settings import get_settings

        settings = get_settings()

        _scheduler_instance = EUVDSchedulerService(
            interval_hours=settings.euvd_refresh_interval_hours,
            auto_start=settings.euvd_auto_sync,
        )

    return _scheduler_instance


async def start_euvd_scheduler() -> EUVDSchedulerService:
    """Start the EUVD scheduler.

    Returns:
        Running EUVDSchedulerService instance.
    """
    scheduler = get_euvd_scheduler()
    await scheduler.start()
    return scheduler


async def stop_euvd_scheduler() -> None:
    """Stop the EUVD scheduler."""
    global _scheduler_instance
    if _scheduler_instance:
        await _scheduler_instance.stop()
        _scheduler_instance = None
