"""OUI -> vendor via mac-vendor-lookup. The IEEE list is downloaded into the data dir on first start and
refreshed monthly; lookups are plain dict hits. If the download fails the column just stays empty."""
import asyncio
import logging
import time
from pathlib import Path

from mac_vendor_lookup import AsyncMacLookup, BaseMacLookup

log = logging.getLogger("netwatch")
MAX_AGE = 30 * 86400


class Vendors:
    def __init__(self, data_dir):
        self.path = Path(data_dir) / "mac-vendors.txt"
        BaseMacLookup.cache_path = str(self.path)
        self.prefixes = {}

    def lookup(self, mac):
        h = (mac or "").replace(":", "").upper()
        if len(h) != 12:
            return ""
        if int(h[:2], 16) & 0x02:
            return "(locally administered)"       # randomised / derived address: no OUI to look up
        return self.prefixes.get(h[:6].encode(), b"").decode(errors="replace")

    async def _refresh(self):
        lk = AsyncMacLookup()
        stale = not self.path.exists() or time.time() - self.path.stat().st_mtime > MAX_AGE - 3600
        if stale:
            try:
                await asyncio.wait_for(lk.update_vendors(), 120)
            except Exception as e:  # noqa: BLE001
                log.warning("OUI list download failed (%s); vendor column %s", type(e).__name__,
                            "uses the old list" if self.path.exists() else "stays empty")
        if self.path.exists() and self.path.stat().st_size:
            await lk.load_vendors()
            self.prefixes = lk.prefixes
            log.info("OUI list: %d vendors", len(self.prefixes))

    async def run(self):
        while True:
            await self._refresh()
            # a failed first download retries hourly instead of leaving the column empty for a month
            await asyncio.sleep(MAX_AGE if self.prefixes else 3600)
