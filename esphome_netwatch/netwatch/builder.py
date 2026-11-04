"""The ESPHome Device Builder's own HTTP API: the same source Home Assistant's ESPHome integration reads.

  GET /devices                        every configured device: name, friendly_name, comment, area, platform, mac, ...
  GET /json-config?configuration=x    that device's fully resolved config: API key / password, web_server auth

As an add-on the Device Builder serves these, without auth, on its trusted ingress site (127.0.0.1:<ingress port>,
loopback and the Supervisor only). NetWatch is on the host network too, so it reaches that site the way HA does; the
ingress port comes from the Supervisor (/addons/<slug>/info). Locally, point `esphome_url` at a Device Builder.
Nothing is read from files or kept on disk: the device list is refreshed every `builder_interval`.
"""
import asyncio
import logging
import os
import time

import aiohttp

from .probes import norm_mac

log = logging.getLogger("netwatch")
FIELDS = ("name", "friendly_name", "comment", "area", "configuration", "target_platform", "deployed_version",
          "current_version")


class DeviceBuilder:
    def __init__(self, opts):
        self.url = (opts.get("esphome_url") or "").rstrip("/") or None
        self.slug = opts.get("esphome_addon") or "5c53de3b_esphome"
        self.interval = opts.get("builder_interval") or 900
        self.token = os.environ.get("SUPERVISOR_TOKEN")
        self.devices = {}          # name -> FIELDS + mac
        self.creds = {}            # name -> {api_key, api_password, web_username, web_password}
        self.stale = set()         # names whose credentials were rejected: fetch again
        self.state = None          # last outcome, for the log (logged on change only)
        self._wake = asyncio.Event()

    def _note(self, state, *args):
        if state != self.state:
            self.state = state
            (log.info if state == "ok" else log.warning)(*args)

    async def _base(self, s):
        if self.url:
            return self.url
        if not self.token:
            self._note("no_supervisor", "Device Builder: no Supervisor token and no esphome_url; device list unavailable")
            return None
        async with s.get(f"http://supervisor/addons/{self.slug}/info",
                         headers={"Authorization": f"Bearer {self.token}"}) as r:
            if r.status != 200:
                self._note("no_addon", "Device Builder: add-on %s not found (HTTP %s); set esphome_addon", self.slug,
                           r.status)
                return None
            d = (await r.json()).get("data") or {}
        if d.get("state") != "started" or not d.get("ingress_port"):
            self._note("stopped", "Device Builder: add-on %s is %s", self.slug, d.get("state"))
            return None
        return f"http://127.0.0.1:{d['ingress_port']}"

    async def _config(self, s, base, name, configuration):
        async with s.get(f"{base}/json-config", params={"configuration": configuration}) as r:
            if r.status != 200:
                return
            c = await r.json()
        api = c.get("api") or {}
        auth = (c.get("web_server") or {}).get("auth") or {}
        self.creds[name] = {"api_key": (api.get("encryption") or {}).get("key"), "api_password": api.get("password"),
                            "web_username": auth.get("username"), "web_password": auth.get("password")}

    async def refresh(self):
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=120)) as s:
            base = await self._base(s)
            if not base:
                return
            async with s.get(f"{base}/devices") as r:
                r.raise_for_status()
                rows = (await r.json()).get("configured") or []
            devs = {}
            for row in rows:
                if row.get("name"):
                    devs[row["name"]] = dict({k: row.get(k) for k in FIELDS}, mac=norm_mac(row.get("mac_address")))
            self.devices = devs
            for name in [n for n in self.creds if n not in devs]:
                del self.creds[name]
            todo = [n for n in devs if n not in self.creds or n in self.stale]
            sem = asyncio.Semaphore(2)              # json-config resolves the whole config: keep it gentle

            async def one(n):
                async with sem:
                    try:
                        await self._config(s, base, n, devs[n]["configuration"])
                    except (aiohttp.ClientError, asyncio.TimeoutError, ValueError):
                        pass
                    self.stale.discard(n)
            await asyncio.gather(*(one(n) for n in todo))
        self._note("ok", "Device Builder: %d configured devices, credentials for %d", len(self.devices),
                   sum(1 for c in self.creds.values() if any(c.values())))

    def rejected(self, name):
        """A device turned down the credentials it was configured with: fetch its config again soon."""
        if name in self.devices and name not in self.stale:
            self.stale.add(name)
            self._wake.set()

    def creds_for(self, name):
        return self.creds.get(name or "") or {}

    def keys(self):
        """Distinct API keys of the fleet, for a host that has not named itself yet."""
        return list(dict.fromkeys(c["api_key"] for c in self.creds.values() if c.get("api_key")))

    async def run(self):
        while True:
            t0 = time.monotonic()
            try:
                await self.refresh()
            except (aiohttp.ClientError, asyncio.TimeoutError, ValueError) as e:
                self._note("error", "Device Builder: %s", e.__class__.__name__)
            self._wake.clear()
            try:
                await asyncio.wait_for(self._wake.wait(), max(30, self.interval - (time.monotonic() - t0)))
                await asyncio.sleep(30)               # batch several rejections into one refresh
            except asyncio.TimeoutError:
                pass
