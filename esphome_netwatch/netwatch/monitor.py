"""Host identity (MAC-keyed) and the probe loops.

Identity: an IP that answers is a host keyed 'ip:<ip>' until its MAC is learned from ARP (same segment only),
the mDNS TXT 'mac', or the API's device_info; its history then moves onto the MAC key. A MAC seen at a new IP
is an 'ip_change'; an IP that turns up with a different MAC is 'ip_reassigned'.

Event kinds: new, down, up, reboot, firmware, roam, api_mode, api_fail, api_ok, http_mode, ports,
             mdns_goodbye, ip_change, ip_reassigned, mac_learned
"""
import asyncio
import ipaddress
import json
import logging
import random
import time

from . import mdns, probes

log = logging.getLogger("netwatch")
REBOOT_SLACK = 120          # boot-time estimates jitter by API latency / SNTP; ignore smaller shifts


CRED_FIELDS = ("api_key", "api_password", "web_username", "web_password")


class Monitor:
    def __init__(self, opts, store, builder):
        self.o = opts
        self.store = store
        self.builder = builder                    # per-device credentials + labels (builder.py)
        # add-on options: only for devices the Device Builder does not know
        self.fallback = {k: opts.get(k) or None for k in CRED_FIELDS}
        self.net = ipaddress.ip_network(opts["subnet"], strict=False)
        self.exclude = set(opts.get("exclude") or [])
        self.hosts = store.load_hosts()
        self.by_ip = {}
        for k, h in sorted(self.hosts.items(), key=lambda kv: kv[1].get("last_seen") or 0):
            if h.get("ip"):
                self.by_ip[h["ip"]] = k
        self.by_mdns = {h["mdns"]: k for k, h in self.hosts.items() if h.get("mdns")}
        self.misses = {}
        self.api_sem = asyncio.Semaphore(3)       # ESP8266s have few API slots; never stack sessions
        self.api_busy = set()
        self.probing = set()                      # IPs with a discovery probe pending
        self.ping_sem = asyncio.Semaphore(64)
        self.browser = mdns.Browser(self._mdns_seen, self._mdns_gone)
        self.has_arp = None

    # identity -----------------------------------------------------------
    def save(self, h):
        self.store.save_host(h["key"], h)

    def ev(self, h, kind, detail="", ts=None):
        if isinstance(detail, dict):
            detail = json.dumps(detail)
        self.store.event(h["key"], h.get("ip"), kind, detail, ts)
        # silent by default: events live in the DB / UI, not the add-on log
        log.debug("%-22s %-15s %-13s %s", h.get("name") or h["key"], h.get("ip"), kind, detail)

    def host_for_ip(self, ip, create=True):
        k = self.by_ip.get(ip)
        if k:
            return self.hosts[k]
        if not create:
            return None
        now = time.time()
        h = {"key": f"ip:{ip}", "ip": ip, "mac": None, "first_seen": now, "last_seen": now, "up": True, "ports": []}
        self.hosts[h["key"]] = h
        self.by_ip[ip] = h["key"]
        self.ev(h, "new")
        self.save(h)
        self.probe_soon(ip)
        return h

    def probe_soon(self, ip):
        """Ports + API for a host that just appeared or changed identity, instead of waiting for the hourly
        port pass (the API loop only probes hosts whose ports include 6053)."""
        if not ip or ip in self.exclude or ip in self.probing:
            return
        self.probing.add(ip)

        async def run():
            try:
                await asyncio.sleep(2)               # let ARP / mDNS settle the identity first
                h = self.host_for_ip(ip, create=False)
                if h:
                    await self._ports(h["key"])
                h = self.host_for_ip(ip, create=False)
                if h and (6053 in (h.get("ports") or []) or h.get("mdns")):
                    await self._api(h["key"])
            finally:
                self.probing.discard(ip)
        asyncio.ensure_future(run())

    def learn_mac(self, ip, mac, source):
        """Returns the (possibly re-keyed) host now owning ip."""
        mac = probes.norm_mac(mac)
        cur = self.host_for_ip(ip)
        if not mac or cur["key"] == mac:
            return cur
        owner = self.hosts.get(mac)
        if cur["key"].startswith("ip:"):
            if owner:                                    # known MAC came back on another IP
                self.store.rekey(cur["key"], mac)
                self.store.delete_host(cur["key"])
                del self.hosts[cur["key"]]
                if owner.get("ip") and owner["ip"] != ip:
                    self.ev(owner, "ip_change", f"{owner['ip']} -> {ip} ({source})")
                    if self.by_ip.get(owner["ip"]) == mac:
                        del self.by_ip[owner["ip"]]
                now = time.time()
                owner.update(ip=ip, last_seen=now)
                if not owner.get("up"):                  # back from an outage: close it, or it never ends
                    since = owner.get("down_since") or now
                    owner.update(up=True, down_since=None)
                    self.ev(owner, "up", {"duration": round(now - since)}, now)
            else:                                        # first time this MAC is known: re-key in place
                self.store.rekey(cur["key"], mac)
                self.store.delete_host(cur["key"])
                del self.hosts[cur["key"]]
                cur.update(key=mac, mac=mac)
                self.hosts[mac] = owner = cur
                self.ev(owner, "mac_learned", source)
        else:                                            # this IP belonged to a different MAC
            self.ev(cur, "ip_reassigned", f"{ip} now answered by {mac} ({source})")
            if owner is None:
                now = time.time()
                owner = {"key": mac, "mac": mac, "ip": ip, "first_seen": now, "last_seen": now, "up": True,
                         "ports": list(cur.get("ports") or [])}
                self.hosts[mac] = owner
                self.ev(owner, "new", source)
            else:
                if owner.get("ip") and owner["ip"] != ip:
                    self.ev(owner, "ip_change", f"{owner['ip']} -> {ip} ({source})")
                    if self.by_ip.get(owner["ip"]) == mac:
                        del self.by_ip[owner["ip"]]
                owner.update(ip=ip, last_seen=time.time())
            cur["ip"] = None
            self.save(cur)
        self.by_ip[ip] = mac
        self.misses.pop(ip, None)
        self.save(owner)
        self.probe_soon(ip)                              # new chip / reassigned IP: refresh what it is now
        return owner

    # ping + ARP ---------------------------------------------------------
    async def _ping(self, ip):
        async with self.ping_sem:
            return await probes.ping(ip)

    async def _arp(self):
        t = await probes.arp_table(self.net)
        if self.has_arp is None or self.has_arp != (t is not None):
            self.has_arp = t is not None
            log.info("ARP %s", "available (on-link)" if t is not None else
                     "unavailable: no interface on %s, MACs come from mDNS/API only" % self.net)
        return t or {}

    async def ping_loop(self):
        n = 0
        while True:
            t0 = time.monotonic()
            ips = [ip for ip in self.by_ip if ip not in self.exclude]
            res = await asyncio.gather(*(self._ping(ip) for ip in ips))
            arp = await self._arp()
            now = time.time()
            for ip, ms in zip(ips, res):
                self._ping_result(ip, ms, arp.get(ip), now)
            self.store.flush()
            n += 1
            await asyncio.sleep(max(1, self.o["ping_interval"] - (time.monotonic() - t0)))

    def _ping_result(self, ip, ms, arp, now):
        h = self.host_for_ip(ip, create=False)
        if h is None:
            return
        if arp and arp != "incomplete" and ms is not None:
            h = self.learn_mac(ip, arp, "arp")
        k = h["key"]
        self.store.stat(k, "ping", ms is not None, ms, now)
        if arp:
            self.store.stat(k, "arp", arp != "incomplete", None, now)
        if ms is not None:
            h["last_seen"] = now
            self.misses.pop(ip, None)
            if not h.get("up"):
                since = h.get("down_since") or now
                h.update(up=True, down_since=None)
                self.ev(h, "up", {"duration": round(now - since)}, now)
                self.save(h)
            return
        first, cnt = self.misses.get(ip, (now, 0))
        self.misses[ip] = (first, cnt + 1)
        if h.get("up") and cnt + 1 >= self.o["outage_misses"]:
            h.update(up=False, down_since=first)
            # arp 'incomplete' = nothing answers ARP (off Wi-Fi / powered off); a complete entry with no ping =
            # still associated but the IP stack is not answering (hung, or the AP is dropping traffic)
            self.ev(h, "down", {"arp": arp or "n/a"}, first)
            self.save(h)

    async def sweep_loop(self):
        while True:
            t0 = time.monotonic()
            known = set(self.by_ip)
            cand = [str(ip) for ip in self.net.hosts() if str(ip) not in known and str(ip) not in self.exclude]
            res = await asyncio.gather(*(self._ping(ip) for ip in cand))
            arp = await self._arp()
            fresh = [ip for ip, ms in zip(cand, res) if ms is not None]
            # ARP-only presence: answers ARP but not ICMP
            fresh += [ip for ip, mac in arp.items() if mac != "incomplete" and ip not in known
                      and ip not in fresh and ip not in self.exclude]
            for ip in fresh:
                h = self.host_for_ip(ip)
                if arp.get(ip, "incomplete") != "incomplete":
                    self.learn_mac(ip, arp[ip], "arp")
                self.probe_soon(ip)
            self.store.flush()
            await asyncio.sleep(max(5, self.o["sweep_interval"] - (time.monotonic() - t0)))

    # ports --------------------------------------------------------------
    async def _ports(self, key):
        h = self.hosts.get(key)
        if not h or not h.get("ip"):
            return
        ports = await probes.port_scan(h["ip"])
        h = self.hosts.get(key) or self.host_for_ip(h["ip"], create=False)
        if h is None:
            return
        if ports and sorted(ports) != sorted(h.get("ports") or []):
            if h.get("ports"):
                self.ev(h, "ports", f"{h['ports']} -> {ports}")
            h["ports"] = ports
            self.save(h)

    async def ports_loop(self):
        await asyncio.sleep(20)
        while True:
            for k in [k for k, h in self.hosts.items() if h.get("up") and h.get("ip")]:
                await self._ports(k)
            await asyncio.sleep(3600)

    # ESPHome API --------------------------------------------------------
    async def api_loop(self):
        await asyncio.sleep(30)
        while True:
            t0 = time.monotonic()
            targets = [k for k, h in self.hosts.items() if h.get("ip") and h["ip"] not in self.exclude
                       and (6053 in (h.get("ports") or []) or h.get("api_mode"))]
            random.shuffle(targets)
            gap = self.o["api_interval"] / max(1, len(targets))
            for k in targets:
                if k not in self.api_busy:
                    asyncio.ensure_future(self._api(k))
                await asyncio.sleep(gap)
            await asyncio.sleep(max(1, self.o["api_interval"] - (time.monotonic() - t0)))

    async def _api(self, key):
        h = self.hosts.get(key)
        if not h or not h.get("ip") or key in self.api_busy:
            return
        self.api_busy.add(key)
        try:
            async with self.api_sem:
                r = await self._api_probe(h["ip"], h.get("name") or h.get("mdns"), h.get("api_mode"))
        finally:
            self.api_busy.discard(key)
        ip = h["ip"]
        if r.get("mac"):
            h = self.learn_mac(ip, r["mac"], "api")
        now = time.time()
        k = h["key"]
        for f in ("name", "friendly", "version", "model"):
            if r.get(f):
                h[f] = r[f]
        self.store.stat(k, "api", r["ok"], r.get("ms"), now)
        mode = r["mode"]
        if not probes.is_transient(mode) and mode != h.get("api_mode"):
            if h.get("api_mode"):
                self.ev(h, "api_mode", f"{h['api_mode']} -> {mode}")
            h["api_mode"] = mode
        if not r["ok"]:
            h["api_streak"] = h.get("api_streak", 0) + 1
            if h["api_streak"] == 1:
                self.ev(h, "api_fail", mode)
            h["api_last"] = mode
            self.save(h)
            return
        if h.get("api_streak"):
            self.ev(h, "api_ok", f"after {h['api_streak']} failed probes")
        h["api_streak"] = 0
        h["api_last"] = "ok"
        h["last_seen"] = now
        flashed = h.get("compiled") and r.get("compiled") and r["compiled"] != h["compiled"]
        if flashed:
            self.ev(h, "firmware", f"{h['compiled']} -> {r['compiled']} ({r.get('version')})")
        h["compiled"] = r.get("compiled")
        if "rssi" in r:
            h["rssi"] = r["rssi"]
            self.store.stat(k, "rssi", True, r["rssi"], now)
        if r.get("bssid"):
            if h.get("bssid") and r["bssid"] != h["bssid"]:
                self.ev(h, "roam", f"{h['bssid']} -> {r['bssid']}")
            h["bssid"] = r["bssid"]
        if "boot_ts" in r:
            prev = h.get("boot_ts")
            if prev and r["boot_ts"] - prev > REBOOT_SLACK:
                self.ev(h, "reboot", {"cause": "ota" if flashed else "unexpected",
                                      "prev_uptime_h": round((r["boot_ts"] - prev) / 3600, 2)}, r["boot_ts"])
            if not prev or abs(r["boot_ts"] - prev) > REBOOT_SLACK:
                h["boot_ts"] = r["boot_ts"]
        self.save(h)

    def creds(self, name):
        c = self.builder.creds_for(name)
        return {k: c.get(k) or self.fallback[k] for k in CRED_FIELDS}

    async def _api_probe(self, ip, name, prefer):
        """With the device's own key from the Device Builder. A host that has not named itself yet gets the fleet's
        keys in turn; a rejected key still names the device (noise hello), so its own key is tried next."""
        c = self.creds(name)
        keys = [c["api_key"]] if c["api_key"] else (self.builder.keys() or [None])
        r = None
        for i, psk in enumerate(keys):
            r = await probes.api_probe(ip, psk, c["api_password"], self.browser.zeroconf,
                                       prefer=prefer if i == 0 else None)
            if r["mode"] != "encrypted:key_bad":
                return r
            own = self.creds(r.get("name")) if r.get("name") and r["name"] != name else None
            if own and own["api_key"] and own["api_key"] != psk:
                return await probes.api_probe(ip, own["api_key"], own["api_password"], self.browser.zeroconf)
        if name:
            self.builder.rejected(name)
        return r

    # HTTP ---------------------------------------------------------------
    async def http_loop(self):
        await asyncio.sleep(60)
        while True:
            t0 = time.monotonic()
            for k in [k for k, h in self.hosts.items() if 80 in (h.get("ports") or []) and h.get("ip")
                      and h["ip"] not in self.exclude]:
                h = self.hosts.get(k)
                if not h:
                    continue
                c = self.creds(h.get("name") or h.get("mdns"))
                r = await probes.http_probe(h["ip"], c["web_username"], c["web_password"])
                self.store.stat(k, "http", r["ok"], r.get("ms"))
                if r["mode"] != h.get("http_mode") and not (h.get("http_mode") is None and r["mode"] == "open"):
                    self.ev(h, "http_mode", f"{h.get('http_mode')} -> {r['mode']}")
                h["http_mode"] = r["mode"]
                if r.get("title") or r.get("server"):
                    h["http_info"] = " ".join(x for x in (r.get("title"), r.get("server")) if x)
                self.save(h)
            self.store.flush()
            await asyncio.sleep(max(5, self.o["http_interval"] - (time.monotonic() - t0)))

    # mDNS ---------------------------------------------------------------
    def _mdns_seen(self, host, ips, txt):
        ips = [ip for ip in ips if ":" not in ip and ipaddress.ip_address(ip) in self.net]
        if not ips:
            return
        h = self.host_for_ip(ips[0])
        if txt.get("mac"):
            h = self.learn_mac(ips[0], txt["mac"], "mdns")
        renamed = h.get("mdns") != host
        h["mdns"] = host
        h.setdefault("name", host)
        for src, dst in (("version", "version"), ("platform", "platform"), ("board", "board")):
            if txt.get(src):
                h[dst] = txt[src]
        self.by_mdns[host] = h["key"]
        self.save(h)
        if renamed or not h.get("api_mode"):
            self.probe_soon(ips[0])

    def _mdns_gone(self, host):
        k = self.by_mdns.get(host)
        if k and k in self.hosts:
            self.ev(self.hosts[k], "mdns_goodbye")

    async def mdns_loop(self):
        await self.browser.start()
        while True:
            t0 = time.monotonic()
            for k, h in list(self.hosts.items()):
                name = h.get("mdns") or (h.get("name") if h.get("api_mode") else None)
                if name and h.get("ip") and h["ip"] not in self.exclude:
                    ms = await mdns.query(h["ip"], name)
                    # some responders only answer by multicast; a miss only means something once this
                    # host has answered a unicast query at least once
                    if ms is not None and not h.get("mdns_ok"):
                        h["mdns_ok"] = True
                        self.save(h)
                    if h.get("mdns_ok"):
                        self.store.stat(k, "mdns", ms is not None, ms)
            self.store.flush()
            await asyncio.sleep(max(10, 2 * self.o["ping_interval"] - (time.monotonic() - t0)))

    # housekeeping -------------------------------------------------------
    def clear_history(self):
        """Start the ranking over. Hosts online now keep their identity, so boot time and firmware build still detect
        changes and nothing is re-probed in a burst; the rest are forgotten and return as new if they reappear."""
        self.store.clear_history()
        now = time.time()
        kept = 0
        for k, h in list(self.hosts.items()):
            if h.get("up") and h.get("ip"):
                h.update(first_seen=now, api_streak=0)
                self.save(h)
                kept += 1
            else:
                self.store.delete_host(k)
                del self.hosts[k]
        self.by_ip = {ip: k for ip, k in self.by_ip.items() if k in self.hosts}
        self.by_mdns = {n: k for n, k in self.by_mdns.items() if k in self.hosts}
        self.misses.clear()
        return {"kept": kept}

    async def prune_loop(self):
        while True:
            self.store.prune(self.o["retention_days"])
            await asyncio.sleep(6 * 3600)

    def tasks(self):
        return [self.ping_loop(), self.sweep_loop(), self.ports_loop(), self.api_loop(),
                self.http_loop(), self.mdns_loop(), self.prune_loop(), self.builder.run()]
