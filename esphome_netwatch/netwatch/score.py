"""Rank hosts by accumulated trouble.

Meant for a monitor that runs for weeks: a single blip barely registers, but blips that keep happening add up.
  * every event has a weight; outages weigh 1 + log2(1 + minutes down), so short ones count little each
  * weights decay with age (HALF_LIFE): what happened this week outranks last week
  * the sum is divided by the (decayed) time the host has been observed -> "trouble per day",
    so a host seen for an hour is not compared raw against one seen for a fortnight
  * steady-state rates (ping loss, API failures, weak RSSI) add on top

The split that matters for hardware hunting:
  drop + reboot   -> lost power or crashed (brown-out, failing regulator/capacitor, watchdog)
  drop, no reboot -> stayed up but fell off Wi-Fi (RF, AP, roaming, DHCP)

A firmware update is maintenance, not a fault: the reboot and what it causes around that moment (a short outage,
a failed API probe, an mDNS goodbye, a roam) neither score nor count as drops.
"""
import json
import math
import time

HALF_LIFE = 3 * 86400
MIN_OBS = 86400                 # a new host is scored as if seen for at least a day
W = {"reboot": 8.0, "ip_change": 2.0, "ip_reassigned": 2.0, "api_fail": 0.5, "mdns_goodbye": 0.25, "roam": 0.25}
OTA_PRE = 300                   # an upload can stall the device this long before it reboots
OTA_POST = 300                  # ... and it can take this long to rejoin
OTA_MAX_OUTAGE = 600            # longer than this is a failed flash or a dead device: it counts
# sightings that prove a host is back; 'reboot' is not one, its timestamp is the boot time, not when it was seen
ALIVE = ("new", "mac_learned", "ip_change", "api_ok", "firmware", "roam")


def _num(d, k):
    try:
        return json.loads(d).get(k) if d and d.startswith("{") else None
    except ValueError:
        return None


def _outages(e, h, now):
    """[(start, end)] from events in time order. An 'up' closes an outage; for one recorded without an 'up' (a host
    that came back on a new IP) the next sighting does. Still open and the host is down: it runs until now."""
    out, start = [], None
    for ts, k, d in e:
        if k == "down":
            if start is not None:
                out.append((start, ts))
            start = ts
        elif k == "up":
            begin = ts - (_num(d, "duration") or 0)
            if start is None and out and abs(out[-1][0] - begin) <= 120:
                out.pop()                       # a sighting closed it first; the 'up' is exact
            out.append((begin, ts))
            start = None
        elif k in ALIVE and start is not None:
            out.append((start, ts))
            start = None
    if start is not None:
        out.append((start, now if not h.get("up") else max(start, h.get("last_seen") or start)))
    elif not h.get("up") and h.get("down_since"):
        out.append((h["down_since"], now))      # went down before the window
    return out


def _online_loss(sent, ok, offline, interval):
    """Ping loss while the host was meant to be reachable. Outages score as outages; counting their missed pings
    as loss too would rate a repaired device as lossy for the whole window."""
    missed = sent - ok
    gone = min(missed, offline / interval)
    return round(100 * (missed - gone) / (sent - gone), 1) if sent - gone >= 20 else None


def hw_class(inv, h):
    """Hardware class: the config's `esphome: comment:`, else the board / platform the device or the Device Builder
    reports."""
    return inv.get("comment") or h.get("model") or inv.get("target_platform") or h.get("platform") or ""


def _decay(age):
    return 0.5 ** (max(0.0, age) / HALF_LIFE)


def _obs_days(span):
    """Decayed observation time in days: integral of _decay over the span."""
    span = max(span, MIN_OBS)
    return HALF_LIFE / math.log(2) * (1 - _decay(span)) / 86400


def rank(mon, window, configured):
    """configured: the Device Builder's devices by name (builder.py)."""
    now = time.time()
    since = now - window
    stats = {}
    for key, probe, sent, ok, vsum, vn in mon.store.stats_since(since):
        stats.setdefault(key, {})[probe] = (sent, ok, vsum, vn)
    evs = {}
    for ts, key, ip, kind, detail in mon.store.events_since(since):
        evs.setdefault(key, []).append((ts, kind, detail))
    vendor = getattr(mon, "vendors", None)
    vendor = vendor.lookup if vendor else (lambda mac: "")
    slack = mon.o["ping_interval"] * (mon.o["outage_misses"] + 1) + 90
    by_name = {n.lower(): d for n, d in configured.items()}
    by_mac = {d["mac"]: d for d in configured.values() if d.get("mac")}
    matched = set()

    def lookup(h):
        """What the device says it is wins: a swapped chip keeps its name, not its MAC. MAC only for hosts that
        have not named themselves (no API / mDNS answer yet)."""
        reported = h.get("name") or h.get("mdns")
        if reported:
            return by_name.get(reported.lower(), {})
        return by_mac.get(h.get("mac") or "", {})

    rows = []
    for key, h in mon.hosts.items():
        s, e = stats.get(key, {}), evs.get(key, [])
        inv = lookup(h)
        if inv:
            matched.add(inv["name"])

        def pct_fail(p, min_sent=1):
            sent, ok = s.get(p, (0, 0, 0, 0))[:2]
            return round(100 * (sent - ok) / sent, 1) if sent >= min_sent else None

        def avg(p):
            v = s.get(p)
            return round(v[2] / v[3], 1) if v and v[3] else None

        flashes = [ts for ts, k, d in e if k == "reboot" and _num(d, "cause") == "ota"]
        reboots = [ts for ts, k, d in e if k == "reboot" and _num(d, "cause") != "ota"]

        def ota_caused(t, lag=0):
            return any(b - OTA_PRE <= t <= b + OTA_POST + lag for b in flashes)

        outages = _outages(e, h, now)
        faults = [(a, b) for a, b in outages
                  if not (ota_caused(a) and b - a <= OTA_MAX_OUTAGE and (h.get("up") or b < now))]
        downtime = sum(b - max(a, since) for a, b in faults)
        drops_reboot = sum(1 for a, b in faults if any(a - slack <= r <= b + slack for r in reboots))
        drops_wifi = len(faults) - drops_reboot

        # a roam is only noticed at the next API probe, so it can trail the flash by a whole interval
        lag = {"roam": mon.o["api_interval"]}
        trouble = sum(W[k] * _decay(now - ts) for ts, k, d in e if k in W and not (
            _num(d, "cause") == "ota" or (k != "reboot" and ota_caused(ts, lag.get(k, 0)))))
        trouble += sum((1 + math.log2(1 + (b - a) / 60)) * _decay(now - b) for a, b in faults)
        days = _obs_days(now - max(h.get("first_seen") or now, since))

        rssi = avg("rssi")
        offline = sum(b - max(a, since) for a, b in outages)
        ping_loss = _online_loss(*s.get("ping", (0, 0))[:2], offline, mon.o["ping_interval"])
        api_fail = pct_fail("api", 3)
        mdns_fail = pct_fail("mdns", 10) if h.get("mdns_ok") else None
        score = (trouble / days + 0.5 * (ping_loss or 0) + 0.1 * (api_fail or 0) + 0.05 * (mdns_fail or 0)
                 + (0.5 * max(0, -75 - rssi) if rssi is not None else 0))

        mode = h.get("api_mode") or ""
        if not h.get("up"):
            verdict = "offline"
        elif mode.endswith(("key_bad", "password_bad", "no_key", "password_required")):
            verdict = "API credentials rejected"
        elif reboots and len(reboots) >= drops_wifi:
            verdict = "reboots: power / crash"
        elif drops_wifi:
            verdict = "Wi-Fi drops, no reboot"
        elif (api_fail or 0) > 20 and (ping_loss or 0) < 5:
            verdict = "pings fine, API failing"
        elif rssi is not None and rssi < -78:
            verdict = "weak signal"
        elif (ping_loss or 0) > 2:
            verdict = "packet loss"
        else:
            verdict = "ok"
        rows.append({
            "key": key, "mac": h.get("mac"), "ip": h.get("ip"), "vendor": vendor(h.get("mac")),
            "name": h.get("friendly") or inv.get("friendly_name") or h.get("name") or h.get("http_info") or "",
            "hostname": h.get("name") or h.get("mdns") or inv.get("name") or "",
            "class": hw_class(inv, h), "area": inv.get("area") or "", "version": h.get("version") or "",
            "ports": h.get("ports") or [], "api_mode": mode, "api_last": h.get("api_last") or "",
            "http_mode": h.get("http_mode") or "", "bssid": h.get("bssid") or "",
            "up": bool(h.get("up")), "last_seen": h.get("last_seen"), "boot_ts": h.get("boot_ts"),
            "observed_days": round((now - max(h.get("first_seen") or now, since)) / 86400, 1),
            "score": round(score, 1), "verdict": verdict,
            "ping_loss": ping_loss, "ping_ms": avg("ping"), "arp_fail": pct_fail("arp", 20),
            "api_fail": api_fail, "mdns_fail": mdns_fail, "http_fail": pct_fail("http", 3),
            "drops": len(faults), "drops_reboot": drops_reboot, "drops_wifi": drops_wifi,
            "reboots": len(reboots), "ota": len(flashes), "downtime_min": round(downtime / 60, 1),
            "ip_changes": sum(1 for _, k, _ in e if k in ("ip_change", "ip_reassigned")),
            "roams": sum(1 for _, k, _ in e if k == "roam"),
            "mdns_goodbyes": sum(1 for _, k, _ in e if k == "mdns_goodbye"), "rssi": rssi,
        })
    for name, inv in configured.items():
        if name not in matched:
            mac = inv.get("mac")
            rows.append({"key": mac or f"name:{name}", "mac": mac, "ip": None, "vendor": vendor(mac) if mac else "",
                         "name": inv.get("friendly_name") or "", "hostname": name, "class": hw_class(inv, {}),
                         "area": inv.get("area") or "", "up": False, "score": 0, "verdict": "never seen", "ports": []})
    rows.sort(key=lambda r: (-r["score"], r["verdict"] == "never seen", r["ip"] or ""))
    return rows
