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
"""
import json
import math
import time

HALF_LIFE = 3 * 86400
MIN_OBS = 86400                 # a new host is scored as if seen for at least a day
W = {"reboot": 8.0, "ip_change": 2.0, "ip_reassigned": 2.0, "api_fail": 0.5, "mdns_goodbye": 0.25, "roam": 0.25}


def _num(d, k):
    try:
        return json.loads(d).get(k) if d and d.startswith("{") else None
    except ValueError:
        return None


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

        downs = [ts for ts, k, _ in e if k == "down"]
        reboots = [ts for ts, k, d in e if k == "reboot" and _num(d, "cause") != "ota"]
        ups = [(ts, _num(d, "duration") or 0) for ts, k, d in e if k == "up"]
        if not h.get("up") and h.get("down_since"):
            ups.append((now, now - max(h["down_since"], since)))     # ongoing outage
        downtime = sum(d for _, d in ups)
        drops_reboot = sum(1 for d in downs if any(d - slack <= r <= d + slack * 4 for r in reboots))
        drops_wifi = len(downs) - drops_reboot

        trouble = sum(w * _decay(now - ts) for ts, k, _ in e for kind, w in W.items() if k == kind) \
            - sum(W["reboot"] * _decay(now - ts) for ts, k, d in e if k == "reboot" and _num(d, "cause") == "ota")
        trouble += sum((1 + math.log2(1 + dur / 60)) * _decay(now - ts) for ts, dur in ups)
        days = _obs_days(now - max(h.get("first_seen") or now, since))

        rssi = avg("rssi")
        ping_loss = pct_fail("ping", 20)
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
            "drops": len(downs), "drops_reboot": drops_reboot, "drops_wifi": drops_wifi,
            "reboots": len(reboots), "downtime_min": round(downtime / 60, 1),
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
