"""Stateless probes: ping, ARP table, TCP ports, HTTP, ESPHome native API."""
import asyncio
import ipaddress
import re
import socket
import struct
import sys
import time
import urllib.error
import urllib.request

WIN = sys.platform == "win32"
PORTS = (6053, 80, 8266, 3232, 6668, 443)   # API, web, ESP8266 OTA, ESP32 OTA, Tuya stock, https


def norm_mac(mac):
    h = re.sub(r"[^0-9a-f]", "", (mac or "").lower())
    return ":".join(h[i:i + 2] for i in range(0, 12, 2)) if len(h) == 12 else None


# ping ------------------------------------------------------------------
async def ping(ip, timeout=1.0):
    """Round-trip ms, or None on no reply."""
    args = (["ping", "-n", "1", "-w", str(int(timeout * 1000)), ip] if WIN
            else ["ping", "-c", "1", "-W", str(max(1, int(timeout))), "-n", ip])
    p = await asyncio.create_subprocess_exec(*args, stdout=asyncio.subprocess.PIPE,
                                             stderr=asyncio.subprocess.DEVNULL)
    out = (await p.communicate())[0].decode(errors="replace")
    if (WIN and "TTL=" not in out) or (not WIN and p.returncode != 0):
        return None
    m = re.search(r"time[=<]([\d.]+)\s*ms", out)
    return float(m[1]) if m else 0.0


# ARP -------------------------------------------------------------------
def _linux_onlink(net):
    try:
        with open("/proc/net/route") as f:
            next(f)
            for line in f:
                c = line.split()
                dest, gw, mask = (struct.unpack("<I", bytes.fromhex(x))[0] for x in (c[1], c[2], c[7]))
                route = ipaddress.ip_network((socket.inet_ntoa(struct.pack(">I", dest)),
                                              socket.inet_ntoa(struct.pack(">I", mask))), strict=False)
                if gw == 0 and route.prefixlen > 0 and net.subnet_of(route):
                    return True
    except (OSError, ValueError, StopIteration):
        pass
    return False


async def arp_table(net):
    """{ip: mac or 'incomplete'} for the subnet, or None when this host has no interface on it
    (ARP only sees the local segment; across a router every IP would show the router's MAC)."""
    out = {}
    if WIN:
        p = await asyncio.create_subprocess_exec("arp", "-a", stdout=asyncio.subprocess.PIPE)
        txt = (await p.communicate())[0].decode(errors="replace")
        onlink, any_onlink = False, False
        for line in txt.splitlines():
            m = re.match(r"Interface:\s+([\d.]+)", line)
            if m:
                onlink = ipaddress.ip_address(m[1]) in net
                any_onlink |= onlink
                continue
            m = re.match(r"\s+([\d.]+)\s+([0-9a-f-]{17})\s+dynamic", line, re.I)
            if onlink and m and ipaddress.ip_address(m[1]) in net:
                out[m[1]] = norm_mac(m[2])
        return out if any_onlink else None
    if not _linux_onlink(net):
        return None
    try:
        with open("/proc/net/arp") as f:
            next(f)
            for line in f:
                ip, _hw, flags, mac = line.split()[:4]
                if ipaddress.ip_address(ip) in net:
                    out[ip] = norm_mac(mac) if int(flags, 16) & 2 else "incomplete"
    except OSError:
        return None
    return out


# TCP ports -------------------------------------------------------------
async def tcp_open(ip, port, timeout=1.5):
    try:
        _, w = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout)
        w.close()
        return "open"
    except ConnectionRefusedError:
        return "refused"
    except (asyncio.TimeoutError, OSError):
        return "timeout"


async def port_scan(ip):
    res = await asyncio.gather(*(tcp_open(ip, p) for p in PORTS))
    return [p for p, r in zip(PORTS, res) if r == "open"]


# HTTP ------------------------------------------------------------------
def _http_get(url, user, pw, timeout):
    handlers = []
    if user is not None:
        mgr = urllib.request.HTTPPasswordMgrWithDefaultRealm()
        mgr.add_password(None, url, user, pw or "")
        handlers = [urllib.request.HTTPBasicAuthHandler(mgr), urllib.request.HTTPDigestAuthHandler(mgr)]
    opener = urllib.request.build_opener(*handlers)
    try:
        with opener.open(url, timeout=timeout) as r:
            return r.status, r.headers.get("Server", ""), r.read(4096).decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.headers.get("Server", ""), ""


async def http_probe(ip, user, pw, timeout=5):
    """mode: open | auth_ok | auth_bad | auth_required (no creds configured) | http_<code> | error:<x>"""
    url = f"http://{ip}/"
    loop = asyncio.get_running_loop()
    t0 = time.monotonic()
    try:
        code, server, body = await loop.run_in_executor(None, _http_get, url, None, None, timeout)
        if code == 401:
            if not user:
                mode = "auth_required"
            else:
                code, server, body = await loop.run_in_executor(None, _http_get, url, user, pw, timeout)
                mode = "auth_ok" if code < 400 else "auth_bad"
        else:
            mode = "open" if code < 400 else f"http_{code}"
    except Exception as e:  # noqa: BLE001 - every failure is a data point
        return {"ok": False, "mode": f"error:{type(e).__name__}", "ms": None}
    title = re.search(r"<title>(.*?)</title>", body, re.I | re.S)
    return {"ok": True, "mode": mode, "ms": (time.monotonic() - t0) * 1000, "server": server,
            "title": title[1].strip()[:60] if title else ""}


# ESPHome native API ----------------------------------------------------
async def _api_session(ip, password, psk, zc, timeout):
    from aioesphomeapi import APIClient, SensorInfo, TextSensorInfo
    c = APIClient(ip, 6053, password, noise_psk=psk, client_info="netwatch", zeroconf_instance=zc)
    t0 = time.monotonic()
    try:
        await asyncio.wait_for(c.connect(login=True), timeout)
        ms = (time.monotonic() - t0) * 1000
        info = await asyncio.wait_for(c.device_info(), timeout)
        ents, _ = await asyncio.wait_for(c.list_entities_services(), timeout)
        want = {}
        for e in ents:
            n = (e.name or e.object_id or "").lower()
            if isinstance(e, SensorInfo) and "uptime" in n:
                want[e.key] = ("uptime", getattr(e, "device_class", "") == "timestamp")
            elif isinstance(e, SensorInfo) and (e.unit_of_measurement or "") == "dBm":
                want[e.key] = ("rssi", False)
            elif isinstance(e, TextSensorInfo) and "bssid" in n:
                want[e.key] = ("bssid", False)
        got = {}
        done = asyncio.Event()

        def on_state(s):
            if s.key in want and not getattr(s, "missing_state", False):
                field, is_ts = want[s.key]
                got[field] = (s.state, is_ts)
                if len(got) == len(want):
                    done.set()

        c.subscribe_states(on_state)
        try:
            await asyncio.wait_for(done.wait(), 4)
        except asyncio.TimeoutError:
            pass
        r = {"ms": ms, "name": info.name, "friendly": info.friendly_name, "mac": norm_mac(info.mac_address),
             "version": info.esphome_version, "model": info.model, "compiled": info.compilation_time}
        if "uptime" in got:
            v, is_ts = got["uptime"]
            if isinstance(v, (int, float)) and v == v:
                r["boot_ts"] = float(v) if (is_ts or v > 1e9) else time.time() - float(v)
        if "rssi" in got and got["rssi"][0] == got["rssi"][0]:
            r["rssi"] = float(got["rssi"][0])
        if "bssid" in got:
            r["bssid"] = str(got["bssid"][0])
        return r
    finally:
        try:
            await asyncio.wait_for(c.disconnect(), 5)
        except Exception:  # noqa: BLE001
            pass


async def api_probe(ip, psk, password, zc=None, prefer=None, timeout=12):
    """One device, as few sessions as possible. Returns dict with 'mode' among:
      encrypted:key_ok | encrypted:key_bad | encrypted:no_key
      plaintext:open | plaintext:password_ok | plaintext:password_bad | plaintext:password_required
      closed (6053 refused) | unreachable (6053 timeout) | handshake_fail | timeout | error:<x>
    plus 'ok' (a full session completed) and the device data on success."""
    from aioesphomeapi import (EncryptionPlaintextAPIError, InvalidAuthAPIError, InvalidEncryptionKeyAPIError,
                               RequiresEncryptionAPIError, HandshakeAPIError)
    port = await tcp_open(ip, 6053, 3)
    if port != "open":
        return {"ok": False, "mode": "closed" if port == "refused" else "unreachable"}

    ident = {}

    async def attempt(pw, key):
        try:
            return "ok", await _api_session(ip, pw, key, zc, timeout)
        except InvalidEncryptionKeyAPIError as e:
            # the noise hello still names the device: identity without a working key
            if norm_mac(getattr(e, "received_mac", None)):
                ident.update(mac=norm_mac(e.received_mac), name=getattr(e, "received_name", None))
            return "key_bad", None
        except RequiresEncryptionAPIError:
            return "needs_key", None
        except EncryptionPlaintextAPIError:
            return "plaintext", None
        except InvalidAuthAPIError:
            return "pw_bad", None
        except HandshakeAPIError as e:
            return f"handshake:{type(e).__name__}", None
        except asyncio.TimeoutError:
            return "timeout", None
        except Exception as e:  # noqa: BLE001
            return f"error:{type(e).__name__}", None

    def done(mode, data):
        return {"ok": data is not None, "mode": mode, **(data or ident)}

    def transport(res):
        """timeout / handshake / other errors say nothing about credentials"""
        if res == "timeout" or res.startswith("error:"):
            return res
        if res.startswith("handshake:"):
            return "handshake_fail"
        return None

    # fast path: re-use the last working mode, so a healthy device costs one session per probe
    creds = {"encrypted:key_ok": (None, psk), "plaintext:open": (None, None),
             "plaintext:password_ok": (password, None)}.get(prefer)
    if creds and (creds[1] or prefer != "encrypted:key_ok"):
        res, d = await attempt(*creds)
        if res == "ok":
            return done(prefer, d)
        if transport(res):
            return done(transport(res), None)
        # credentials outcome changed (reflashed / key rotated): classify from scratch

    if psk:
        res, d = await attempt(None, psk)
        if res == "ok":
            return done("encrypted:key_ok", d)
        if res == "key_bad":
            return done("encrypted:key_bad", None)
        if res != "plaintext":
            return done(transport(res) or res, None)
    res, d = await attempt(None, None)
    if res == "ok":
        return done("plaintext:open", d)
    if res == "needs_key":
        return done("encrypted:no_key", None)
    if res != "pw_bad":
        return done(transport(res) or res, None)
    if not password:
        return done("plaintext:password_required", None)
    res, d = await attempt(password, None)
    if res == "ok":
        return done("plaintext:password_ok", d)
    return done("plaintext:password_bad" if res == "pw_bad" else transport(res) or res, None)


TRANSIENT = ("timeout", "handshake_fail", "unreachable")


def is_transient(mode):
    return mode in TRANSIENT or mode.startswith("error:")
