"""Entry point. As an HA add-on: options from /data/options.json, DB in /data, UI on ingress :8099.
Locally: python -m netwatch --options local-options.json --data ./data  (UI on http://127.0.0.1:8099)"""
import argparse
import asyncio
import json
import logging
import signal
import sys
from pathlib import Path

from aiohttp import web

from .builder import DeviceBuilder
from .monitor import Monitor
from .store import Store
from .vendor import Vendors
from .web import make_app

log = logging.getLogger("netwatch")


def detect_subnet():
    """The directly connected network of the interface that carries the default route (Linux / HAOS host network)."""
    import ipaddress
    import socket
    import struct
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("192.0.2.1", 9))          # no packet is sent; just selects the outbound interface
        local = ipaddress.ip_address(s.getsockname()[0])
        s.close()
        with open("/proc/net/route") as f:
            next(f)
            for line in f:
                c = line.split()
                dest, gw, mask = (struct.unpack("<I", bytes.fromhex(x))[0] for x in (c[1], c[2], c[7]))
                if gw or not mask:
                    continue
                net = ipaddress.ip_network((socket.inet_ntoa(struct.pack(">I", dest)),
                                            socket.inet_ntoa(struct.pack(">I", mask))), strict=False)
                if local in net:
                    return str(net)
    except (OSError, ValueError, StopIteration):
        pass
    return None


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--options", default="/data/options.json")
    ap.add_argument("--data", default="/data")
    ap.add_argument("--bind", default=None, help="default 0.0.0.0 as add-on (ingress-only), 127.0.0.1 locally")
    ap.add_argument("--port", type=int, default=8099)
    a = ap.parse_args()
    addon = a.options == "/data/options.json"
    o = json.loads(Path(a.options).read_text(encoding="utf-8"))
    if o.get("log_events"):
        log.setLevel(logging.DEBUG)
    if not o.get("subnet"):
        o["subnet"] = detect_subnet()
        if not o["subnet"]:
            sys.exit("subnet is not set and could not be detected; set it in the add-on Configuration tab")
        log.info("subnet not configured; detected %s from the host's LAN interface", o["subnet"])
    import ipaddress
    try:
        net = ipaddress.ip_network(o["subnet"], strict=False)
    except ValueError:
        sys.exit(f"subnet {o['subnet']!r} is not a valid CIDR network")
    if net.prefixlen < 22:
        # the sweep pings every address each sweep_interval
        sys.exit(f"subnet {net} is too large to sweep (more than 1022 hosts); set a /22 or smaller in Configuration")
    Path(a.data).mkdir(parents=True, exist_ok=True)
    store = Store(str(Path(a.data) / "netwatch.db"))
    mon = Monitor(o, store, DeviceBuilder(o))
    mon.vendors = Vendors(a.data)
    runner = web.AppRunner(make_app(mon, ingress_only=addon))
    await runner.setup()
    await web.TCPSite(runner, a.bind or ("0.0.0.0" if addon else "127.0.0.1"), a.port).start()
    log.info("watching %s, %d known hosts", o["subnet"], len(mon.hosts))
    tasks = [asyncio.ensure_future(t) for t in mon.tasks() + [mon.vendors.run()]]
    stop = asyncio.Event()
    if hasattr(signal, "SIGTERM") and sys.platform != "win32":
        # the Supervisor stops add-ons with SIGTERM: flush buffered stats and exit 0 instead of dying mid-write
        asyncio.get_running_loop().add_signal_handler(signal.SIGTERM, stop.set)
    stopper = asyncio.ensure_future(stop.wait())
    done, _ = await asyncio.wait(tasks + [stopper], return_when=asyncio.FIRST_COMPLETED)
    for t in tasks:
        t.cancel()
    store.flush()
    await runner.cleanup()
    for t in done:
        if t is not stopper:
            t.result()      # surface the crash; the watchdog restarts the add-on
    log.info("stopped")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s", datefmt="%H:%M:%S")
    # failed probes are recorded as events; the library's per-failure warnings would flood the add-on log
    logging.getLogger("aioesphomeapi").setLevel(logging.ERROR)
    logging.getLogger("aiohttp.access").setLevel(logging.WARNING)
    asyncio.run(main())
