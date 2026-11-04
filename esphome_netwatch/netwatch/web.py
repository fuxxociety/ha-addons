"""aiohttp UI/JSON. Under HA ingress every request comes from the Supervisor (172.30.32.2); with
host_network the port is also on the LAN, so anything else is refused."""
import json
import time
from pathlib import Path

from aiohttp import web

from .score import rank

INGRESS_PEER = "172.30.32.2"
WINDOWS = {"1h": 3600, "6h": 6 * 3600, "24h": 86400, "7d": 7 * 86400, "14d": 14 * 86400}


def make_app(mon, ingress_only):
    @web.middleware
    async def guard(request, handler):
        if ingress_only and request.remote != INGRESS_PEER:
            raise web.HTTPForbidden(text="NetWatch is only served through Home Assistant ingress")
        return await handler(request)

    def window(request):
        return WINDOWS.get(request.query.get("window", "24h"), 86400)

    async def index(request):
        return web.FileResponse(Path(__file__).with_name("index.html"))

    async def hosts(request):
        rows = rank(mon, window(request), mon.builder.devices)
        return web.json_response({"now": time.time(), "subnet": str(mon.net), "arp": mon.has_arp, "hosts": rows})

    async def events(request):
        key = request.match_info["key"]
        rows = [{"ts": ts, "ip": ip, "kind": kind, "detail": detail}
                for ts, _, ip, kind, detail in mon.store.events_since(time.time() - window(request), key)]
        return web.json_response({"key": key, "host": mon.hosts.get(key), "events": rows[:500]},
                                 dumps=lambda o: json.dumps(o, default=str))

    async def probe_now(request):
        key = request.match_info["key"]
        if key not in mon.hosts:
            raise web.HTTPNotFound()
        await mon._ports(key)
        await mon._api(key)
        return web.json_response({"host": mon.hosts.get(key)})

    app = web.Application(middlewares=[guard])
    app.add_routes([web.get("/", index), web.get("/api/hosts", hosts),
                    web.get("/api/host/{key}/events", events), web.post("/api/host/{key}/probe", probe_now)])
    return app
