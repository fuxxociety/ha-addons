"""mDNS: a passive browser for _esphomelib._tcp (discovery, TXT mac, goodbyes) and an active,
cache-free liveness query sent unicast to the device's IP:5353 (works across routed subnets too)."""
import asyncio
import socket
import time

from zeroconf import DNSIncoming, DNSOutgoing, DNSQuestion, ServiceStateChange, const
from zeroconf.asyncio import AsyncServiceBrowser, AsyncServiceInfo, AsyncZeroconf

ESPHOME = "_esphomelib._tcp.local."


class _Reply(asyncio.DatagramProtocol):
    def __init__(self, fut):
        self.fut = fut

    def datagram_received(self, data, addr):
        try:
            msg = DNSIncoming(data)
        except Exception:  # noqa: BLE001
            return
        if not self.fut.done() and any(a.type == const._TYPE_A for a in msg.answers()):
            self.fut.set_result(addr[0])


async def query(ip, hostname, timeout=2.0):
    """ms until the device answers an A query for <hostname>.local, or None."""
    out = DNSOutgoing(const._FLAGS_QR_QUERY)
    out.add_question(DNSQuestion(f"{hostname}.local.", const._TYPE_A, const._CLASS_IN))
    loop = asyncio.get_running_loop()
    fut = loop.create_future()
    tr, _ = await loop.create_datagram_endpoint(lambda: _Reply(fut), family=socket.AF_INET, local_addr=("0.0.0.0", 0))
    try:
        t0 = time.monotonic()
        tr.sendto(out.packets()[0], (ip, 5353))
        await asyncio.wait_for(fut, timeout)
        return (time.monotonic() - t0) * 1000
    except asyncio.TimeoutError:
        return None
    finally:
        tr.close()


class Browser:
    """Calls on_seen(hostname, [ips], txt) and on_gone(hostname)."""

    def __init__(self, on_seen, on_gone):
        self.on_seen, self.on_gone = on_seen, on_gone
        self.azc = None

    async def start(self):
        self.azc = AsyncZeroconf()
        self.browser = AsyncServiceBrowser(self.azc.zeroconf, [ESPHOME], handlers=[self._changed])

    @property
    def zeroconf(self):
        return self.azc.zeroconf if self.azc else None

    def _changed(self, zeroconf, service_type, name, state_change):
        asyncio.ensure_future(self._handle(name, state_change))

    async def _handle(self, name, change):
        host = name.split(".")[0]
        if change is ServiceStateChange.Removed:
            self.on_gone(host)
            return
        info = AsyncServiceInfo(ESPHOME, name)
        if await info.async_request(self.azc.zeroconf, 3000):
            txt = {k.decode(errors="replace"): (v or b"").decode(errors="replace") for k, v in info.properties.items()}
            self.on_seen(host, info.parsed_addresses(), txt)

    async def close(self):
        if self.azc:
            await self.browser.async_cancel()
            await self.azc.async_close()
