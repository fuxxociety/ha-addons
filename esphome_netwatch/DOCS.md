# ESPHome NetWatch

NetWatch runs in the background. It watches every host on your IoT subnet, keyed by MAC address, and ranks them by
how much connectivity trouble they cause over time. Open it from the **NetWatch** panel in the sidebar.

## What it measures

| Probe | Default cadence | What it tells you |
|---|---|---|
| ICMP ping | every 30 s, known hosts | loss, latency, outages (`outage_misses` misses in a row = down) |
| Ping sweep + ARP | every 5 min, whole subnet | new hosts, hosts that answer ARP but not ICMP |
| ARP state at each drop | with each ping | `incomplete` = off Wi-Fi or unpowered; `complete` = associated but not answering (hung stack, or the AP is dropping traffic) |
| TCP ports | on discovery (then an immediate API probe), on a MAC/IP change, then hourly | 6053 ESPHome API, 80 web, 8266/3232 OTA, 6668 stock Tuya, 443 |
| mDNS | passive browser, plus a unicast query every 2 × ping interval | discovery, MAC from TXT, goodbyes, mDNS responsiveness |
| HTTP `GET /` | every 15 min, hosts with port 80 open | `open`, `auth_ok`, `auth_bad`, `auth_required`, errors |
| ESPHome native API | every 10 min, spread out; at most 3 at once and never 2 on one device | credential mode, uptime (**reboots**), RSSI, BSSID (**roams**), firmware changes |

**API modes:**
- `encrypted:key_ok`
- `encrypted:key_bad`: the device's name and MAC are still learned from the handshake
- `encrypted:no_key`
- `plaintext:open`
- `plaintext:password_ok`
- `plaintext:password_bad`
- `plaintext:password_required`
- `closed`
- `unreachable`

After a device's first full classification, each probe makes a single session in the mode that worked. NetWatch
classifies the device again only when the credentials outcome changes.

## Reading the ranking

**Trouble/day** is the column to sort by:
- Each event has a weight. An outage weighs 1 + log2(1 + minutes down), so short blips count little each but add
  up when they keep happening.
- Weights fade with a 3-day half-life.
- The total is divided by how long the device has been observed, so a device first seen an hour ago compares fairly
  with one watched for two weeks.
- Steady ping loss, API failures and weak RSSI add on top. **Ping loss %** covers only the time a device was meant to
  be reachable; time offline counts as an outage instead.

**Firmware updates don't count against a device.** NetWatch recognises a flash from the changed build time. That
reboot, and a short outage, failed API probe, mDNS goodbye or roam around it, neither score nor appear as drops; the
**OTA** column counts the flashes instead. An outage over 10 minutes still counts: that is a failed flash or a dead
device, not maintenance.

The **Verdict** column separates **drops with a reboot** (power or crash: brown-out, failing regulator or capacitor,
watchdog) from **drops without a reboot** (Wi-Fi: RF, AP, roaming, DHCP). Two summary tables follow the ranking:
- **By hardware class:** totals per class, so a weakness shared by one board type stands out. The class is the
  device config's `esphome: comment:`, else its board or platform. To group by hardware type, give every config of
  one type the same comment.
- **By access point:** totals per BSSID, so trouble that follows one radio stands out.

Click a row to see that device's events and to run **Probe now**.

## Where device data comes from

Nothing is read from files. NetWatch asks the **ESPHome Device Builder** add-on, over the same API Home Assistant's
ESPHome integration uses:
- `/devices`: every configured device, with its name, friendly name, comment (the class), area and MAC. Configured
  devices that never answer show as **never seen**.
- `/json-config`: each device's own API encryption key (or API password) and web-server login.

The Supervisor provides the add-on's ingress port. The Device Builder answers on `127.0.0.1:<port>`, only to loopback
and the Supervisor, so no extra port or login is needed. The list is refreshed every `builder_interval`, and at once
for a device that rejects its key (reflashed with a new one).

A device is matched by the name it reports (API or mDNS), not its MAC, so a replacement chip needs no edit anywhere.

## Configuration

| Option | Default | |
|---|---|---|
| `subnet` | blank | CIDR to watch. Blank uses the host's own LAN subnet. |
| `esphome_addon` | `5c53de3b_esphome` | slug of the ESPHome add-on, as in its page URL |
| `esphome_url` | – | a Device Builder URL instead of the add-on (local runs) |
| `builder_interval` | 900 s | how often the device list is refreshed |
| `api_key`, `api_password`, `web_username`, `web_password` | – | only for devices the Device Builder does not know |
| `ping_interval`, `sweep_interval`, `api_interval`, `http_interval` | 30, 300, 600, 900 s | probe cadences |
| `outage_misses` | 3 | consecutive missed pings that count as an outage |
| `retention_days` | 14 | history kept in `/data/netwatch.db` |
| `log_events` | false | also write every event to the add-on log |
| `exclude` | [] | IPs never to probe |

The add-on never logs or stores secret values: credentials stay in memory, and the log only shows how many devices it
has credentials for.

## Networking

The add-on uses the host network. ARP and passive mDNS therefore need the HA host to have an interface on the watched
subnet. If it doesn't, the log says so and MAC addresses come from mDNS and the API only. The UI is served only through
Home Assistant ingress: the port refuses requests from anything except the Supervisor.

## Local development

```
cd esphome_netwatch
python -m venv .venv && .venv/Scripts/pip install -r requirements.txt
.venv/Scripts/python -m netwatch --options local-options.json --data ./data
```

`local-options.json` uses the same keys as the add-on options. Set `subnet`, since it isn't detected on Windows, and
`esphome_url` to a local Device Builder (`pip install esphome-device-builder`, then
`esphome-device-builder --ha-addon --ingress-port 18099 --ingress-host 127.0.0.1 <config dir>` gives the same
no-auth loopback site as the add-on: `"esphome_url": "http://127.0.0.1:18099"`). The UI is at http://127.0.0.1:8099.
