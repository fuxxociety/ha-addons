# ESPHome NetWatch

NetWatch runs in the background. It watches every host on your IoT subnet, keyed by MAC address, and ranks them by
how much connectivity trouble they cause over time. Open it from the **NetWatch** panel in the sidebar.

## What it measures

| Probe | Default cadence | What it tells you |
|---|---|---|
| ICMP ping | every 30 s, known hosts | loss, latency, outages (`outage_misses` misses in a row = down) |
| Ping sweep + ARP | every 5 min, whole subnet | new hosts, hosts that answer ARP but not ICMP |
| ARP state at each drop | with each ping | `incomplete` = off Wi-Fi or unpowered; `complete` = associated but not answering (hung stack, or the AP is dropping traffic) |
| TCP ports | on discovery, then hourly | 6053 ESPHome API, 80 web, 8266/3232 OTA, 6668 stock Tuya, 443 |
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
- Steady ping loss, API failures and weak RSSI add on top.

The **Verdict** column separates **drops with a reboot** (power or crash: brown-out, failing regulator or capacitor,
watchdog) from **drops without a reboot** (Wi-Fi: RF, AP, roaming, DHCP). Two summary tables follow the ranking:
- **By hardware class:** totals per `class` from your inventory file, so a weakness shared by one board type stands out.
- **By access point:** totals per BSSID, so trouble that follows one radio stands out.

Click a row to see that device's events and to run **Probe now**.

## Configuration

| Option | Default | |
|---|---|---|
| `subnet` | blank | CIDR to watch. Blank uses the host's own LAN subnet. |
| `secrets_path` | `/homeassistant/esphome/secrets.yaml` | ESPHome `secrets.yaml` to read credentials from (`/homeassistant` = your HA `/config`) |
| `inventory_path` | `/homeassistant/esphome/naming/naming.yaml` | optional; YAML with `devices: [{mac, friendly_name, new_hostname, class, live}]`, used for names, the class table and "never seen" rows |
| `secret_api_key`, `secret_api_password`, `secret_web_username`, `secret_web_password` | `api_enc_key`, … | key names to look up in `secrets.yaml` |
| `api_key`, `api_password`, `web_username`, `web_password` | – | explicit values; these override `secrets.yaml` |
| `ping_interval`, `sweep_interval`, `api_interval`, `http_interval` | 30, 300, 600, 900 s | probe cadences |
| `outage_misses` | 3 | consecutive missed pings that count as an outage |
| `retention_days` | 14 | history kept in `/data/netwatch.db` |
| `log_events` | false | also write every event to the add-on log |
| `exclude` | [] | IPs never to probe |

The add-on never logs secret values: at start-up the log only shows each credential as `set` or `none`.

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

`local-options.json` uses the same keys as the add-on options; set `subnet`, since it isn't detected on Windows. The UI is
at http://127.0.0.1:8099.
