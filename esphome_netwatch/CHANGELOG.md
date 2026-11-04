# Changelog

## 0.2.0
- **No more files as a source.** Devices, names, classes, areas and each device's own API key / password and web
  login now come from the ESPHome Device Builder add-on's API (`/devices`, `/json-config`), the same source Home
  Assistant's ESPHome integration uses, found through the Supervisor. The `/config` mapping and the `secrets_path`,
  `inventory_path` and `secret_*` options are gone (left-over values are ignored). New options: `esphome_addon`,
  `esphome_url`, `builder_interval`.
- Devices are matched by the name they report (API / mDNS), not their MAC: a replacement chip needs no edit anywhere.
  A device that rejects its key triggers a fresh fetch of its config.
- New devices show up within seconds: any host first seen by ping, ARP or mDNS, or answering on an IP with a new
  MAC (replacement chip, DHCP reshuffle), gets a port scan and an API probe right away. Before, a host first found by
  mDNS waited for the hourly port pass, and stayed hidden by the "ESPHome only" filter until then.
- Area column; the class is the config's `esphome: comment:`.

## 0.1.1
- First release in the add-on repository.
- If `subnet` is left blank, it is detected from the host's LAN interface.
- A stop (SIGTERM) now flushes the buffered stats and exits cleanly.
- Vendor column (IEEE OUI lookup), sorting IPs by value, MAC addresses in monospace capitals, and fixed decimals for ping ms and RSSI.

## 0.1.0
- Initial version, installed as a local add-on.
