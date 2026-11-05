# Changelog

## 0.2.2
- **Clear history** button: starts the ranking over, for example after repair work. Online hosts keep their identity
  and offline hosts are forgotten. The erased data can't be recovered.

## 0.2.1
- Firmware updates no longer count against a device. The short outage, failed API probe, mDNS goodbye and roam around
  a flash are ignored, and a new OTA column counts flashes. An outage over 10 minutes still counts.
- Ping loss now covers only the time a device was meant to be reachable. Outages were counted twice, as an outage and
  as loss, and the loss never faded within the window.
- A long outage that ends in a reboot now counts as a drop with a reboot, not a Wi-Fi drop.
- An outage now ends when a host returns on a new IP. It used to stay open, which understated downtime.
- All four apply to the stored history as well as new data.

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
