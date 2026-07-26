# Smart-G4 Builder

A Home Assistant **ingress add-on** for programming and monitoring your
Smart-G4 (S-BUS) system — modelled on the new ESPHome Device Builder. It opens
as a panel in the HA sidebar (no separate login, proxied through HA).

## What it does

- **Device grid** — every module discovered on the bus as a card (dimmers,
  relays, DDP panels, sensors, HVAC, Z-Audio), with online status, firmware,
  address, and channel/button counts. A "Take control" banner adopts newly
  found, un-named modules (like ESPHome's adopt flow).
- **DDP button programmer** — click *Program* on a panel to see its real
  configuration, decoded from a flash backup: 16 buttons with labels and
  their "Magic Line" command lists (multi-command buttons included). Edit
  labels, targets, channels, levels and fades; *Test* fires a command on
  the bus immediately; *Write to panel* stages the changed flash pages
  (0xDC15), commits (0xDC16), and verifies by reading everything back.
  Writing requires the `enable_flash_write` option (see below).
- **Flash backup / restore groundwork** — back up any module (not just
  panels) to a vendor-compatible `.sbd` under `/share/smartg4`.
- **Control from Home Assistant** — flip a button to "Control from Home
  Assistant" and it fires an HA event instead of a fixed target, so its
  behaviour lives in an HA automation. No vendor software required.
- **Live bus monitor** — an ESPHome-logs-style console streaming every decoded
  telegram in real time. Press a physical wall button and watch it appear.

## Configuration

| Option        | Default            | Meaning                                        |
|---------------|--------------------|------------------------------------------------|
| `gateway`     | `255.255.255.255`  | RSIP / Z-Audio IP, or a broadcast address      |
| `bus_subnet`  | `238`              | This add-on's own S-BUS subnet ID              |
| `bus_device`  | `238`              | This add-on's own S-BUS device ID              |
| `enable_flash_write` | `false`     | Allow the button programmer to write flash pages back to panels. The restore commit (0xDC16) is **experimental** — keep fresh backups and enable at your own risk. |

## Requirements

- The add-on runs on the **host network** so it can send and receive S-BUS UDP
  broadcasts on port 6000. Home Assistant and the gateway must be on the same
  LAN subnet.
- Device backups (`.sbd`) are written under `/share/smartg4`.

## How it works

The frontend (`www/app.html`) is served wrapped in an HTML skeleton and talks to
a small aiohttp API backed by the `pysmartg4` library:

- `GET  /api/devices` — run a bus discovery scan
- `POST /api/send` — send any command `{target, opcode, data|payload}`
- `WS   /api/monitor` — live decoded telegram stream

- `GET  /api/config` — the add-on's gateway / bus-address settings
- `POST /api/rename` — write a device's name `{target, remark}` (0x0010)
- `POST /api/backup` — start a flash backup `{target}`; `.sbd` lands in
  `/share/smartg4`
- `GET  /api/backup/status` — progress of the running backup
- `GET  /api/backups` — list saved `.sbd` files
- `GET  /api/panel/buttons?target=` — decode a panel's buttons from its backup
- `POST /api/panel/write` — write one button back (dry-run without
  `confirm`; real writes additionally need `enable_flash_write`)

All paths are relative, so the UI works unchanged behind the HA ingress proxy.

## Building

The Dockerfile expects a copy of the library at `pysmartg4/` inside this
directory. Stage it from the repo's `src/` before building:

```bash
scripts/build_addon.sh   # from the repo root
```

