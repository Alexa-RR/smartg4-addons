# Smart-G4 add-ons for Home Assistant

Home Assistant add-on repository for the
[Smart-G4 / S-BUS](https://www.smarthomebus.com/smart-bus-sbus-technology.html)
smart home system.

## Installation

1. *Settings → Add-ons → Add-on Store → ⋮ → Repositories* and add:
   `https://github.com/Alexa-RR/smartg4-addons`
2. Install **Smart-G4 Builder** and start it — it opens from the HA
   sidebar (ingress).

## Add-ons

### Smart-G4 Builder

Program and monitor your S-BUS installation without the vendor software:

- **Device grid** — live bus discovery with on-bus names, online status
  and per-channel state; rename modules (written to the device itself).
- **Channel control** — switch/dim any relay or dimmer channel.
- **Flash backup** — back up any module to a vendor-compatible `.sbd`
  file under `/share/smartg4`.
- **DDP button programmer** — decode a panel's real button configuration
  from its backup (labels + Magic-Line command lists), edit it, and test
  commands live. Flash *writes* are experimental and disabled unless the
  `enable_flash_write` option is turned on — keep fresh backups.
- **Bus monitor** — live decoded telegram console.

Companion Home Assistant integration (entities, events, HACS):
[smartg4-ha](https://github.com/Alexa-RR/smartg4-ha).
