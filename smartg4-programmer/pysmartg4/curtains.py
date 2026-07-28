"""Shutter / curtain configuration stored in relay modules.

Confirmed live: `0xDC23` (Read_Curtain_Control_Enabled) answers `0xDC24`
with `[enabled_bitmask, running_time per group...]`. Bit N of the mask
enables curtain group N+1, and group N drives the channel pair
`(2N-1, 2N)` — the first channel opens, the second closes. Cross-checked
against the modules' own channel names on a live installation, e.g.
1.101 group 4 -> channels 7/8 named "Drape U" / "Drape D".

Running time is the seconds the motor needs end to end; the module uses
it to interlock the pair and drop the relay at the end of travel, which
is why the wall panels can drive these channels with ordinary
single-channel commands.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any

from .bus import SmartG4Bus
from .packet import DeviceAddress

DEFAULT_TRAVEL_TIME = 30


@dataclass
class CurtainGroup:
    group: int           # 1-based
    up_channel: int
    down_channel: int
    travel_time: int     # seconds

    def as_dict(self) -> dict[str, Any]:
        return {
            "group": self.group,
            "up_channel": self.up_channel,
            "down_channel": self.down_channel,
            "travel_time": self.travel_time,
        }


def parse_curtain_config(payload: bytes) -> list[CurtainGroup]:
    """Decode a 0xDC24 payload into the enabled curtain groups."""
    if not payload:
        return []
    mask = payload[0]
    times = payload[1:]
    groups: list[CurtainGroup] = []
    for index in range(8):
        if not mask & (1 << index):
            continue
        group = index + 1
        travel = times[index] if index < len(times) else DEFAULT_TRAVEL_TIME
        if not travel or travel == 0xFF:
            travel = DEFAULT_TRAVEL_TIME
        groups.append(
            CurtainGroup(
                group=group,
                up_channel=group * 2 - 1,
                down_channel=group * 2,
                travel_time=travel,
            )
        )
    return groups


async def read_curtain_config(
    bus: SmartG4Bus, target: DeviceAddress, retries: int = 3
) -> list[CurtainGroup]:
    """Ask a module which of its channel pairs are shutters."""
    try:
        packet = await bus.request(
            target, 0xDC23, timeout=1.5, retries=retries
        )
    except (TimeoutError, asyncio.TimeoutError):
        return []
    return parse_curtain_config(packet.payload)
