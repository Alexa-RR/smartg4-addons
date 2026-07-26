"""Bus device discovery.

Active: broadcast ReadMACAddress (0xF003) to 255.255 — every module
answers 0xF004 with its MAC and remark (user-assigned name), and the
frame header carries its subnet/device/type.

Passive: while listening, record the header of every telegram seen, so
even devices that ignore 0xF003 show up once they broadcast anything
(sensors, panels and scene modules chat regularly).
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any

from .bus import SmartG4Bus
from .device_types import device_type_name
from .packet import BROADCAST, Packet


@dataclass
class DiscoveredDevice:
    subnet: int
    device: int
    device_type: int
    mac: str | None = None
    remark: str | None = None
    opcodes_seen: set[int] = field(default_factory=set)

    @property
    def address(self) -> str:
        return f"{self.subnet}.{self.device}"

    @property
    def type_name(self) -> str:
        return device_type_name(self.device_type)

    def as_dict(self) -> dict[str, Any]:
        return {
            "address": self.address,
            "subnet": self.subnet,
            "device": self.device,
            "device_type": f"0x{self.device_type:04X}",
            "type_name": self.type_name,
            "mac": self.mac,
            "remark": self.remark,
            "opcodes_seen": sorted(f"0x{op:04X}" for op in self.opcodes_seen),
        }


def merge_device_lists(
    existing: list[dict[str, Any]], found: list[dict[str, Any]]
) -> tuple[list[dict[str, Any]], int]:
    """Merge a new scan into a stored device list (as_dict shape).

    Never drops stored devices — scan replies are lossy, so absence from
    one scan means nothing. Returns (merged, number_of_new_devices).
    """
    by_address = {d["address"]: dict(d) for d in existing}
    new = 0
    for device in found:
        current = by_address.get(device["address"])
        if current is None:
            by_address[device["address"]] = dict(device)
            new += 1
            continue
        if device.get("remark"):
            current["remark"] = device["remark"]
        if device.get("mac"):
            current["mac"] = device["mac"]
        current["device_type"] = device["device_type"]
        current["type_name"] = device["type_name"]
        current["opcodes_seen"] = sorted(
            set(current.get("opcodes_seen", []))
            | set(device.get("opcodes_seen", []))
        )
    merged = sorted(
        by_address.values(), key=lambda d: (d["subnet"], d["device"])
    )
    return merged, new


async def discover(
    bus: SmartG4Bus,
    duration: float = 15.0,
    probes: int | None = None,
    probe_interval: float = 0.5,
) -> list[DiscoveredDevice]:
    """Discover devices actively and passively for `duration` seconds.

    Broadcast scan responses are very lossy: when every module answers at
    once, the RS-485 side collides and the gateway relays only a random
    subset (observed ~10 of ~38 per probe). So we keep probing for the
    whole window and accumulate the union — the official SDK likewise
    repeats every send 3x at 300 ms for this reason. `probes` limits the
    number of probe rounds; by default rounds continue until `duration`
    ends.
    """
    found: dict[tuple[int, int], DiscoveredDevice] = {}

    def record(packet: Packet, parsed: dict[str, Any] | None) -> None:
        # Skip our own frames and community-style PC integrations. Do NOT
        # filter modules by device type: 0x000F scan responses carry each
        # module's real type in the header.
        if packet.source == bus.sender or packet.source_type == 0xFFFE:
            return
        key = (packet.source.subnet, packet.source.device)
        entry = found.get(key)
        if entry is None:
            entry = found[key] = DiscoveredDevice(
                subnet=packet.source.subnet,
                device=packet.source.device,
                device_type=packet.source_type,
            )
        entry.opcodes_seen.add(packet.opcode)
        if packet.opcode == 0x000F and parsed and parsed.get("remark"):
            entry.remark = parsed["remark"]
        if packet.opcode == 0xF004 and parsed:
            entry.mac = parsed["mac"]
            # 0xF004's remark is only a 4-byte fragment of the name on the
            # firmware observed here — never overwrite a full 0x000F name.
            if entry.remark is None and parsed["remark"].strip():
                entry.remark = parsed["remark"]

    unsubscribe = bus.on_packet(record)
    try:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + duration
        rounds = 0
        while loop.time() < deadline and (probes is None or rounds < probes):
            # 0x000E is the vendor tool's primary "scan online" probe;
            # 0xF003 additionally returns each device's MAC + remark (name).
            # Burst like the SDK (3x, 300 ms apart), then stay quiet so the
            # RS-485 side can drain the response pile-up before the next
            # round; alternating the two probe opcodes between rounds.
            opcode = 0x000E if rounds % 2 == 0 else 0xF003
            for _ in range(3):
                bus.send(BROADCAST, opcode)
                await asyncio.sleep(0.3)
            rounds += 1
            quiet = min(2.0, max(deadline - loop.time(), 0))
            await asyncio.sleep(quiet)
        remaining = deadline - loop.time()
        if remaining > 0:
            await asyncio.sleep(remaining)
    finally:
        unsubscribe()

    return sorted(found.values(), key=lambda d: (d.subnet, d.device))
