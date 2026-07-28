"""Read and write device / channel names (remarks) over the bus.

All four operations use documented SDK opcodes and are confirmed live:

- device name:  write 0x0010 (ack 0x0011); the name also comes back in
  every 0x000F scan response
- zone name:    read 0xF00A / write 0xF00C
- channel name: read 0xF00E / write 0xF010

Names are 20 bytes of space-padded ASCII. Requests are lost often on a
busy bus, so everything here retries.
"""

from __future__ import annotations

import asyncio

from .bus import SmartG4Bus
from .packet import DeviceAddress

NAME_LEN = 20


def clean(name: str) -> str:
    """Coerce a name to what the hardware can store."""
    return name.encode("ascii", "replace")[:NAME_LEN].decode("ascii").rstrip()


async def read_channel_name(
    bus: SmartG4Bus, target: DeviceAddress, channel: int, retries: int = 3
) -> str | None:
    try:
        packet = await bus.request(
            target,
            0xF00E,
            {"channel": channel},
            timeout=1.0,
            retries=retries,
            match=lambda p: p.payload[:1] == bytes([channel]),
        )
    except (TimeoutError, asyncio.TimeoutError):
        return None
    return packet.payload[1:].decode("ascii", "replace").rstrip("\x00 ")


async def read_channel_names(
    bus: SmartG4Bus, target: DeviceAddress, count: int
) -> list[str | None]:
    """Read every channel name of a module (None where no reply came)."""
    names: list[str | None] = []
    for channel in range(1, count + 1):
        names.append(await read_channel_name(bus, target, channel))
        await asyncio.sleep(0.05)
    return names


async def write_channel_name(
    bus: SmartG4Bus, target: DeviceAddress, channel: int, name: str
) -> bool:
    """Write a channel name; verify by reading it back."""
    name = clean(name)
    try:
        await bus.request(
            target,
            0xF010,
            {"channel": channel, "remark": name},
            timeout=2.0,
            retries=2,
        )
    except (TimeoutError, asyncio.TimeoutError):
        pass  # some modules ack late or not at all — verify by reading
    await asyncio.sleep(0.3)
    return await read_channel_name(bus, target, channel) == name


async def write_device_name(
    bus: SmartG4Bus, target: DeviceAddress, name: str
) -> bool:
    """Write a device name (0x0010). Returns True if the module acked."""
    try:
        await bus.request(
            target, 0x0010, {"remark": clean(name)}, timeout=2.0, retries=2
        )
        return True
    except (TimeoutError, asyncio.TimeoutError):
        return False
