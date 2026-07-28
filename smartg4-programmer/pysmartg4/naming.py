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

# Smart-G4 stores names as 20 raw bytes. Latin text is plain ASCII;
# Hebrew installations use CP1255 (Windows Hebrew), whose 0x20-0x7E range
# is identical to ASCII, so one codec round-trips both.
ENCODING = "cp1255"


def encode_name(name: str) -> bytes:
    """Encode a name to the 20-byte, space-padded on-device form."""
    raw = name.encode(ENCODING, "replace")[:NAME_LEN]
    return raw.ljust(NAME_LEN, b" ")


def clean(name: str) -> str:
    """Coerce a name to exactly what the hardware will store."""
    return encode_name(name).decode(ENCODING).rstrip()


def decode_name(raw: bytes) -> str | None:
    """Decode a stored name field, or None if it was never set.

    Unset fields are 0xFF / 0x00 padding. A field counts as a name only
    if every byte is printable in CP1255 — which covers ASCII and
    Hebrew, and rejects the binary junk left in unused flash.
    """
    text = raw.split(b"\x00")[0].rstrip(b"\xff\x00 ")
    if not text:
        return None
    # printable ASCII, or CP1255 Hebrew/punctuation — never control bytes
    if any(b < 0x20 or b == 0x7F or 0x80 <= b <= 0xBF or b >= 0xFB for b in text):
        return None
    try:
        return text.decode(ENCODING)
    except UnicodeDecodeError:
        return None


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
    return decode_name(packet.payload[1:])


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
    stored = await read_channel_name(bus, target, channel)
    # Clearing a name reads back as "never set" (None), not "".
    return stored == name or (not name and stored is None)


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
