"""Device flash backup over the bus (0xDC1x family).

Read path, confirmed live against a DDP panel and relay modules:

1. ``0xDC10`` (no payload) → ``0xDC11`` ``[0xF8, total_hi, total_lo]`` —
   the number of flash pages (715 on a DDP panel, matching the vendor
   .sbd's ``TotalQTY``).
2. ``0xDC14`` ``[pkg_hi, pkg_lo]`` → ``0xDC15``
   ``[pkg_hi, pkg_lo, flag, addr_hi, addr_mid, addr_lo, data...]`` —
   one flash page (59 data bytes observed). ``flag`` is the .sbd
   ``FlagOfMemory`` (memory bank), ``addr`` its ``StartAddress``.

Out-of-range page numbers still get an answer (garbage), so always
bound reads by the ``0xDC10`` total. The restore/write path (0xDC16...)
is intentionally not implemented yet: the per-page write opcode is not
exposed by the SDK surface and experimenting blind could brick a panel.

The .sbd format written/read here is the vendor's own: an INI file of
pages, directly loadable by Smart Cloud as a fallback.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Awaitable, Callable

from .bus import SmartG4Bus
from .packet import DeviceAddress

ProgressCallback = Callable[[int, int], "Awaitable[None] | None"]


@dataclass
class FlashPage:
    number: int          # 1-based package number
    flag: int            # FlagOfMemory (memory bank)
    address: int         # StartAddress within the bank
    data: bytes

    @classmethod
    def parse(cls, payload: bytes) -> "FlashPage":
        if len(payload) < 7:
            raise ValueError(f"0xDC15 payload too short: {len(payload)}")
        return cls(
            number=int.from_bytes(payload[0:2], "big"),
            flag=payload[2],
            address=int.from_bytes(payload[3:6], "big"),
            data=payload[6:],
        )


@dataclass
class DeviceBackup:
    subnet: int
    device: int
    device_type: int
    pages: list[FlashPage] = field(default_factory=list)

    def to_sbd(self) -> str:
        lines = [
            "[Base]",
            f"SubnetID={self.subnet}",
            f"DeviceID={self.device}",
            f"DeviceType={self.device_type}",
            f"TotalQTY={len(self.pages)}",
            f"LastPackageNo={len(self.pages)}",
        ]
        for page in self.pages:
            lines += [
                f"[{page.number}]",
                f"LenOfFlashData={len(page.data)}",
                f"FlagOfMemory={page.flag}",
                f"StartAddress={page.address}",
                "FlashData=" + ",".join(str(b) for b in page.data),
            ]
        return "\n".join(lines) + "\n"

    @classmethod
    def from_sbd(cls, text: str) -> "DeviceBackup":
        import re

        sections = re.split(r"(?m)^\[([^\]]+)\]\r?\n", text)
        base: dict[str, str] = {}
        pages: list[FlashPage] = []
        for i in range(1, len(sections) - 1, 2):
            name, body = sections[i], sections[i + 1]
            kv = dict(re.findall(r"(?m)^(\w+)=(.*?)\r?$", body))
            if name == "Base":
                base = kv
                continue
            data = bytes(
                int(v) for v in kv["FlashData"].split(",") if v.strip()
            )
            pages.append(
                FlashPage(
                    number=int(name),
                    flag=int(kv.get("FlagOfMemory", 0)),
                    address=int(kv.get("StartAddress", 0)),
                    data=data,
                )
            )
        return cls(
            subnet=int(base.get("SubnetID", 0)),
            device=int(base.get("DeviceID", 0)),
            device_type=int(base.get("DeviceType", 0)),
            pages=pages,
        )

    def bank(self, flag: int) -> bytes:
        """Reassemble one memory bank as a contiguous image."""
        pages = sorted(
            (p for p in self.pages if p.flag == flag), key=lambda p: p.address
        )
        image = bytearray()
        for page in pages:
            if page.address > len(image):
                image.extend(b"\xff" * (page.address - len(image)))
            image[page.address : page.address + len(page.data)] = page.data
        return bytes(image)


async def read_backup_info(
    bus: SmartG4Bus, target: DeviceAddress, timeout: float = 2.0, retries: int = 3
) -> int:
    """Return the device's total flash-page count (0xDC10 → 0xDC11)."""
    packet = await bus.request(
        target, 0xDC10, timeout=timeout, retries=retries
    )
    if len(packet.payload) < 3 or packet.payload[0] != 0xF8:
        raise ValueError(f"unexpected 0xDC11 payload: {packet.payload.hex()}")
    return int.from_bytes(packet.payload[1:3], "big")


async def read_page(
    bus: SmartG4Bus,
    target: DeviceAddress,
    number: int,
    timeout: float = 0.5,
    retries: int = 10,
) -> FlashPage:
    # Replies arrive well under 0.5 s when the frame gets through; frames
    # are simply lost often (RS-485 collisions with periodic broadcasts),
    # so many quick retries beat few slow ones.
    """Read one flash page (0xDC14 → 0xDC15), retrying through collisions."""
    payload = number.to_bytes(2, "big")
    packet = await bus.request(
        target,
        0xDC14,
        payload=payload,
        timeout=timeout,
        retries=retries,
        # Devices emit duplicate 0xDC15s; pair the reply to OUR page number
        # so a late duplicate of page N can't satisfy the request for N+1.
        match=lambda p: p.payload[0:2] == payload,
    )
    return FlashPage.parse(packet.payload)


def stage_page(bus: SmartG4Bus, target: DeviceAddress, page: FlashPage) -> None:
    """Send one page to a device in 0xDC15 format (restore staging).

    Sending a page whose content is identical to the device's current
    flash is a no-op regardless of how the device treats staging.
    """
    payload = (
        page.number.to_bytes(2, "big")
        + bytes([page.flag])
        + page.address.to_bytes(3, "big")
        + page.data
    )
    bus.send(target, 0xDC15, payload=payload)


async def commit_restore(
    bus: SmartG4Bus, target: DeviceAddress, packages: int, timeout: float = 5.0
):
    """DANGER — commit a restore (0xDC16 → ack 0xDC17). UNVERIFIED on real
    hardware: the exact semantics of the page count and the ordering
    contract are inferred from the SDK surface, not yet observed live.
    Never call this without a fresh full backup of the target and explicit
    user consent."""
    return await bus.request(
        target, 0xDC16, {"packages": packages}, timeout=timeout, retries=1
    )


async def backup_device(
    bus: SmartG4Bus,
    target: DeviceAddress,
    device_type: int = 0,
    progress: ProgressCallback | None = None,
    inter_page_delay: float = 0.02,
) -> DeviceBackup:
    """Read a device's full flash image. Takes ~1-3 min on a DDP panel."""
    total = await read_backup_info(bus, target)
    backup = DeviceBackup(
        subnet=target.subnet, device=target.device, device_type=device_type
    )
    pages: dict[int, FlashPage] = {}
    missing = list(range(1, total + 1))
    # Transient dead spells happen on a busy bus — sweep the missing set
    # up to three times before giving up.
    for sweep in range(3):
        still_missing: list[int] = []
        for number in missing:
            try:
                pages[number] = await read_page(bus, target, number)
            except (TimeoutError, asyncio.TimeoutError):
                still_missing.append(number)
            if progress is not None:
                result = progress(len(pages), total)
                if asyncio.iscoroutine(result):
                    await result
            # A short gap keeps the RS-485 side from re-colliding.
            await asyncio.sleep(inter_page_delay)
        missing = still_missing
        if not missing:
            break
        await asyncio.sleep(2.0)  # let the bus drain before the next sweep
    if missing:
        raise TimeoutError(
            f"could not read pages {missing[:10]}{'...' if len(missing) > 10 else ''} "
            f"from {target} after 3 sweeps"
        )
    backup.pages = [pages[n] for n in sorted(pages)]
    return backup
