"""DDP panel flash-image decoding: button labels and Magic-Line commands.

Layout reverse-engineered from a live DDP backup (device type 0x0095,
"F1 Door") and verified against its known button assignments — all in
memory bank 1 (``FlagOfMemory=1``):

- ``0``       panel name, 20 bytes space-padded ASCII
- ``15616``   button labels: 16 fields x 20 bytes space-padded ASCII
- ``16896``   button commands: 16 slots x 990 bytes, each slot a list of
              9-byte records terminated by a non-record byte (0x00/0xFF)

One command record::

    [function, target_subnet, target_device, p1, p2, p3_hi, p3_lo, crc_hi, crc_lo]

where ``crc`` = CRC-16/XMODEM over the first 7 bytes (verified byte-exact)
and ``function`` selects the Magic-Line command; ``0x59`` = single-channel
control (p1=channel, p2=level %, p3=fade time) — the only function observed
on this panel so far. Other function codes decode generically until mapped.

These offsets are from DDP firmware 0x0095; treat decode failures as
"unknown layout" rather than trusting garbage.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .backup import DeviceBackup
from .crc import crc16_xmodem

PANEL_NAME_OFFSET = 0  # bank 1 on every panel type observed
LABEL_LEN = 20
COMMAND_STRIDE = 990
RECORD_LEN = 9

FUNCTION_NAMES = {
    0x59: "single_channel",
}


@dataclass(frozen=True)
class PanelLayout:
    """Where a panel model keeps its button data (bank, offset)."""

    buttons: int
    labels_bank: int
    labels_offset: int
    commands_bank: int
    commands_offset: int


# Live-verified layouts, keyed by S-BUS device type. Both models share
# the 20-char label fields, the 990-byte command slots and the 9-byte
# CRC records — only counts and offsets differ.
LAYOUTS: dict[int, PanelLayout] = {
    # SV-DDP dynamic display panel
    0x0095: PanelLayout(
        buttons=16,
        labels_bank=1, labels_offset=15616,
        commands_bank=1, commands_offset=16896,
    ),
    # SB-6BS 6-button switch
    0x0119: PanelLayout(
        buttons=6,
        labels_bank=0, labels_offset=200,
        commands_bank=1, commands_offset=20,
    ),
}

# Backwards-compatible aliases (DDP was implemented first).
LABELS_OFFSET = LAYOUTS[0x0095].labels_offset
BUTTON_COUNT = LAYOUTS[0x0095].buttons
COMMANDS_OFFSET = LAYOUTS[0x0095].commands_offset


@dataclass
class ButtonCommand:
    function: int
    subnet: int
    device: int
    p1: int
    p2: int
    p3: int

    @property
    def function_name(self) -> str:
        return FUNCTION_NAMES.get(self.function, f"0x{self.function:02X}")

    def encode(self) -> bytes:
        body = bytes(
            [self.function, self.subnet, self.device, self.p1, self.p2]
        ) + self.p3.to_bytes(2, "big")
        return body + crc16_xmodem(body).to_bytes(2, "big")

    @classmethod
    def parse(cls, record: bytes) -> "ButtonCommand | None":
        """Return the command, or None if the CRC shows it isn't a record."""
        if len(record) < RECORD_LEN:
            return None
        # 0x00/0xFF function bytes are slot padding, and all-zero padding
        # even carries a "valid" CRC (CRC-16/XMODEM of zeros is zero).
        if record[0] in (0x00, 0xFF):
            return None
        body, crc = record[:7], int.from_bytes(record[7:9], "big")
        if crc16_xmodem(body) != crc:
            return None
        return cls(
            function=body[0],
            subnet=body[1],
            device=body[2],
            p1=body[3],
            p2=body[4],
            p3=int.from_bytes(body[5:7], "big"),
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "function": f"0x{self.function:02X}",
            "function_name": self.function_name,
            "target": f"{self.subnet}.{self.device}",
            "p1": self.p1,
            "p2": self.p2,
            "p3": self.p3,
        }


@dataclass
class PanelButton:
    index: int  # 1-based
    label: str
    commands: list[ButtonCommand] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "label": self.label,
            "commands": [c.as_dict() for c in self.commands],
        }


def _text(image: bytes, offset: int, length: int) -> str:
    """Decode a stored label — ASCII or Hebrew (CP1255); '' if unset."""
    from .naming import decode_name

    return decode_name(image[offset : offset + length]) or ""


def _is_label_byte(b: int) -> bool:
    """Bytes a stored label may contain: printable ASCII, CP1255 Hebrew,
    or the 0x00/0xFF padding of an unset field."""
    return (
        0x20 <= b <= 0x7E  # ASCII
        or 0xC0 <= b <= 0xFA  # CP1255 Hebrew letters + punctuation
        or b in (0x00, 0xFF)
    )


def resolve_layout(
    backup: DeviceBackup, device_type: int | None = None
) -> tuple[int, PanelLayout]:
    """Pick the layout for a backup — by device type, or by detection.

    Detection checks that every label field is printable ASCII and the
    command region is large enough; the first fitting layout wins.
    """
    if device_type is not None:
        layout = LAYOUTS.get(device_type)
        if layout is None:
            raise ValueError(
                f"no known button layout for device type 0x{device_type:04X}"
            )
        return device_type, layout
    for dtype, layout in LAYOUTS.items():
        labels_bank = backup.bank(layout.labels_bank)
        commands_bank = backup.bank(layout.commands_bank)
        span = layout.labels_offset + layout.buttons * LABEL_LEN
        if len(labels_bank) < span:
            continue
        if len(commands_bank) < (
            layout.commands_offset + layout.buttons * COMMAND_STRIDE
        ):
            continue
        fields = labels_bank[layout.labels_offset : span]
        if all(_is_label_byte(b) for b in fields):
            return dtype, layout
    raise ValueError("backup matches no known panel layout")


def apply_button(
    backup: DeviceBackup,
    index: int,
    label: str | None,
    commands: list[ButtonCommand],
    device_type: int | None = None,
) -> list["FlashPage"]:
    """Apply a button edit to a backup image and return ONLY the flash
    pages whose bytes changed (what a restore must write). `index` is
    1-based; `label=None` keeps the existing label."""
    from .backup import FlashPage

    _dtype, layout = resolve_layout(backup, device_type)
    if not 1 <= index <= layout.buttons:
        raise ValueError(f"button index {index} out of range")
    if len(commands) * RECORD_LEN > COMMAND_STRIDE:
        raise ValueError(f"too many commands ({len(commands)})")

    images = {
        flag: bytearray(backup.bank(flag))
        for flag in {layout.labels_bank, layout.commands_bank}
    }
    if label is not None:
        encoded = label.encode("ascii", "replace")[:LABEL_LEN].ljust(
            LABEL_LEN, b" "
        )
        offset = layout.labels_offset + (index - 1) * LABEL_LEN
        images[layout.labels_bank][offset : offset + LABEL_LEN] = encoded

    # Overwrite only what must change: the new records plus one zero
    # "terminator" record (decode stops there). Original slot padding is
    # preserved so a small edit touches as few flash pages as possible.
    offset = layout.commands_offset + (index - 1) * COMMAND_STRIDE
    slot = images[layout.commands_bank]
    position = offset
    for command in commands:
        slot[position : position + RECORD_LEN] = command.encode()
        position += RECORD_LEN
    if position + RECORD_LEN <= offset + COMMAND_STRIDE:
        slot[position : position + RECORD_LEN] = bytes(RECORD_LEN)

    changed: list[FlashPage] = []
    for page in backup.pages:
        image = images.get(page.flag)
        if image is None:
            continue
        new_data = bytes(image[page.address : page.address + len(page.data)])
        if new_data != page.data:
            changed.append(
                FlashPage(
                    number=page.number,
                    flag=page.flag,
                    address=page.address,
                    data=new_data,
                )
            )
    return changed


def find_channel_names(
    backup: DeviceBackup, count: int, bank: int = 0
) -> list[str] | None:
    """Locate a module's channel-name table: `count` consecutive 20-byte
    printable ASCII fields in a bank (observed at bank 0 @405 on a
    12-channel relay). Returns the names, or None if no table is found.
    Searches beyond offset 100 to skip the device/zone remark fields."""
    image = backup.bank(bank)

    def field_ok(chunk: bytes) -> bool:
        return (
            len(chunk) == LABEL_LEN
            and all(0x20 <= b <= 0x7E or 0xC0 <= b <= 0xFA for b in chunk)
            and bool(chunk.strip())
        )

    for start in range(100, len(image) - count * LABEL_LEN + 1):
        fields = [
            image[start + i * LABEL_LEN : start + (i + 1) * LABEL_LEN]
            for i in range(count)
        ]
        if all(field_ok(f) for f in fields):
            from .naming import decode_name

            return [decode_name(f) or "" for f in fields]
    return None


def decode_panel(
    backup: DeviceBackup, device_type: int | None = None
) -> dict[str, Any]:
    """Decode a panel backup into {name, model, buttons: [...]}."""
    dtype, layout = resolve_layout(backup, device_type)
    labels_bank = backup.bank(layout.labels_bank)
    commands_bank = backup.bank(layout.commands_bank)
    needed = layout.commands_offset + layout.buttons * COMMAND_STRIDE
    if len(commands_bank) < needed:
        raise ValueError(
            f"bank {layout.commands_bank} too small for layout "
            f"({len(commands_bank)} < {needed})"
        )
    buttons: list[PanelButton] = []
    for n in range(layout.buttons):
        label = _text(
            labels_bank, layout.labels_offset + n * LABEL_LEN, LABEL_LEN
        )
        slot = commands_bank[
            layout.commands_offset
            + n * COMMAND_STRIDE : layout.commands_offset
            + (n + 1) * COMMAND_STRIDE
        ]
        commands: list[ButtonCommand] = []
        for i in range(0, len(slot) - RECORD_LEN + 1, RECORD_LEN):
            command = ButtonCommand.parse(slot[i : i + RECORD_LEN])
            if command is None:
                break
            commands.append(command)
        buttons.append(PanelButton(index=n + 1, label=label, commands=commands))
    return {
        "name": _text(backup.bank(1), PANEL_NAME_OFFSET, LABEL_LEN),
        "device_type": f"0x{dtype:04X}",
        "buttons": [b.as_dict() for b in buttons],
    }
