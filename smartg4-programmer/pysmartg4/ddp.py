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

PANEL_NAME_OFFSET = 0
LABELS_OFFSET = 15616
LABEL_LEN = 20
BUTTON_COUNT = 16
COMMANDS_OFFSET = 16896
COMMAND_STRIDE = 990
RECORD_LEN = 9

FUNCTION_NAMES = {
    0x59: "single_channel",
}


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
    return (
        image[offset : offset + length]
        .decode("ascii", "replace")
        .rstrip("\x00\xff ")
        .strip()
    )


def apply_button(
    backup: DeviceBackup,
    index: int,
    label: str | None,
    commands: list[ButtonCommand],
) -> list["FlashPage"]:
    """Apply a button edit to a backup image and return ONLY the flash
    pages whose bytes changed (what a restore must write). `index` is
    1-based; `label=None` keeps the existing label."""
    from .backup import FlashPage

    if not 1 <= index <= BUTTON_COUNT:
        raise ValueError(f"button index {index} out of range")
    if len(commands) * RECORD_LEN > COMMAND_STRIDE:
        raise ValueError(f"too many commands ({len(commands)})")

    image = bytearray(backup.bank(1))
    if label is not None:
        encoded = label.encode("ascii", "replace")[:LABEL_LEN].ljust(
            LABEL_LEN, b" "
        )
        offset = LABELS_OFFSET + (index - 1) * LABEL_LEN
        image[offset : offset + LABEL_LEN] = encoded

    slot = bytearray(COMMAND_STRIDE)  # zero padding terminates the list
    position = 0
    for command in commands:
        slot[position : position + RECORD_LEN] = command.encode()
        position += RECORD_LEN
    offset = COMMANDS_OFFSET + (index - 1) * COMMAND_STRIDE
    image[offset : offset + COMMAND_STRIDE] = slot

    changed: list[FlashPage] = []
    for page in backup.pages:
        if page.flag != 1:
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


def decode_panel(backup: DeviceBackup) -> dict[str, Any]:
    """Decode a DDP backup into {name, buttons: [...]}."""
    image = backup.bank(1)
    needed = COMMANDS_OFFSET + BUTTON_COUNT * COMMAND_STRIDE
    if len(image) < needed:
        raise ValueError(
            f"bank 1 too small for DDP layout ({len(image)} < {needed})"
        )
    buttons: list[PanelButton] = []
    for n in range(BUTTON_COUNT):
        label = _text(image, LABELS_OFFSET + n * LABEL_LEN, LABEL_LEN)
        slot = image[
            COMMANDS_OFFSET
            + n * COMMAND_STRIDE : COMMANDS_OFFSET
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
        "name": _text(image, PANEL_NAME_OFFSET, LABEL_LEN),
        "buttons": [b.as_dict() for b in buttons],
    }
