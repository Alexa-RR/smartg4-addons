"""Capture-free panel button programming (read/write a key's function config).

This replaces the old capture-and-replay path (:mod:`pysmartg4.vendor_frame`):
now that the header cipher is known (:mod:`pysmartg4.vendor_cipher`), the
frames are built from scratch for any panel, so nothing has to be captured
first and any target can be addressed.

Protocol (reversed from ``TfrmMain.ReadPanelKeyFunConfig`` /
``TfrmMain.ModifyPanelKeyFunConfig`` in Smart Cloud V16.38):

======  =========================  ================================================
opcode  meaning                    payload
======  =========================  ================================================
0xE000  read key function config   ``[button, page]``
0xE001  read response              ``[button, page, function, subnet, device, p1, p2, p3hi, p3lo]``
0xE002  write key function config  ``[button, page, function, subnet, device, p1, p2, p3hi, p3lo, last]``
0xE003  write ack                  ``[button, page]``
======  =========================  ================================================

``button`` is the key number (1-based on the panel). ``page`` is the function
index within that key — a key can hold several function entries, addressed
0,1,2,... (the app calls it "function no."). ``function`` is the KeyFunType
(0x59 single-channel, 0x55 scene, 0x56 sequence, 0x58 universal switch, ...);
``subnet``/``device`` are the command's target; ``p1..p3`` are its parameters.
``last`` is a trailing byte the app sends (0xFF for most function types, or a
mode/param for a few); ``0xFF`` is safe as a default.

The app retries the read/write up to 3 times with a ~2 s timeout each, because
these frames collide with the panel's periodic broadcasts — mirror that.
"""

from __future__ import annotations

from dataclasses import dataclass

from .packet import BROADCAST, DeviceAddress, Packet
from .vendor_cipher import from_vendor_frame, is_vendor_frame, to_vendor_frame

READ_OPCODE = 0xE000
READ_RESPONSE = 0xE001
WRITE_OPCODE = 0xE002
WRITE_RESPONSE = 0xE003

DEFAULT_LAST_BYTE = 0xFF


@dataclass
class ButtonFunction:
    """One function entry stored on a panel key."""

    button: int
    page: int
    function: int
    target: DeviceAddress
    p1: int = 0
    p2: int = 0
    p3: int = 0

    def record(self) -> bytes:
        """The 9-byte body shared by read responses and write requests."""
        return bytes(
            [
                self.function,
                self.target.subnet,
                self.target.device,
                self.p1,
                self.p2,
                (self.p3 >> 8) & 0xFF,
                self.p3 & 0xFF,
            ]
        )


def build_read_frame(
    button: int,
    page: int,
    target: DeviceAddress,
    *,
    source: DeviceAddress = DeviceAddress(0xEE, 0xEE),
    source_type: int = 0xFFFE,
    source_ip: bytes = b"\x00\x00\x00\x00",
    key: bytes | str | None = None,
) -> bytes:
    """A ready-to-send ``0xE000`` frame asking one key/page for its config."""
    pkt = Packet(
        opcode=READ_OPCODE,
        source=source,
        target=target,
        source_type=source_type,
        payload=bytes([button, page]),
        source_ip=source_ip,
    )
    return to_vendor_frame(pkt.encode(), key)


def build_write_frame(
    fn: ButtonFunction,
    target: DeviceAddress,
    *,
    last: int = DEFAULT_LAST_BYTE,
    source: DeviceAddress = DeviceAddress(0xEE, 0xEE),
    source_type: int = 0xFFFE,
    source_ip: bytes = b"\x00\x00\x00\x00",
    key: bytes | str | None = None,
) -> bytes:
    """A ready-to-send ``0xE002`` frame assigning one key/page.

    ``target`` is the panel being programmed; ``fn.target`` is what the key
    controls.
    """
    payload = bytes([fn.button, fn.page]) + fn.record() + bytes([last & 0xFF])
    pkt = Packet(
        opcode=WRITE_OPCODE,
        source=source,
        target=target,
        source_type=source_type,
        payload=payload,
        source_ip=source_ip,
    )
    return to_vendor_frame(pkt.encode(), key)


def parse_response(datagram: bytes, key: bytes | str | None = None) -> dict | None:
    """Decode a ``0xE001`` read response or ``0xE003`` write ack.

    Returns a dict with the fields, plus ``"opcode"``; ``None`` if the datagram
    is not a vendor programming response.
    """
    if not is_vendor_frame(datagram):
        return None
    try:
        pkt = Packet.decode(from_vendor_frame(datagram, key))
    except ValueError:
        return None
    if pkt.opcode not in (READ_RESPONSE, WRITE_RESPONSE):
        return None
    p = pkt.payload
    result: dict = {"opcode": pkt.opcode, "source": str(pkt.source)}
    if len(p) >= 2:
        result["button"] = p[0]
        result["page"] = p[1]
    if pkt.opcode == READ_RESPONSE and len(p) >= 9:
        result.update(
            function=p[2],
            target=f"{p[3]}.{p[4]}",
            p1=p[5],
            p2=p[6],
            p3=int.from_bytes(p[7:9], "big"),
        )
    return result


__all__ = [
    "READ_OPCODE",
    "READ_RESPONSE",
    "WRITE_OPCODE",
    "WRITE_RESPONSE",
    "ButtonFunction",
    "build_read_frame",
    "build_write_frame",
    "parse_response",
    "BROADCAST",
]
