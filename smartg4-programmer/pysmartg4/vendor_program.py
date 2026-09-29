"""Capture-free panel button programming (read/write a key's function config).

This replaces the old capture-and-replay path (:mod:`pysmartg4.vendor_frame`):
now that the header cipher is known (:mod:`pysmartg4.vendor_cipher`), the
frames are built from scratch for any panel, so nothing has to be captured
first and any target can be addressed.

Protocol (reversed from ``TfrmMain.ReadPanelKeyFunConfig`` /
``ModifyPanelKeyFunConfig`` in Smart Cloud V16.38, and checked against the
live captures in ``captures/``):

======  =========================  ================================================
opcode  meaning                    payload
======  =========================  ================================================
0xE000  read key function config   ``[key, page]``
0xE001  read response              ``[key, page, function, subnet, device, p1, p2, p3hi, p3lo]``
0xE002  write key function config  ``[key, page, function, subnet, device, p1, p2, p3hi, p3lo, last]``
0xE003  write ack                  ``[key, page]``
0xE004  read key label             ``[key]``
0xE005  label response             ``[key, 20 label bytes]``
0xE006  write key label            ``[key, 20 label bytes]``
0xE007  label write ack            ``[key]``
0xE008  read key modes             ``[]``
0xE009  key modes response         ``[mode per key ...]`` (``01`` × 6 on an SB-6BS)
0xE00A  write key modes            ``[mode per key ...]``
0xE00B  key modes ack              ``[status]`` (``0xF8`` observed)
======  =========================  ================================================

``key`` is the key number, **1-based**. ``page`` is the function entry within
that key and is **1-based too**: every frame Smart Cloud ever sent, and every
write the add-on verified, carries ``page == 1`` (:data:`FIRST_PAGE`). A key
can hold several entries in flash, so higher pages presumably address the
2nd, 3rd... entry, but only page 1 has been exercised live. Page 0 has never
been seen on the wire — don't send it.

Smart Cloud always sends ``0xE00A`` (echoing what ``0xE008`` returned) right
before each ``0xE002`` write, and the panel acks with ``0xE00B``. Whether the
write depends on it is unknown, so callers should mirror the sequence.

``function`` is the KeyFunType (0x59 single-channel, 0x55 scene, 0x56
sequence, 0x58 universal switch, ...); ``subnet``/``device`` are the command's
target; ``p1..p3`` are its parameters. ``last`` is a trailing byte the app
sends (0xFF for most function types, or a mode/param for a few); ``0xFF`` is
safe as a default.

The app retries the read/write up to 3 times with a ~2 s timeout each, because
these frames collide with the panel's periodic broadcasts — mirror that.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .naming import decode_name
from .packet import BROADCAST, DeviceAddress, Packet
from .vendor_cipher import from_vendor_frame, is_vendor_frame, to_vendor_frame

READ_OPCODE = 0xE000
READ_RESPONSE = 0xE001
WRITE_OPCODE = 0xE002
WRITE_RESPONSE = 0xE003
LABEL_READ_OPCODE = 0xE004
LABEL_READ_RESPONSE = 0xE005
LABEL_WRITE_OPCODE = 0xE006
LABEL_WRITE_RESPONSE = 0xE007
KEYMODE_READ_OPCODE = 0xE008
KEYMODE_READ_RESPONSE = 0xE009
KEYMODE_WRITE_OPCODE = 0xE00A
KEYMODE_WRITE_RESPONSE = 0xE00B

RESPONSE_OPCODES = {
    READ_RESPONSE,
    WRITE_RESPONSE,
    LABEL_READ_RESPONSE,
    LABEL_WRITE_RESPONSE,
    KEYMODE_READ_RESPONSE,
    KEYMODE_WRITE_RESPONSE,
}

#: The first (and, so far, only live-verified) function entry of a key.
FIRST_PAGE = 1
DEFAULT_LAST_BYTE = 0xFF
LABEL_LEN = 20

DEFAULT_SOURCE = DeviceAddress(0xEE, 0xEE)
DEFAULT_SOURCE_TYPE = 0xFFFE


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
        """The 7-byte body shared by read responses and write requests."""
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


def build_frame(
    opcode: int,
    payload: bytes,
    target: DeviceAddress,
    *,
    source: DeviceAddress = DEFAULT_SOURCE,
    source_type: int = DEFAULT_SOURCE_TYPE,
    source_ip: bytes = b"\x00\x00\x00\x00",
    key: bytes | str | None = None,
) -> bytes:
    """A ready-to-send vendor frame for any of the ``0xE00x`` operations."""
    pkt = Packet(
        opcode=opcode,
        source=source,
        target=target,
        source_type=source_type,
        payload=payload,
        source_ip=source_ip,
    )
    return to_vendor_frame(pkt.encode(), key)


def build_read_frame(
    button: int, page: int, target: DeviceAddress, **kwargs: Any
) -> bytes:
    """A ``0xE000`` frame asking one key/page for its config."""
    return build_frame(READ_OPCODE, bytes([button, page]), target, **kwargs)


def build_write_frame(
    fn: ButtonFunction,
    target: DeviceAddress,
    *,
    last: int = DEFAULT_LAST_BYTE,
    **kwargs: Any,
) -> bytes:
    """A ``0xE002`` frame assigning one key/page.

    ``target`` is the panel being programmed; ``fn.target`` is what the key
    controls.
    """
    payload = bytes([fn.button, fn.page]) + fn.record() + bytes([last & 0xFF])
    return build_frame(WRITE_OPCODE, payload, target, **kwargs)


def build_label_read_frame(
    button: int, target: DeviceAddress, **kwargs: Any
) -> bytes:
    """A ``0xE004`` frame asking one key for its 20-byte label."""
    return build_frame(LABEL_READ_OPCODE, bytes([button]), target, **kwargs)


def build_keymode_read_frame(target: DeviceAddress, **kwargs: Any) -> bytes:
    """A ``0xE008`` frame asking the panel for its per-key mode bytes."""
    return build_frame(KEYMODE_READ_OPCODE, b"", target, **kwargs)


def build_keymode_write_frame(
    modes: bytes, target: DeviceAddress, **kwargs: Any
) -> bytes:
    """A ``0xE00A`` frame — Smart Cloud sends this before every key write."""
    return build_frame(KEYMODE_WRITE_OPCODE, bytes(modes), target, **kwargs)


def parse_response(
    datagram: bytes, key: bytes | str | None = None
) -> dict[str, Any] | None:
    """Decode any ``0xE00x`` reply from a panel.

    Returns ``None`` unless the datagram is a vendor frame carrying one of
    :data:`RESPONSE_OPCODES`. The dict always has ``opcode``, ``source`` and
    ``payload`` (hex); replies that identify a key add ``button``; ``0xE001``
    adds the function fields, ``0xE005`` adds ``label``, ``0xE009`` adds
    ``modes``.
    """
    if not is_vendor_frame(datagram):
        return None
    try:
        pkt = Packet.decode(from_vendor_frame(datagram, key))
    except ValueError:
        return None
    if pkt.opcode not in RESPONSE_OPCODES:
        return None
    p = pkt.payload
    result: dict[str, Any] = {
        "opcode": pkt.opcode,
        "source": str(pkt.source),
        "payload": p.hex(),
    }
    if pkt.opcode in (READ_RESPONSE, WRITE_RESPONSE) and len(p) >= 2:
        result["button"] = p[0]
        result["page"] = p[1]
    elif pkt.opcode in (LABEL_READ_RESPONSE, LABEL_WRITE_RESPONSE) and p:
        result["button"] = p[0]
    if pkt.opcode == READ_RESPONSE and len(p) >= 9:
        result.update(
            function=p[2],
            target=f"{p[3]}.{p[4]}",
            p1=p[5],
            p2=p[6],
            p3=int.from_bytes(p[7:9], "big"),
        )
    elif pkt.opcode == LABEL_READ_RESPONSE and len(p) >= 2:
        result["label"] = decode_name(p[1 : 1 + LABEL_LEN]) or ""
    elif pkt.opcode == KEYMODE_READ_RESPONSE:
        result["modes"] = list(p)
    return result


__all__ = [
    "FIRST_PAGE",
    "KEYMODE_READ_OPCODE",
    "KEYMODE_READ_RESPONSE",
    "KEYMODE_WRITE_OPCODE",
    "KEYMODE_WRITE_RESPONSE",
    "LABEL_READ_OPCODE",
    "LABEL_READ_RESPONSE",
    "LABEL_WRITE_OPCODE",
    "LABEL_WRITE_RESPONSE",
    "READ_OPCODE",
    "READ_RESPONSE",
    "RESPONSE_OPCODES",
    "WRITE_OPCODE",
    "WRITE_RESPONSE",
    "ButtonFunction",
    "build_frame",
    "build_keymode_read_frame",
    "build_keymode_write_frame",
    "build_label_read_frame",
    "build_read_frame",
    "build_write_frame",
    "parse_response",
    "BROADCAST",
]
