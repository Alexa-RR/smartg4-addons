"""Wall-panel configuration beyond the key function entries.

Everything the Smart Cloud "Panel" form can set on a panel besides the
per-key function list (which lives in :mod:`pysmartg4.vendor_program`):
key modes, key labels ("remarks"), backlight / LED levels, mode linking
("mutex"), joining buttons ("assembled"), the OFF delay of mechanical-switch
keys, button correlation, button lock and the panel's IR remote address.

All opcodes were read off the static decompilation of ``Smart Cloud
Configuration V16.38``; every constant below names the Delphi method it came
from. The vendor's own method->opcode listing (``docs/smartcloud_method_
opcodes_raw.txt``) is *misattributed* for most of these (it lists the opcode
of the next method in the binary), so the values here come from the actual
``TfrmMain.SendAddBuf`` calls and the ``PTR_DAT_01321158 == <opcode>`` polls
that follow them.

Frame format
------------
``TfrmMain.SendAddBuf`` decides per device whether to emit a plain
``0xAA 0xAA`` telegram or the scrambled ``0x45 0x63`` "vendor" variant, from
the DB flags ``IsHadPW`` (device has a programming password) and ``IsComDev``,
not from the opcode. Panels were observed live to take the vendor variant, so
every builder here defaults to ``vendor=True`` (see
:mod:`pysmartg4.vendor_cipher`) and accepts ``vendor=False`` for plain frames.
Parsers accept either form.

Acks
----
Write acks carry ``0xF8`` (ok) or ``0xF5`` (fail) in their first byte, the
same convention as the documented S-BUS commands. Two different response
parsers exist in the app (``FUN_0100b7bc`` and ``FUN_0128db2c``); the second
checks the *second* byte for ``0xE113`` (assembled write). :func:`parse_ack`
therefore accepts ``0xF8`` in either of the first two bytes.

Retries
-------
Every app method sends, then polls for the response opcode for ~2 s, and
retries up to 3 times ("Time out!" after the third). :func:`vendor_exchange`
mirrors that.

Confidence
----------
Opcodes and request payload layouts are read directly from the senders and
are high-confidence. Response layouts come from the handlers named in each
docstring; where the decompile was ambiguous the docstring says so and the
field is tagged ``UNVERIFIED``. ``docs/features/panel_config.md`` has the
per-row confidence table.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Callable, Protocol

from .naming import NAME_LEN, decode_name, encode_name
from .packet import DeviceAddress, Packet
from .vendor_cipher import from_vendor_frame, is_vendor_frame, to_vendor_frame

_LOGGER = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Opcodes (send -> response), each with the decompiled method it came from.
# ---------------------------------------------------------------------------

#: ``TfrmMain.ReadPanelKeyRemark`` / handler ``FUN_01290688`` (E005)
KEY_REMARK_READ = 0xE004
KEY_REMARK_READ_RESPONSE = 0xE005
#: ``FUN_00acded4`` / ``FUN_011e3f38`` / ``FUN_0092087c`` (all send E006)
KEY_REMARK_WRITE = 0xE006
KEY_REMARK_WRITE_RESPONSE = 0xE007

#: ``TfrmMain.ReadPanelKeyMode`` / handler ``FUN_0128fdcc`` (E009)
KEY_MODE_READ = 0xE008
KEY_MODE_READ_RESPONSE = 0xE009
#: ``FUN_0105d630`` / ``FUN_0092040c`` (send E00A); handler ``FUN_012900cc``
KEY_MODE_WRITE = 0xE00A
KEY_MODE_WRITE_RESPONSE = 0xE00B

#: ``TfrmMain.ReadPanelLEDLevel`` / ``TfrmMain.ShowPanelLEDLevel`` (E011)
LED_LEVEL_READ = 0xE010
LED_LEVEL_READ_RESPONSE = 0xE011
#: ``TfrmMain.ModifyPanelLEDLevel`` (11-byte), ``FUN_0105c65c`` (7-byte),
#: ``FUN_006307b0`` (1-byte)
LED_LEVEL_WRITE = 0xE012
LED_LEVEL_WRITE_RESPONSE = 0xE013

#: ``TfrmMain.ReadPanelAssembled`` (E110); handler in ``FUN_0100b7bc``
ASSEMBLED_READ = 0xE110
ASSEMBLED_READ_RESPONSE = 0xE111
#: ``TfrmMain.ModifyPannelAssembled``
ASSEMBLED_WRITE = 0xE112
ASSEMBLED_WRITE_RESPONSE = 0xE113

#: ``TfrmMain.ReadPanelCloseDelay`` / ``TfrmMain.ShowPanelDelayOfClose``
CLOSE_DELAY_READ = 0xE114
CLOSE_DELAY_READ_RESPONSE = 0xE115
#: ``TfrmMain.ModifyPannelDelayClose``
CLOSE_DELAY_WRITE = 0xE116
CLOSE_DELAY_WRITE_RESPONSE = 0xE117

#: ``FUN_0105c8c4`` (button correlation matrix); the opcode depends on the
#: device type: E11E for DDP-class panels (types 0x1C3, 0x25C, 0x25D and a
#: bitmap of newer types), E118 otherwise.
KEY_RELATION_WRITE = 0xE118
KEY_RELATION_WRITE_RESPONSE = 0xE119
KEY_RELATION_WRITE_DDP = 0xE11E
KEY_RELATION_WRITE_DDP_RESPONSE = 0xE11F

#: ``FUN_01058220`` (read, no payload) / ``FUN_010584b8`` (write 3 bytes);
#: shown by ``FUN_0096fd7c`` in the button-correlation form as three
#: yes/no radio pairs.
RELATION_OPTIONS_READ = 0xE11A
RELATION_OPTIONS_READ_RESPONSE = 0xE11B
RELATION_OPTIONS_WRITE = 0xE11C
RELATION_OPTIONS_WRITE_RESPONSE = 0xE11D

#: ``FUN_0105b7dc`` / ``FUN_010ce434`` / ``FUN_011ec114`` (read, no payload)
#: and ``FUN_011ec3a0`` (write 1 byte). Handler clamps the value to 0/1 for
#: non-DDP panels. Most plausibly the "Button lock startup" setting of
#: ``[frmEditKeyLock]``; the form that calls it was not decompiled, so the
#: meaning is UNVERIFIED.
KEY_LOCK_READ = 0xE120
KEY_LOCK_READ_RESPONSE = 0xE121
KEY_LOCK_WRITE = 0xE122
KEY_LOCK_WRITE_RESPONSE = 0xE123
#: Response handled in ``FUN_0100b7bc`` (8 data bytes, stored next to the
#: E121 value). No sender was decompiled; request assumed empty. UNVERIFIED.
KEY_LOCK_TABLE_READ = 0xE124
KEY_LOCK_TABLE_READ_RESPONSE = 0xE125

#: ``TfrmMain.ReadRemoteAddr`` ("View remote control address" in frmPanel).
REMOTE_ADDR_READ = 0xE2F0
REMOTE_ADDR_READ_RESPONSE = 0xE2F1

#: ``TfrmMain.ReadPanelKeyMutex`` / handler ``FUN_01001750`` (E321)
KEY_MUTEX_READ = 0xE320
KEY_MUTEX_READ_RESPONSE = 0xE321
#: ``TfrmMain.ModifyPannelKeyMutex`` / ``FUN_0062f298``
KEY_MUTEX_WRITE = 0xE322
KEY_MUTEX_WRITE_RESPONSE = 0xE323

ACK_OK = 0xF8
ACK_FAIL = 0xF5

#: Largest OFF delay the app accepts (59:59); ``ShowPanelDelayOfClose`` clamps.
MAX_CLOSE_DELAY_SECONDS = 3599

#: Bytes of correlation matrix carried per E118/E11E frame.
KEY_RELATION_CHUNK_LEN = 16

# ---------------------------------------------------------------------------
# Key modes: wire value -> name.
#
# The byte on the wire is ``defKeyMode.KeyModeNO`` (the app stores the raw
# E009 byte in ``tmpButtonInfo.ButtonMode`` and sends it back unchanged in
# E00A). Names are the English ones from ``lang_en.ini [KeyMode]``, joined via
# the CSV's KeyModeNO<->ID columns. IDs 16/17 of the language file ("Fan
# Speed", "Fan Gate Control") have no CSV row and are not mapped.
# ---------------------------------------------------------------------------

KEY_MODE_INVALID = 0
KEY_MODE_SINGLE_ON = 1
KEY_MODE_SINGLE_OFF = 2
KEY_MODE_SINGLE_ON_OFF = 3
KEY_MODE_COMBINATION_ON = 4
KEY_MODE_COMBINATION_OFF = 5
KEY_MODE_COMBINATION_ON_OFF = 6
KEY_MODE_SEPARATE_MOMENTARY = 7
KEY_MODE_SEPARATE_COMBINATION = 8
KEY_MODE_DOUBLE_CLICK_SINGLE = 9
KEY_MODE_DOUBLE_CLICK_COMBINATION = 10
KEY_MODE_MOMENTARY = 11
KEY_MODE_CLOCK = 12
KEY_MODE_MECHANICAL_SWITCH = 13
KEY_MODE_SEPARATE_SINGLE = 14

KEY_MODES: dict[int, str] = {
    KEY_MODE_INVALID: "Invalid",
    KEY_MODE_SINGLE_ON: "Single on",
    KEY_MODE_SINGLE_OFF: "Single off",
    KEY_MODE_SINGLE_ON_OFF: "Single on/off",
    KEY_MODE_COMBINATION_ON: "Combination On",
    KEY_MODE_COMBINATION_OFF: "Combination Off",
    KEY_MODE_COMBINATION_ON_OFF: "Combination on/off",
    KEY_MODE_SEPARATE_MOMENTARY: (
        "Separated left/right button for pressing on/releasing off"
    ),
    KEY_MODE_SEPARATE_COMBINATION: (
        "Separated Left/right button for Combination on/off"
    ),
    KEY_MODE_DOUBLE_CLICK_SINGLE: "Dblclick and Single On/Off",
    KEY_MODE_DOUBLE_CLICK_COMBINATION: "Dblclick and Combination On/Off",
    KEY_MODE_MOMENTARY: "Pressing On/Release Off",
    KEY_MODE_CLOCK: "Clock",
    KEY_MODE_MECHANICAL_SWITCH: "Mechanical Switch",
    KEY_MODE_SEPARATE_SINGLE: (
        "Separated left/right button(left button is for off, right button is for on)"
    ),
}

#: Modes the "mode linking" (mutex) form requires (``[frmEditPanelKeyMutex]``:
#: Combination On / Combination off / Combination On/Off / Dblclick and
#: Combination On/Off).
KEY_MODES_LINKABLE = frozenset(
    {
        KEY_MODE_COMBINATION_ON,
        KEY_MODE_COMBINATION_OFF,
        KEY_MODE_COMBINATION_ON_OFF,
        KEY_MODE_DOUBLE_CLICK_COMBINATION,
    }
)

#: ``defKeyMode.IsCombination`` — modes the DB flags as combination modes.
KEY_MODES_COMBINATION = frozenset(
    {
        KEY_MODE_COMBINATION_ON,
        KEY_MODE_COMBINATION_OFF,
        KEY_MODE_COMBINATION_ON_OFF,
        KEY_MODE_SEPARATE_COMBINATION,
        KEY_MODE_DOUBLE_CLICK_COMBINATION,
        KEY_MODE_CLOCK,
        KEY_MODE_MECHANICAL_SWITCH,
    }
)


def key_mode_name(mode: int) -> str:
    return KEY_MODES.get(mode, f"Unknown ({mode})")


# ---------------------------------------------------------------------------
# Frame plumbing
# ---------------------------------------------------------------------------

DEFAULT_SOURCE = DeviceAddress(0xEE, 0xEE)
DEFAULT_SOURCE_TYPE = 0xFFFE
DEFAULT_SOURCE_IP = b"\x00\x00\x00\x00"


def build_frame(
    opcode: int,
    payload: bytes,
    target: DeviceAddress,
    *,
    vendor: bool = True,
    source: DeviceAddress = DEFAULT_SOURCE,
    source_type: int = DEFAULT_SOURCE_TYPE,
    source_ip: bytes = DEFAULT_SOURCE_IP,
    key: bytes | str | None = None,
) -> bytes:
    """Encode one panel-config request as a ready-to-send datagram.

    ``vendor=True`` produces the ``0x45 0x63`` scrambled-header form the app
    uses for password-capable panels; ``vendor=False`` a plain ``0xAAAA``
    telegram. ``key`` is the panel's programming password for the vendor
    form (``None`` = the default ``SMARTBUS``).
    """
    pkt = Packet(
        opcode=opcode,
        source=source,
        target=target,
        source_type=source_type,
        payload=bytes(payload),
        source_ip=source_ip,
    )
    raw = pkt.encode()
    return to_vendor_frame(raw, key) if vendor else raw


def decode_frame(datagram: bytes, key: bytes | str | None = None) -> Packet | None:
    """Decode a plain or vendor datagram to a :class:`Packet`, or ``None``."""
    try:
        if is_vendor_frame(datagram):
            return Packet.decode(from_vendor_frame(datagram, key))
        return Packet.decode(datagram)
    except ValueError:
        return None


def _decode_for(
    datagram: bytes, opcode: int, key: bytes | str | None = None
) -> Packet | None:
    pkt = decode_frame(datagram, key)
    if pkt is None or pkt.opcode != opcode:
        return None
    return pkt


def _u16(value: int) -> bytes:
    return bytes([(value >> 8) & 0xFF, value & 0xFF])


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


@dataclass
class Ack:
    """A write acknowledgement (``0xE007``, ``0xE00B``, ``0xE013``, ...)."""

    opcode: int
    source: DeviceAddress
    ok: bool
    payload: bytes = b""


@dataclass
class KeyModes:
    """Result of ``0xE008``: the mode of every key, index 0 = key 1."""

    source: DeviceAddress
    modes: list[int]

    def names(self) -> list[str]:
        return [key_mode_name(m) for m in self.modes]


@dataclass
class KeyRemark:
    """Result of ``0xE004``: one key's 20-byte label."""

    source: DeviceAddress
    key: int
    name: str | None
    raw: bytes
    #: Trailing byte after the name, present on paginated (DDP) panels.
    page: int | None = None


@dataclass
class LedLevel:
    """Backlight / LED settings (``0xE010``/``0xE012``).

    Byte positions come from the assembly of ``TfrmMain.ShowPanelLEDLevel``
    (the C decompile of it was unusable): bytes 0 and 1 are clamped to 100
    and shown in the frmPanel "Backlight" and "LED" edits, byte 2 drives a
    checkbox, byte 3 a numeric edit, bytes 4..6 are passed as three bytes to
    a time-encoding routine and shown in a time picker. For device family
    0x6D6 the same bytes 3..10 are shown as four 16-bit words instead
    (``wide`` layout) — which is also what the 11-byte
    ``TfrmMain.ModifyPanelLEDLevel`` sends.

    Field *names* beyond ``backlight``/``led`` are UNVERIFIED: the vendor
    guide's "Memory, Dimming and LED" page lists dimming enable, save last
    dimming value, LED enable, and a backlight-off timeout, but which byte is
    which was not recoverable from the disassembly.
    """

    backlight: int
    led: int
    enabled: bool = False
    #: Bytes 3.. as sent/received. Narrow layout: ``[b3, h, m, s]``;
    #: wide layout: four big-endian 16-bit words.
    params: tuple[int, ...] = (0, 0, 0, 0)
    wide: bool = False
    source: DeviceAddress | None = None
    raw: bytes = b""

    def payload(self) -> bytes:
        """The ``0xE012`` payload for this record (7 or 11 bytes)."""
        if not 0 <= self.backlight <= 100 or not 0 <= self.led <= 100:
            raise ValueError("backlight and led must be 0..100")
        params = tuple(self.params)
        if len(params) != 4:
            raise ValueError("params must hold exactly four values")
        head = bytes([self.backlight, self.led, 1 if self.enabled else 0])
        if self.wide:
            return head + b"".join(_u16(p & 0xFFFF) for p in params)
        return head + bytes(p & 0xFF for p in params)


@dataclass
class Assembled:
    """Result of ``0xE110``: which key a key is joined to.

    ``FUN_0100b7bc`` accepts the E111 reply only when byte 1 equals the key
    that was asked for, and stores byte 2 as the joined key. Byte 0 is a
    status byte (``0xF8`` on the panels seen). The meaning of ``joined_to``
    = 0 (no partner) is UNVERIFIED.
    """

    source: DeviceAddress
    key: int
    joined_to: int
    status: int


@dataclass
class CloseDelay:
    """Result of ``0xE114``: OFF delay of a mechanical-switch key.

    ``ShowPanelDelayOfClose`` requires byte 0 == ``0xF8``, takes the delay as
    the 16-bit big-endian seconds in bytes 2..3 (clamped to 3599) and writes
    the DB row for key index ``byte1 + 1`` — so the panel echoes a 0-based
    key index. Whether the *request* key is also 0-based could not be
    confirmed (the form that calls it was not decompiled): UNVERIFIED.
    """

    source: DeviceAddress
    key_echo: int
    seconds: int

    @property
    def minutes(self) -> int:
        return self.seconds // 60

    @property
    def remainder_seconds(self) -> int:
        return self.seconds % 60


@dataclass
class KeyMutex:
    """Result of ``0xE320``: mode-linking flag per key, index 0 = key 1.

    ``FUN_01001750`` walks one byte per key (up to 16, or 6 for device type
    0x40), clamping anything above 1 to 0 for ordinary panels; DDP panels
    take the bytes shifted by one and allow values up to 8. The DDP offset
    (a leading page byte?) is UNVERIFIED.
    """

    source: DeviceAddress
    flags: list[int]


@dataclass
class RelationOptions:
    """Three yes/no options of the button-correlation form (``0xE11A``)."""

    source: DeviceAddress
    option1: bool
    option2: bool
    option3: bool

    def payload(self) -> bytes:
        return bytes([int(self.option1), int(self.option2), int(self.option3)])


@dataclass
class KeyLock:
    """Result of ``0xE120``: one byte, 0/1 on ordinary panels."""

    source: DeviceAddress
    value: int

    @property
    def locked(self) -> bool:
        return self.value != 0


@dataclass
class KeyLockTable:
    """Result of ``0xE124``: 8 data bytes (UNVERIFIED meaning)."""

    source: DeviceAddress
    data: bytes


@dataclass
class RemoteAddress:
    """Result of ``0xE2F0``: the panel's IR remote-control address."""

    source: DeviceAddress
    address: int


# ---------------------------------------------------------------------------
# Builders + parsers, one section per feature
# ---------------------------------------------------------------------------

# -- key modes (0xE008 / 0xE00A) --------------------------------------------


def build_key_mode_read_frame(
    target: DeviceAddress, page: int | None = None, **kw
) -> bytes:
    """``0xE008`` — ``TfrmMain.ReadPanelKeyMode``.

    Payload is empty, or ``[page]`` when the caller passes a page (the app
    does so for paginated DDP panels: ``defDeviceType.IsHasPagination``).
    """
    payload = b"" if page is None else bytes([page & 0xFF])
    return build_frame(KEY_MODE_READ, payload, target, **kw)


def build_key_mode_write_frame(
    target: DeviceAddress, modes: list[int], page: int | None = None, **kw
) -> bytes:
    """``0xE00A`` — ``FUN_0105d630`` / ``FUN_0092040c``.

    Payload is one mode byte per key, key 1 first, for *every* key of the
    panel (the app always sends ``defDeviceType.MaxValue`` bytes, refilled
    from the last ``0xE009`` read), optionally followed by ``[page]``.
    """
    if not modes:
        raise ValueError("modes must not be empty")
    payload = bytes(m & 0xFF for m in modes)
    if page is not None:
        payload += bytes([page & 0xFF])
    return build_frame(KEY_MODE_WRITE, payload, target, **kw)


def parse_key_modes(datagram: bytes, key: bytes | str | None = None) -> KeyModes | None:
    """``0xE009`` — one byte per key (``FUN_0128fdcc``: ``ButtonID = i + 1``)."""
    pkt = _decode_for(datagram, KEY_MODE_READ_RESPONSE, key)
    if pkt is None:
        return None
    return KeyModes(source=pkt.source, modes=list(pkt.payload))


# -- key remarks (0xE004 / 0xE006) ------------------------------------------


def build_key_remark_read_frame(
    target: DeviceAddress, key_no: int, page: int | None = None, **kw
) -> bytes:
    """``0xE004`` — ``TfrmMain.ReadPanelKeyRemark``: ``[key]`` or ``[key, page]``."""
    payload = bytes([key_no & 0xFF])
    if page is not None:
        payload += bytes([page & 0xFF])
    return build_frame(KEY_REMARK_READ, payload, target, **kw)


def build_key_remark_write_frame(
    target: DeviceAddress,
    key_no: int,
    name: str,
    page: int | None = None,
    *,
    pad: bytes = b" ",
    **kw,
) -> bytes:
    """``0xE006`` — ``FUN_00acded4`` / ``FUN_011e3f38``: ``[key, name*20]``.

    ``FUN_011e3f38`` appends ``[page]`` for paginated panels. The name is 20
    bytes; ``FUN_0092087c`` pre-fills the buffer with ``0xFF`` before copying
    the text in, the other two senders leave the allocator's zero fill, so
    the padding byte is not significant — spaces (``pad=b" "``) match how
    device/channel names are stored elsewhere.
    """
    encoded = encode_name(name)
    if pad != b" ":
        text = encoded.rstrip(b" ")
        encoded = text + pad[:1] * (NAME_LEN - len(text))
    payload = bytes([key_no & 0xFF]) + encoded
    if page is not None:
        payload += bytes([page & 0xFF])
    return build_frame(KEY_REMARK_WRITE, payload, target, **kw)


def parse_key_remark(datagram: bytes, key: bytes | str | None = None) -> KeyRemark | None:
    """``0xE005`` — ``[key, name*20(, page)]`` (``FUN_01290688``).

    A key byte of ``0xF5`` means the panel rejected the request; the record
    is then returned with ``name=None`` and ``key=0xF5``.
    """
    pkt = _decode_for(datagram, KEY_REMARK_READ_RESPONSE, key)
    if pkt is None or len(pkt.payload) < 1:
        return None
    p = pkt.payload
    raw = p[1 : 1 + NAME_LEN]
    page = p[1 + NAME_LEN] if len(p) > 1 + NAME_LEN else None
    if p[0] == ACK_FAIL:
        return KeyRemark(pkt.source, p[0], None, raw, page)
    return KeyRemark(pkt.source, p[0], decode_name(raw), raw, page)


# -- LED / backlight level (0xE010 / 0xE012) --------------------------------


def build_led_level_read_frame(target: DeviceAddress, **kw) -> bytes:
    """``0xE010`` — ``TfrmMain.ReadPanelLEDLevel``: empty payload."""
    return build_frame(LED_LEVEL_READ, b"", target, **kw)


def build_led_level_write_frame(target: DeviceAddress, level: LedLevel, **kw) -> bytes:
    """``0xE012`` — 7-byte (``FUN_0105c65c``) or 11-byte
    (``TfrmMain.ModifyPanelLEDLevel``) payload, see :class:`LedLevel`."""
    return build_frame(LED_LEVEL_WRITE, level.payload(), target, **kw)


def build_led_level_simple_write_frame(target: DeviceAddress, level: int, **kw) -> bytes:
    """``0xE012`` with the 1-byte payload ``FUN_006307b0`` sends (the value it
    last received in byte 0 of ``0xE011``)."""
    if not 0 <= level <= 100:
        raise ValueError("level must be 0..100")
    return build_frame(LED_LEVEL_WRITE, bytes([level]), target, **kw)


def parse_led_level(datagram: bytes, key: bytes | str | None = None) -> LedLevel | None:
    """``0xE011`` — ``[backlight, led, flag, b3, b4, b5, b6, ...]``.

    ``wide`` is set when 11 or more payload bytes arrive, in which case
    ``params`` are the four big-endian words at 3..10 (the 0x6D6 family);
    otherwise ``params`` are bytes 3..6 (zero-padded if shorter).
    """
    pkt = _decode_for(datagram, LED_LEVEL_READ_RESPONSE, key)
    if pkt is None or len(pkt.payload) < 1:
        return None
    p = pkt.payload
    backlight = min(p[0], 100)
    led = min(p[1], 100) if len(p) > 1 else 0
    enabled = bool(p[2]) if len(p) > 2 else False
    if len(p) >= 11:
        params = tuple(int.from_bytes(p[i : i + 2], "big") for i in (3, 5, 7, 9))
        wide = True
    else:
        tail = p[3:7].ljust(4, b"\x00")
        params = tuple(tail)
        wide = False
    return LedLevel(backlight, led, enabled, params, wide, pkt.source, bytes(p))


# -- joining buttons / assembled (0xE110 / 0xE112) ---------------------------


def build_assembled_read_frame(target: DeviceAddress, key_no: int, **kw) -> bytes:
    """``0xE110`` — ``TfrmMain.ReadPanelAssembled``: ``[key]``."""
    return build_frame(ASSEMBLED_READ, bytes([key_no & 0xFF]), target, **kw)


def build_assembled_write_frame(
    target: DeviceAddress, key_no: int, joined_to: int, **kw
) -> bytes:
    """``0xE112`` — ``TfrmMain.ModifyPannelAssembled``: ``[key, joined_key]``."""
    return build_frame(
        ASSEMBLED_WRITE, bytes([key_no & 0xFF, joined_to & 0xFF]), target, **kw
    )


def parse_assembled(datagram: bytes, key: bytes | str | None = None) -> Assembled | None:
    """``0xE111`` — ``[status, key, joined_key]``."""
    pkt = _decode_for(datagram, ASSEMBLED_READ_RESPONSE, key)
    if pkt is None or len(pkt.payload) < 3:
        return None
    p = pkt.payload
    return Assembled(pkt.source, key=p[1], joined_to=p[2], status=p[0])


# -- OFF delay for mechanical switch (0xE114 / 0xE116) -----------------------


def build_close_delay_read_frame(target: DeviceAddress, key_no: int, **kw) -> bytes:
    """``0xE114`` — ``TfrmMain.ReadPanelCloseDelay``: ``[key]``.

    See :class:`CloseDelay` about the key index base (UNVERIFIED).
    """
    return build_frame(CLOSE_DELAY_READ, bytes([key_no & 0xFF]), target, **kw)


def build_close_delay_write_frame(
    target: DeviceAddress, key_no: int, seconds: int, **kw
) -> bytes:
    """``0xE116`` — ``TfrmMain.ModifyPannelDelayClose``: ``[key, sec_hi, sec_lo]``
    with ``seconds = minutes * 60 + seconds`` as the form computes it."""
    if not 0 <= seconds <= MAX_CLOSE_DELAY_SECONDS:
        raise ValueError(f"seconds must be 0..{MAX_CLOSE_DELAY_SECONDS}")
    return build_frame(
        CLOSE_DELAY_WRITE, bytes([key_no & 0xFF]) + _u16(seconds), target, **kw
    )


def parse_close_delay(datagram: bytes, key: bytes | str | None = None) -> CloseDelay | None:
    """``0xE115`` — ``[0xF8, key_echo, sec_hi, sec_lo]``; ``None`` unless byte 0 is ``0xF8``."""
    pkt = _decode_for(datagram, CLOSE_DELAY_READ_RESPONSE, key)
    if pkt is None or len(pkt.payload) < 4 or pkt.payload[0] != ACK_OK:
        return None
    p = pkt.payload
    seconds = min(int.from_bytes(p[2:4], "big"), MAX_CLOSE_DELAY_SECONDS)
    return CloseDelay(pkt.source, key_echo=p[1], seconds=seconds)


# -- mode linking / mutex (0xE320 / 0xE322) ----------------------------------


def build_key_mutex_read_frame(
    target: DeviceAddress, page: int | None = None, **kw
) -> bytes:
    """``0xE320`` — ``TfrmMain.ReadPanelKeyMutex``: empty or ``[page]``."""
    payload = b"" if page is None else bytes([page & 0xFF])
    return build_frame(KEY_MUTEX_READ, payload, target, **kw)


def build_key_mutex_write_frame(
    target: DeviceAddress, flags: list[int], **kw
) -> bytes:
    """``0xE322`` — ``TfrmMain.ModifyPannelKeyMutex``: one byte per key.

    ``FUN_0062f298`` sends the 8-byte buffer the last ``0xE321`` filled, so
    send a flag for every key of the panel (0 = not linked, 1 = linked; DDP
    panels accept 0..8).
    """
    if not flags:
        raise ValueError("flags must not be empty")
    return build_frame(KEY_MUTEX_WRITE, bytes(f & 0xFF for f in flags), target, **kw)


def parse_key_mutex(
    datagram: bytes, key: bytes | str | None = None, *, ddp: bool = False
) -> KeyMutex | None:
    """``0xE321`` — one byte per key; ``ddp=True`` skips the leading byte
    the DDP branch of ``FUN_01001750`` skips (UNVERIFIED)."""
    pkt = _decode_for(datagram, KEY_MUTEX_READ_RESPONSE, key)
    if pkt is None:
        return None
    data = pkt.payload[1:] if ddp else pkt.payload
    return KeyMutex(pkt.source, flags=list(data))


# -- button correlation matrix (0xE118 / 0xE11E) -----------------------------


def pack_relation_matrix(rows: list[list[bool]]) -> bytes:
    """Pack a related-buttons matrix the way ``FUN_00972af4`` does.

    Each grid row becomes ``ceil(cols / 8)`` bytes, then every byte is
    inverted (the app stores ``~byte``), so a *set* relation is a **0** bit.
    Bit order inside a byte (LSB = first column) is UNVERIFIED.
    """
    out = bytearray()
    for row in rows:
        for start in range(0, len(row), 8):
            b = 0
            for i, cell in enumerate(row[start : start + 8]):
                if cell:
                    b |= 1 << i
            out.append((~b) & 0xFF)
    return bytes(out)


def build_key_relation_frame(
    target: DeviceAddress,
    chunk_index: int,
    chunk: bytes,
    *,
    multi_channel: bool = False,
    ddp: bool = False,
    **kw,
) -> bytes:
    """``0xE118`` / ``0xE11E`` — ``FUN_0105c8c4`` via ``FUN_00972af4``.

    Payload (19 bytes): ``[2, multi_channel, chunk_index, matrix[16]]``. The
    form splits :func:`pack_relation_matrix` output into 16-byte chunks and
    sends one frame per chunk, waiting for the ack (``0xE119``/``0xE11F``)
    between them. Byte 0 is the constant ``2`` in the decompile (purpose
    unknown). ``ddp=True`` selects ``0xE11E`` (types 0x1C3/0x25C/0x25D and a
    bitmap of newer types in the app).
    """
    if len(chunk) != KEY_RELATION_CHUNK_LEN:
        raise ValueError(f"chunk must be {KEY_RELATION_CHUNK_LEN} bytes")
    payload = bytes([2, 1 if multi_channel else 0, chunk_index & 0xFF]) + bytes(chunk)
    opcode = KEY_RELATION_WRITE_DDP if ddp else KEY_RELATION_WRITE
    return build_frame(opcode, payload, target, **kw)


def relation_chunks(matrix: bytes) -> list[bytes]:
    """Split packed matrix bytes into zero-padded 16-byte chunks."""
    chunks = []
    for start in range(0, len(matrix), KEY_RELATION_CHUNK_LEN):
        chunks.append(matrix[start : start + KEY_RELATION_CHUNK_LEN].ljust(
            KEY_RELATION_CHUNK_LEN, b"\x00"
        ))
    return chunks


# -- correlation options (0xE11A / 0xE11C) -----------------------------------


def build_relation_options_read_frame(target: DeviceAddress, **kw) -> bytes:
    """``0xE11A`` — ``FUN_01058220``: empty payload."""
    return build_frame(RELATION_OPTIONS_READ, b"", target, **kw)


def build_relation_options_write_frame(
    target: DeviceAddress, option1: bool, option2: bool, option3: bool, **kw
) -> bytes:
    """``0xE11C`` — ``FUN_010584b8``: ``[o1, o2, o3]`` (each 0/1)."""
    return build_frame(
        RELATION_OPTIONS_WRITE,
        bytes([int(option1), int(option2), int(option3)]),
        target,
        **kw,
    )


def parse_relation_options(
    datagram: bytes, key: bytes | str | None = None
) -> RelationOptions | None:
    """``0xE11B`` — ``[o1, o2, o3]``."""
    pkt = _decode_for(datagram, RELATION_OPTIONS_READ_RESPONSE, key)
    if pkt is None or len(pkt.payload) < 3:
        return None
    p = pkt.payload
    return RelationOptions(pkt.source, bool(p[0]), bool(p[1]), bool(p[2]))


# -- button lock (0xE120 / 0xE122 / 0xE124) ----------------------------------


def build_key_lock_read_frame(target: DeviceAddress, **kw) -> bytes:
    """``0xE120`` — ``FUN_011ec114`` / ``FUN_010ce434``: empty payload."""
    return build_frame(KEY_LOCK_READ, b"", target, **kw)


def build_key_lock_write_frame(target: DeviceAddress, value: int, **kw) -> bytes:
    """``0xE122`` — ``FUN_011ec3a0``: ``[value]``."""
    return build_frame(KEY_LOCK_WRITE, bytes([value & 0xFF]), target, **kw)


def build_key_lock_table_read_frame(target: DeviceAddress, **kw) -> bytes:
    """``0xE124`` — no sender decompiled; empty payload assumed (UNVERIFIED)."""
    return build_frame(KEY_LOCK_TABLE_READ, b"", target, **kw)


def parse_key_lock(datagram: bytes, key: bytes | str | None = None) -> KeyLock | None:
    """``0xE121`` — ``[value]``."""
    pkt = _decode_for(datagram, KEY_LOCK_READ_RESPONSE, key)
    if pkt is None or len(pkt.payload) < 1:
        return None
    return KeyLock(pkt.source, pkt.payload[0])


def parse_key_lock_table(
    datagram: bytes, key: bytes | str | None = None
) -> KeyLockTable | None:
    """``0xE125`` — 8 data bytes (``FUN_0100b7bc`` stores bytes 0..7)."""
    pkt = _decode_for(datagram, KEY_LOCK_TABLE_READ_RESPONSE, key)
    if pkt is None:
        return None
    return KeyLockTable(pkt.source, bytes(pkt.payload[:8]))


# -- remote-control address (0xE2F0) -----------------------------------------


def build_remote_addr_read_frame(target: DeviceAddress, **kw) -> bytes:
    """``0xE2F0`` — ``TfrmMain.ReadRemoteAddr``: empty payload."""
    return build_frame(REMOTE_ADDR_READ, b"", target, **kw)


def parse_remote_addr(
    datagram: bytes, key: bytes | str | None = None
) -> RemoteAddress | None:
    """``0xE2F1`` — ``[addr_hi, addr_lo]`` (``FUN_0100b7bc`` stores a 16-bit value)."""
    pkt = _decode_for(datagram, REMOTE_ADDR_READ_RESPONSE, key)
    if pkt is None or len(pkt.payload) < 2:
        return None
    return RemoteAddress(pkt.source, int.from_bytes(pkt.payload[:2], "big"))


# -- acks --------------------------------------------------------------------

ACK_OPCODES = frozenset(
    {
        KEY_REMARK_WRITE_RESPONSE,
        KEY_MODE_WRITE_RESPONSE,
        LED_LEVEL_WRITE_RESPONSE,
        ASSEMBLED_WRITE_RESPONSE,
        CLOSE_DELAY_WRITE_RESPONSE,
        KEY_RELATION_WRITE_RESPONSE,
        KEY_RELATION_WRITE_DDP_RESPONSE,
        RELATION_OPTIONS_WRITE_RESPONSE,
        KEY_LOCK_WRITE_RESPONSE,
        KEY_MUTEX_WRITE_RESPONSE,
    }
)


def parse_ack(datagram: bytes, key: bytes | str | None = None) -> Ack | None:
    """Decode any of the write acks in :data:`ACK_OPCODES`.

    ``ok`` is true when ``0xF8`` is in byte 0 or byte 1 (see module notes),
    or when the ack has no payload at all (``0xE007``/``0xE11D`` are accepted
    by the app on opcode alone).
    """
    pkt = decode_frame(datagram, key)
    if pkt is None or pkt.opcode not in ACK_OPCODES:
        return None
    p = pkt.payload
    ok = (not p) or (ACK_OK in p[:2] and ACK_FAIL not in p[:1])
    return Ack(pkt.opcode, pkt.source, ok, bytes(p))


# ---------------------------------------------------------------------------
# Async exchange
# ---------------------------------------------------------------------------


class _RawBus(Protocol):
    def send_raw(self, frame: bytes) -> None: ...

    def on_raw(
        self, callback: Callable[[bytes, tuple[str, int]], None]
    ) -> Callable[[], None]: ...


async def vendor_exchange(
    bus: _RawBus,
    frame: bytes,
    want_opcode: int,
    predicate: Callable[[Packet], bool] | None = None,
    *,
    timeout: float = 2.0,
    retries: int = 3,
    key: bytes | str | None = None,
) -> Packet | None:
    """Send a pre-built frame and await the matching reply, app-style.

    Up to ``retries`` attempts of ``timeout`` seconds each (Smart Cloud: 3 x
    ~2 s), because these frames collide with the panel's periodic
    broadcasts. Every raw datagram is decoded (vendor or plain) and accepted
    when its opcode is ``want_opcode`` and ``predicate`` (if any) passes.
    Returns the decoded :class:`Packet`, or ``None`` after the last timeout.
    """
    for _ in range(retries):
        loop = asyncio.get_running_loop()
        future: asyncio.Future[Packet] = loop.create_future()

        def on_raw(data: bytes, _addr: tuple[str, int]) -> None:
            if future.done():
                return
            pkt = decode_frame(data, key)
            if pkt is None or pkt.opcode != want_opcode:
                return
            if predicate is not None and not predicate(pkt):
                return
            future.set_result(pkt)

        unsubscribe = bus.on_raw(on_raw)
        try:
            bus.send_raw(frame)
            return await asyncio.wait_for(future, timeout)
        except (TimeoutError, asyncio.TimeoutError):
            continue
        finally:
            unsubscribe()
    return None


def _from(panel: DeviceAddress) -> Callable[[Packet], bool]:
    """Predicate: reply comes from the panel we addressed (unless broadcast)."""
    if panel.is_broadcast:
        return lambda _pkt: True
    return lambda pkt: pkt.source == panel


async def _exchange_ack(
    bus: _RawBus,
    frame: bytes,
    panel: DeviceAddress,
    want_opcode: int,
    **xkw,
) -> bool:
    pkt = await vendor_exchange(bus, frame, want_opcode, _from(panel), **xkw)
    if pkt is None:
        return False
    ack = parse_ack(pkt.encode(), None)
    return bool(ack and ack.ok)


# The builders take frame keyword args (vendor/source/...); the exchange takes
# timeout/retries/key. Split one **kw dict into the two.
_FRAME_KEYS = ("vendor", "source", "source_type", "source_ip", "key")
_XCHG_KEYS = ("timeout", "retries", "key")


def _split(kw: dict) -> tuple[dict, dict]:
    fkw = {k: v for k, v in kw.items() if k in _FRAME_KEYS}
    xkw = {k: v for k, v in kw.items() if k in _XCHG_KEYS}
    unknown = set(kw) - set(_FRAME_KEYS) - set(_XCHG_KEYS)
    if unknown:
        raise TypeError(f"unexpected keyword arguments: {sorted(unknown)}")
    return fkw, xkw


async def read_key_modes(
    bus: _RawBus, panel: DeviceAddress, page: int | None = None, **kw
) -> KeyModes | None:
    fkw, xkw = _split(kw)
    pkt = await vendor_exchange(
        bus,
        build_key_mode_read_frame(panel, page, **fkw),
        KEY_MODE_READ_RESPONSE,
        _from(panel),
        **xkw,
    )
    return parse_key_modes(pkt.encode()) if pkt else None


async def write_key_modes(
    bus: _RawBus,
    panel: DeviceAddress,
    modes: list[int],
    page: int | None = None,
    **kw,
) -> bool:
    fkw, xkw = _split(kw)
    return await _exchange_ack(
        bus,
        build_key_mode_write_frame(panel, modes, page, **fkw),
        panel,
        KEY_MODE_WRITE_RESPONSE,
        **xkw,
    )


async def read_key_remark(
    bus: _RawBus, panel: DeviceAddress, key_no: int, page: int | None = None, **kw
) -> KeyRemark | None:
    fkw, xkw = _split(kw)
    pkt = await vendor_exchange(
        bus,
        build_key_remark_read_frame(panel, key_no, page, **fkw),
        KEY_REMARK_READ_RESPONSE,
        lambda p: _from(panel)(p) and len(p.payload) > 0 and p.payload[0] in (key_no, ACK_FAIL),
        **xkw,
    )
    return parse_key_remark(pkt.encode()) if pkt else None


async def read_key_remarks(
    bus: _RawBus, panel: DeviceAddress, count: int, page: int | None = None, **kw
) -> list[str | None]:
    """Labels of keys 1..count (``None`` where no reply came)."""
    names: list[str | None] = []
    for key_no in range(1, count + 1):
        rec = await read_key_remark(bus, panel, key_no, page, **kw)
        names.append(rec.name if rec else None)
        await asyncio.sleep(0.05)
    return names


async def write_key_remark(
    bus: _RawBus,
    panel: DeviceAddress,
    key_no: int,
    name: str,
    page: int | None = None,
    **kw,
) -> bool:
    fkw, xkw = _split(kw)
    return await _exchange_ack(
        bus,
        build_key_remark_write_frame(panel, key_no, name, page, **fkw),
        panel,
        KEY_REMARK_WRITE_RESPONSE,
        **xkw,
    )


async def read_led_level(bus: _RawBus, panel: DeviceAddress, **kw) -> LedLevel | None:
    fkw, xkw = _split(kw)
    pkt = await vendor_exchange(
        bus,
        build_led_level_read_frame(panel, **fkw),
        LED_LEVEL_READ_RESPONSE,
        _from(panel),
        **xkw,
    )
    return parse_led_level(pkt.encode()) if pkt else None


async def write_led_level(
    bus: _RawBus, panel: DeviceAddress, level: LedLevel, **kw
) -> bool:
    fkw, xkw = _split(kw)
    return await _exchange_ack(
        bus,
        build_led_level_write_frame(panel, level, **fkw),
        panel,
        LED_LEVEL_WRITE_RESPONSE,
        **xkw,
    )


async def read_assembled(
    bus: _RawBus, panel: DeviceAddress, key_no: int, **kw
) -> Assembled | None:
    fkw, xkw = _split(kw)
    pkt = await vendor_exchange(
        bus,
        build_assembled_read_frame(panel, key_no, **fkw),
        ASSEMBLED_READ_RESPONSE,
        lambda p: _from(panel)(p) and len(p.payload) >= 2 and p.payload[1] == key_no,
        **xkw,
    )
    return parse_assembled(pkt.encode()) if pkt else None


async def write_assembled(
    bus: _RawBus, panel: DeviceAddress, key_no: int, joined_to: int, **kw
) -> bool:
    fkw, xkw = _split(kw)
    return await _exchange_ack(
        bus,
        build_assembled_write_frame(panel, key_no, joined_to, **fkw),
        panel,
        ASSEMBLED_WRITE_RESPONSE,
        **xkw,
    )


async def read_close_delay(
    bus: _RawBus, panel: DeviceAddress, key_no: int, **kw
) -> CloseDelay | None:
    fkw, xkw = _split(kw)
    pkt = await vendor_exchange(
        bus,
        build_close_delay_read_frame(panel, key_no, **fkw),
        CLOSE_DELAY_READ_RESPONSE,
        _from(panel),
        **xkw,
    )
    return parse_close_delay(pkt.encode()) if pkt else None


async def write_close_delay(
    bus: _RawBus, panel: DeviceAddress, key_no: int, seconds: int, **kw
) -> bool:
    fkw, xkw = _split(kw)
    return await _exchange_ack(
        bus,
        build_close_delay_write_frame(panel, key_no, seconds, **fkw),
        panel,
        CLOSE_DELAY_WRITE_RESPONSE,
        **xkw,
    )


async def read_key_mutex(
    bus: _RawBus,
    panel: DeviceAddress,
    page: int | None = None,
    *,
    ddp: bool = False,
    **kw,
) -> KeyMutex | None:
    fkw, xkw = _split(kw)
    pkt = await vendor_exchange(
        bus,
        build_key_mutex_read_frame(panel, page, **fkw),
        KEY_MUTEX_READ_RESPONSE,
        _from(panel),
        **xkw,
    )
    return parse_key_mutex(pkt.encode(), ddp=ddp) if pkt else None


async def write_key_mutex(
    bus: _RawBus, panel: DeviceAddress, flags: list[int], **kw
) -> bool:
    fkw, xkw = _split(kw)
    return await _exchange_ack(
        bus,
        build_key_mutex_write_frame(panel, flags, **fkw),
        panel,
        KEY_MUTEX_WRITE_RESPONSE,
        **xkw,
    )


async def write_key_relation(
    bus: _RawBus,
    panel: DeviceAddress,
    matrix: bytes,
    *,
    multi_channel: bool = False,
    ddp: bool = False,
    **kw,
) -> bool:
    """Send a packed correlation matrix chunk by chunk, stopping on the
    first missing ack (as ``FUN_00972af4`` does)."""
    fkw, xkw = _split(kw)
    want = KEY_RELATION_WRITE_DDP_RESPONSE if ddp else KEY_RELATION_WRITE_RESPONSE
    for index, chunk in enumerate(relation_chunks(matrix)):
        frame = build_key_relation_frame(
            panel, index, chunk, multi_channel=multi_channel, ddp=ddp, **fkw
        )
        if not await _exchange_ack(bus, frame, panel, want, **xkw):
            return False
    return True


async def read_relation_options(
    bus: _RawBus, panel: DeviceAddress, **kw
) -> RelationOptions | None:
    fkw, xkw = _split(kw)
    pkt = await vendor_exchange(
        bus,
        build_relation_options_read_frame(panel, **fkw),
        RELATION_OPTIONS_READ_RESPONSE,
        _from(panel),
        **xkw,
    )
    return parse_relation_options(pkt.encode()) if pkt else None


async def write_relation_options(
    bus: _RawBus,
    panel: DeviceAddress,
    option1: bool,
    option2: bool,
    option3: bool,
    **kw,
) -> bool:
    fkw, xkw = _split(kw)
    return await _exchange_ack(
        bus,
        build_relation_options_write_frame(panel, option1, option2, option3, **fkw),
        panel,
        RELATION_OPTIONS_WRITE_RESPONSE,
        **xkw,
    )


async def read_key_lock(bus: _RawBus, panel: DeviceAddress, **kw) -> KeyLock | None:
    fkw, xkw = _split(kw)
    pkt = await vendor_exchange(
        bus,
        build_key_lock_read_frame(panel, **fkw),
        KEY_LOCK_READ_RESPONSE,
        _from(panel),
        **xkw,
    )
    return parse_key_lock(pkt.encode()) if pkt else None


async def write_key_lock(bus: _RawBus, panel: DeviceAddress, value: int, **kw) -> bool:
    fkw, xkw = _split(kw)
    return await _exchange_ack(
        bus,
        build_key_lock_write_frame(panel, value, **fkw),
        panel,
        KEY_LOCK_WRITE_RESPONSE,
        **xkw,
    )


async def read_key_lock_table(
    bus: _RawBus, panel: DeviceAddress, **kw
) -> KeyLockTable | None:
    fkw, xkw = _split(kw)
    pkt = await vendor_exchange(
        bus,
        build_key_lock_table_read_frame(panel, **fkw),
        KEY_LOCK_TABLE_READ_RESPONSE,
        _from(panel),
        **xkw,
    )
    return parse_key_lock_table(pkt.encode()) if pkt else None


async def read_remote_addr(
    bus: _RawBus, panel: DeviceAddress, **kw
) -> RemoteAddress | None:
    fkw, xkw = _split(kw)
    pkt = await vendor_exchange(
        bus,
        build_remote_addr_read_frame(panel, **fkw),
        REMOTE_ADDR_READ_RESPONSE,
        _from(panel),
        **xkw,
    )
    return parse_remote_addr(pkt.encode()) if pkt else None


# ---------------------------------------------------------------------------
# Reading every key function entry (ReadAllPanelKeyFunConfig)
# ---------------------------------------------------------------------------


async def read_all_key_functions(
    bus: _RawBus,
    panel: DeviceAddress,
    keys: int,
    pages: int,
    *,
    gap: float = 0.3,
    stop_on_failure: bool = True,
    **kw,
) -> dict[tuple[int, int], dict | None]:
    """Read ``keys x pages`` function entries with ``0xE000``.

    Mirrors ``TfrmMain.ReadAllPanelKeyFunConfig``: it calls the single-entry
    reader (``FUN_0105d948`` — payload ``[key, page]``) once per entry with
    ``Sleep(300)`` between them and aborts on the first failure. The device
    does not report how many entries exist: the app takes the key count from
    ``defDeviceType.MaxValue`` (:func:`pysmartg4.device_catalog.channel_count`
    for panels) and the function slots per key from its own tables
    (``IsHas99KeyObject`` panels expose up to 99 "function no." entries).
    Returns ``{(key, page): parsed_or_None}``.
    """
    from . import vendor_program  # local import: keeps module load light

    fkw, xkw = _split(kw)
    fkw.pop("vendor", None)  # vendor_program builds vendor frames only
    out: dict[tuple[int, int], dict | None] = {}
    for key_no in range(1, keys + 1):
        for page in range(pages):
            frame = vendor_program.build_read_frame(key_no, page, panel, **fkw)
            pkt = await vendor_exchange(
                bus,
                frame,
                vendor_program.READ_RESPONSE,
                lambda p, k=key_no, g=page: _from(panel)(p)
                and p.payload[:2] == bytes([k, g]),
                **xkw,
            )
            parsed = vendor_program.parse_response(to_vendor_frame(pkt.encode())) if pkt else None
            out[(key_no, page)] = parsed
            if parsed is None and stop_on_failure:
                return out
            await asyncio.sleep(gap)
    return out


__all__ = [
    # opcodes
    "KEY_REMARK_READ", "KEY_REMARK_READ_RESPONSE", "KEY_REMARK_WRITE",
    "KEY_REMARK_WRITE_RESPONSE", "KEY_MODE_READ", "KEY_MODE_READ_RESPONSE",
    "KEY_MODE_WRITE", "KEY_MODE_WRITE_RESPONSE", "LED_LEVEL_READ",
    "LED_LEVEL_READ_RESPONSE", "LED_LEVEL_WRITE", "LED_LEVEL_WRITE_RESPONSE",
    "ASSEMBLED_READ", "ASSEMBLED_READ_RESPONSE", "ASSEMBLED_WRITE",
    "ASSEMBLED_WRITE_RESPONSE", "CLOSE_DELAY_READ", "CLOSE_DELAY_READ_RESPONSE",
    "CLOSE_DELAY_WRITE", "CLOSE_DELAY_WRITE_RESPONSE", "KEY_RELATION_WRITE",
    "KEY_RELATION_WRITE_RESPONSE", "KEY_RELATION_WRITE_DDP",
    "KEY_RELATION_WRITE_DDP_RESPONSE", "RELATION_OPTIONS_READ",
    "RELATION_OPTIONS_READ_RESPONSE", "RELATION_OPTIONS_WRITE",
    "RELATION_OPTIONS_WRITE_RESPONSE", "KEY_LOCK_READ", "KEY_LOCK_READ_RESPONSE",
    "KEY_LOCK_WRITE", "KEY_LOCK_WRITE_RESPONSE", "KEY_LOCK_TABLE_READ",
    "KEY_LOCK_TABLE_READ_RESPONSE", "REMOTE_ADDR_READ", "REMOTE_ADDR_READ_RESPONSE",
    "KEY_MUTEX_READ", "KEY_MUTEX_READ_RESPONSE", "KEY_MUTEX_WRITE",
    "KEY_MUTEX_WRITE_RESPONSE", "ACK_OK", "ACK_FAIL", "ACK_OPCODES",
    "MAX_CLOSE_DELAY_SECONDS", "KEY_RELATION_CHUNK_LEN",
    # key modes
    "KEY_MODES", "KEY_MODES_LINKABLE", "KEY_MODES_COMBINATION", "key_mode_name",
    # records
    "Ack", "KeyModes", "KeyRemark", "LedLevel", "Assembled", "CloseDelay",
    "KeyMutex", "RelationOptions", "KeyLock", "KeyLockTable", "RemoteAddress",
    # plumbing
    "build_frame", "decode_frame", "vendor_exchange",
    # builders / parsers
    "build_key_mode_read_frame", "build_key_mode_write_frame", "parse_key_modes",
    "build_key_remark_read_frame", "build_key_remark_write_frame", "parse_key_remark",
    "build_led_level_read_frame", "build_led_level_write_frame",
    "build_led_level_simple_write_frame", "parse_led_level",
    "build_assembled_read_frame", "build_assembled_write_frame", "parse_assembled",
    "build_close_delay_read_frame", "build_close_delay_write_frame", "parse_close_delay",
    "build_key_mutex_read_frame", "build_key_mutex_write_frame", "parse_key_mutex",
    "pack_relation_matrix", "relation_chunks", "build_key_relation_frame",
    "build_relation_options_read_frame", "build_relation_options_write_frame",
    "parse_relation_options", "build_key_lock_read_frame", "build_key_lock_write_frame",
    "build_key_lock_table_read_frame", "parse_key_lock", "parse_key_lock_table",
    "build_remote_addr_read_frame", "parse_remote_addr", "parse_ack",
    # async helpers
    "read_key_modes", "write_key_modes", "read_key_remark", "read_key_remarks",
    "write_key_remark", "read_led_level", "write_led_level", "read_assembled",
    "write_assembled", "read_close_delay", "write_close_delay", "read_key_mutex",
    "write_key_mutex", "write_key_relation", "read_relation_options",
    "write_relation_options", "read_key_lock", "write_key_lock",
    "read_key_lock_table", "read_remote_addr", "read_all_key_functions",
]
