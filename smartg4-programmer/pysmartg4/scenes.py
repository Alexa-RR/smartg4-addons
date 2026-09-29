"""Scenes ("Que") and sequences ("Series") stored inside dimmer / relay modules.

Recovered from the Ghidra decompilation of the vendor's "Smart Cloud
Configuration V16.38" tool (function names below are its Delphi debug
symbols) and cross-checked against the official SBUS.dll SDK opcode table
(``docs/opcodes.json``). All frames are PLAIN 0xAAAA S-BUS frames.

Vocabulary: the vendor calls an *area/zone* "Zone", a *scene* "Que" and a
*sequence* "Series". A module keeps, per zone, up to N scenes (each a level
per channel plus a running/fade time) and a pool of sequences; a sequence
is an ordered list of *steps*, each "go to scene X, wait T", with a mode
(forward / backward / both / random) and a repeat count.

Confidence, per family (details in ``docs/features/module_config.md``):

=============================  ====================  ==========================
feature                        request (vendor)      response / layout
=============================  ====================  ==========================
scene levels (read)            0x0000 / 0x10FE       0x0001 / 0x10FF     HIGH/MED
scene levels (write)           0x0008 / 0x1001       0x0009              HIGH
scene preview / end preview    0xF074 / 0xF076       - / 0xF077          MED/LOW
scene remark                   0xF024 / 0xF026       0xF025 / 0xF027     HIGH
zone remark                    0xF00A / 0xF00C       0xF00B / 0xF00D     HIGH (live)
running scene of every zone    0xF078 (SDK)          0xF079              LOW
zones that own sequences       0x001C? / 0x001E      0x001D / 0x001F     LOW/MED
sequence config                0x0012 / 0x0018       0x0013 / 0x0019     MED
sequences of a zone (vendor)   0x0291                0x0292              LOW
sequence total per zone        0xF067                0xF068              MED
sequence step                  0x0014 / 0x0016       0x0015 / 0x0017     HIGH
add / delete sequence          0xD006 / 0xF072       0xD007 / 0xF073     MED/HIGH
free / restore sequence slot   0xF06B / 0xF06E       0xF06C / 0xF06F     HIGH
free sequence slots left       0xF070                0xF071              HIGH/LOW
sequence remark                0xF028 / 0xF030       0xF029 / 0xF031     HIGH
=============================  ====================  ==========================

Not implemented here on purpose: scene *trigger* (0x0002) and sequence
*trigger* (0x001A) already live in :mod:`pysmartg4.commands` / the bus.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any, Sequence

from .bus import SmartG4Bus
from .module_config import DEFAULT_SOURCE, _acked, _packet, _reply
from .naming import NAME_LEN, clean, decode_name, encode_name
from .packet import DeviceAddress, Packet

# ---------------------------------------------------------------------------
# Opcodes
# ---------------------------------------------------------------------------

# Scene levels. SDK Read_Scene_Model 0x0000 [zone, scene] → 0x0001. The
# vendor's TfrmMain.ReadQueOfZone only ever sends the 16-bit-scene form
# 0x10FE [zone, scene_hi, scene_lo]; TfrmMain.ShowQueLight accepts either
# 0x10FF (time in tenths) or the plain reply (time in seconds).
OP_READ_SCENE = 0x0000
OP_READ_SCENE_RESP = 0x0001
OP_READ_SCENE_LONG = 0x10FE
OP_READ_SCENE_LONG_RESP = 0x10FF
# TfrmMain.ModifyQueOfZone: plain 0x0008 → 0x0009 (SDK Modify_Scene_Model);
# "long" 0x1001 (length-prefixed, 16-bit scene, tenths) → also 0x0009.
OP_WRITE_SCENE = 0x0008
OP_WRITE_SCENE_RESP = 0x0009
OP_WRITE_SCENE_LONG = 0x1001
# TfrmMain.PreviewQue ("ON-site run scene", frmEditQueBright 01806) — the
# vendor does not wait for a reply. TfrmMain.EndPreviewQue 0xF076 → 0xF077
# ("Terminating scene on-site run").
OP_PREVIEW_SCENE = 0xF074
OP_PREVIEW_SCENE_RESP = 0xF075  # UNVERIFIED: never awaited by the vendor
OP_END_PREVIEW_SCENE = 0xF076
OP_END_PREVIEW_SCENE_RESP = 0xF077
# TfrmMain.ReadQueRemark / ModifyQueRemark (SDK Read/Write_Remark_Zone_Scene)
OP_READ_SCENE_REMARK = 0xF024
OP_READ_SCENE_REMARK_RESP = 0xF025
OP_WRITE_SCENE_REMARK = 0xF026
OP_WRITE_SCENE_REMARK_RESP = 0xF027
# TfrmMain.ReadZoneRemark / ModifyZoneRemark (SDK Read/Write_Remark_One_Zone;
# both already registered in pysmartg4.commands, confirmed live)
OP_READ_ZONE_REMARK = 0xF00A
OP_READ_ZONE_REMARK_RESP = 0xF00B
OP_WRITE_ZONE_REMARK = 0xF00C
OP_WRITE_ZONE_REMARK_RESP = 0xF00D
# SDK Read_Scene_All_Zones_Running (not used by the vendor tool)
OP_READ_RUNNING_SCENES = 0xF078
OP_READ_RUNNING_SCENES_RESP = 0xF079

# Sequences ("Series")
# TfrmMain.ReadWhichZoneHasSeries: empty payload, waits for 0x001D. The
# request opcode immediate is not visible in the decompile (passed in a
# register); 0x001C is the natural even/odd pairing.  # UNVERIFIED opcode
OP_READ_ZONES_WITH_SEQUENCES = 0x001C
OP_READ_ZONES_WITH_SEQUENCES_RESP = 0x001D
# TfrmMain.ModifyWhichZoneHasSeries [zone] → 0x001F
OP_WRITE_ZONE_HAS_SEQUENCES = 0x001E
OP_WRITE_ZONE_HAS_SEQUENCES_RESP = 0x001F
# SDK Read_Sequence_Running 0x0012 [zone, sequence] → 0x0013; the SDK names
# the 0x0019 ack "MODIFY_SEQUENCE_RUNNING", i.e. TfrmMain.ModifySeries 0x0018.
OP_READ_SEQUENCE = 0x0012
OP_READ_SEQUENCE_RESP = 0x0013
OP_WRITE_SEQUENCE = 0x0018
OP_WRITE_SEQUENCE_RESP = 0x0019
# TfrmMain.ReadSeriesOfZone (vendor-only, empty payload) → 0x0292
OP_READ_SEQUENCES_OF_ZONE = 0x0291
OP_READ_SEQUENCES_OF_ZONE_RESP = 0x0292
# TfrmMain.ReadSeriesTotal [zone] → 0xF068 ("Reading total Sequences")
OP_READ_SEQUENCE_TOTAL = 0xF067
OP_READ_SEQUENCE_TOTAL_RESP = 0xF068
# TfrmMain.ReadStepOfSeries / ModifyStepOfSeries (SDK Read/Modify_Sequence_Detail)
OP_READ_STEP = 0x0014
OP_READ_STEP_RESP = 0x0015
OP_WRITE_STEP = 0x0016
OP_WRITE_STEP_RESP = 0x0017
# TfrmMain.AddNewSeries / DeleteSeries / FreeRoomSeries / ResumeSeries /
# ReadSeriesLeftCountRoom
OP_ADD_SEQUENCE = 0xD006
OP_ADD_SEQUENCE_RESP = 0xD007
OP_DELETE_SEQUENCE = 0xF072
OP_DELETE_SEQUENCE_RESP = 0xF073
OP_FREE_SEQUENCE = 0xF06B          # "Inactivate sequence space" (frmFreeRoomSeries)
OP_FREE_SEQUENCE_RESP = 0xF06C
OP_RESTORE_SEQUENCE = 0xF06E       # "Restore inactivated sequence" (frmResumeSeries)
OP_RESTORE_SEQUENCE_RESP = 0xF06F
OP_READ_FREE_SEQUENCE_SLOTS = 0xF070   # "Reading surplus Sequence space"
OP_READ_FREE_SEQUENCE_SLOTS_RESP = 0xF071
# TfrmMain.ReadSeriesRemark (SDK Read_Sequence_Remark) / ModifySeriesRemark
OP_READ_SEQUENCE_REMARK = 0xF028
OP_READ_SEQUENCE_REMARK_RESP = 0xF029
OP_WRITE_SEQUENCE_REMARK = 0xF030
OP_WRITE_SEQUENCE_REMARK_RESP = 0xF031

# lang_en.ini [SequenceMode]
SEQUENCE_MODES: dict[int, str] = {
    0: "Forward",
    1: "Backward",
    2: "Forward and backward",
    3: "Random",
}
SEQUENCE_TIMES_UNLIMITED = 0   # TfrmMain.ShowSeries prints "Unlimited" for 0; else 1..99
# lang_en.ini [SequenceStatus]
SEQUENCE_STATUS: dict[int, str] = {0: "free", 1: "usable"}

MAX_RUNTIME_SECONDS = 0xFFFF
MAX_STEP_TENTHS = 0xFFFF


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass
class SceneLevels:
    """Stored contents of one scene: channel levels (%) and the fade/run time."""

    zone: int
    scene: int
    runtime: float                 # seconds; tenth-second resolution on 0x10FF
    levels: list[int]              # percent per channel, channel 1 first

    def as_dict(self) -> dict[str, Any]:
        return {"zone": self.zone, "scene": self.scene, "runtime": self.runtime, "levels": self.levels}


@dataclass
class SequenceConfig:
    zone: int
    sequence: int
    mode: int                      # SEQUENCE_MODES key
    times: int                     # 0 = unlimited, else 1..99 repetitions
    steps: int                     # number of steps ("Step totality")

    def as_dict(self) -> dict[str, Any]:
        return {
            "zone": self.zone,
            "sequence": self.sequence,
            "mode": self.mode,
            "mode_name": SEQUENCE_MODES.get(self.mode, f"mode {self.mode}"),
            "times": self.times,
            "steps": self.steps,
        }


@dataclass
class SequenceStep:
    zone: int
    sequence: int
    step: int
    scene: int
    interval: float                # seconds, tenth-second resolution

    def as_dict(self) -> dict[str, Any]:
        return {
            "zone": self.zone,
            "sequence": self.sequence,
            "step": self.step,
            "scene": self.scene,
            "interval": self.interval,
        }


def _byte(value: int, name: str) -> int:
    if not 0 <= int(value) <= 255:
        raise ValueError(f"{name} {value} not in 0..255")
    return int(value)


def _word(value: int, name: str) -> bytes:
    if not 0 <= int(value) <= 0xFFFF:
        raise ValueError(f"{name} {value} not in 0..65535")
    return int(value).to_bytes(2, "big")


def _levels(levels: Sequence[int]) -> bytes:
    if not levels:
        raise ValueError("need at least one channel level")
    out = bytearray()
    for i, level in enumerate(levels, start=1):
        if not 0 <= int(level) <= 100:
            raise ValueError(f"channel {i} level {level} not in 0..100")
        out.append(int(level))
    return bytes(out)


def _tenths(seconds: float) -> int:
    """Seconds → tenths of a second, the unit of the 16-bit step/scene timers.

    TfrmMain.ModifyStepOfSeries computes ``minutes * 600 + seconds * 10 +
    tenths``; ModifyQueOfZone's long form does the same.
    """
    tenths = round(float(seconds) * 10)
    if not 0 <= tenths <= MAX_STEP_TENTHS:
        raise ValueError(f"time {seconds}s out of range (max {MAX_STEP_TENTHS / 10}s)")
    return tenths


# ---------------------------------------------------------------------------
# Scene levels
# ---------------------------------------------------------------------------


def build_read_scene(
    target: DeviceAddress, zone: int, scene: int, source: DeviceAddress = DEFAULT_SOURCE,
    long: bool = False,
) -> Packet:
    """Read the stored levels of ``scene`` in ``zone``.

    Plain (SDK Read_Scene_Model): 0x0000 ``[zone, scene]`` → 0x0001.
    ``long=True`` (what TfrmMain.ReadQueOfZone always sends): 0x10FE
    ``[zone, scene_hi, scene_lo]`` → 0x10FF (or 0x0001 on older firmware —
    TfrmMain.ShowQueLight handles both, see :func:`parse_scene`).
    """
    if long:
        return _packet(target, OP_READ_SCENE_LONG, bytes([_byte(zone, "zone")]) + _word(scene, "scene"), source)
    return _packet(target, OP_READ_SCENE, bytes([_byte(zone, "zone"), _byte(scene, "scene")]), source)


def parse_scene(payload: bytes, opcode: int = OP_READ_SCENE_RESP) -> SceneLevels:
    """Parse a 0x0001 or 0x10FF scene reply.

    0x0001: ``[zone, scene, seconds_hi, seconds_lo, level_ch1, ...]``
    0x10FF: ``[zone, scene_hi, scene_lo, tenths_hi, tenths_lo, level_ch1, ...]``

    # UNVERIFIED: layouts mirror the matching 0x0008 / 0x1001 write
    payloads; TfrmMain.ShowQueLight confirms only the time arithmetic
    (``/600``, ``/10 % 60``, ``% 10`` for 0x10FF; ``/60``, ``% 60`` for the
    plain reply). A 16-bit length prefix on 0x10FF, if present, is stripped.
    """
    if opcode == OP_READ_SCENE_LONG_RESP:
        if len(payload) >= 2 and int.from_bytes(payload[:2], "big") in (len(payload), len(payload) - 2):
            payload = payload[2:]
        if len(payload) < 5:
            raise ValueError(f"0x10FF payload too short: {len(payload)}")
        return SceneLevels(
            zone=payload[0],
            scene=int.from_bytes(payload[1:3], "big"),
            runtime=int.from_bytes(payload[3:5], "big") / 10,
            levels=list(payload[5:]),
        )
    if len(payload) < 4:
        raise ValueError(f"0x0001 payload too short: {len(payload)}")
    return SceneLevels(
        zone=payload[0],
        scene=payload[1],
        runtime=float(int.from_bytes(payload[2:4], "big")),
        levels=list(payload[4:]),
    )


def build_write_scene(
    target: DeviceAddress,
    zone: int,
    scene: int,
    runtime: float,
    levels: Sequence[int],
    source: DeviceAddress = DEFAULT_SOURCE,
    long: bool = False,
) -> Packet:
    """Store ``levels`` (%) and ``runtime`` (seconds) as ``scene`` of ``zone``.

    Plain (TfrmMain.ModifyQueOfZone, SDK Modify_Scene_Model): 0x0008
    ``[zone, scene, seconds_hi, seconds_lo, level_ch1, ..., level_chN]`` →
    ack 0x0009. The vendor computes ``minutes * 60 + seconds``; the fade
    time is whole seconds here.

    ``long=True``: 0x1001 ``[len_hi, len_lo, zone, scene_hi, scene_lo,
    tenths_hi, tenths_lo, levels...]`` → ack 0x0009, where ``len`` counts
    the bytes after the prefix (``N + 5``). Used by the vendor for
    modules whose scene numbers exceed 255.
    """
    table = _levels(levels)
    if long:
        body = bytes([_byte(zone, "zone")]) + _word(scene, "scene") + _word(_tenths(runtime), "runtime") + table
        return _packet(target, OP_WRITE_SCENE_LONG, _word(len(body), "length") + body, source)
    seconds = round(float(runtime))
    if not 0 <= seconds <= MAX_RUNTIME_SECONDS:
        raise ValueError("runtime out of range")
    payload = bytes([_byte(zone, "zone"), _byte(scene, "scene")]) + _word(seconds, "runtime") + table
    return _packet(target, OP_WRITE_SCENE, payload, source)


def build_preview_scene(
    target: DeviceAddress,
    zone: int,
    scene: int,
    runtime: float | None = None,
    levels: Sequence[int] | None = None,
    source: DeviceAddress = DEFAULT_SOURCE,
) -> Packet:
    """0xF074 — run a scene "on-site" without storing it (TfrmMain.PreviewQue).

    The vendor passes an opaque, caller-built array and does not wait for a
    reply.  # UNVERIFIED payload: the only caller (frmEditQueBright's
    "ON-site run scene") edits the same fields as :func:`build_write_scene`,
    so with ``levels`` given the payload is ``[zone, scene, seconds_be16,
    levels...]``; without them it is just ``[zone, scene]``. Stop the
    preview with :func:`build_end_preview_scene`.
    """
    head = bytes([_byte(zone, "zone"), _byte(scene, "scene")])
    if levels is None:
        return _packet(target, OP_PREVIEW_SCENE, head, source)
    seconds = round(float(runtime or 0))
    return _packet(target, OP_PREVIEW_SCENE, head + _word(seconds, "runtime") + _levels(levels), source)


def build_end_preview_scene(
    target: DeviceAddress, zone: int, scene: int, source: DeviceAddress = DEFAULT_SOURCE, long: bool = False
) -> Packet:
    """0xF076 ``[zone, scene]`` → ack 0xF077 (TfrmMain.EndPreviewQue).

    ``long=True`` sends ``[zone, scene_hi, scene_lo]`` (same opcode; the
    vendor only switches to 0x1122 for device type 0x200).
    """
    if long:
        return _packet(target, OP_END_PREVIEW_SCENE, bytes([_byte(zone, "zone")]) + _word(scene, "scene"), source)
    return _packet(target, OP_END_PREVIEW_SCENE, bytes([_byte(zone, "zone"), _byte(scene, "scene")]), source)


async def read_scene(
    bus: SmartG4Bus, target: DeviceAddress, zone: int, scene: int, retries: int = 2, long: bool = False
) -> SceneLevels | None:
    """Read a scene; with ``long`` accept either 0x10FF or 0x0001 as the reply."""
    packet = build_read_scene(target, zone, scene, long=long)
    if not long:
        reply = await _reply(
            bus, packet, OP_READ_SCENE_RESP, retries=retries,
            match=lambda p: p.payload[:2] == bytes([zone, scene]),
        )
        return None if reply is None else parse_scene(reply.payload, OP_READ_SCENE_RESP)

    # The vendor waits on "zone/scene globals updated by ShowQueLight", which
    # fires for either reply opcode; emulate with a two-opcode matcher.
    from .module_config import request  # local import keeps module import order simple

    def matches(p: Packet) -> bool:
        return p.opcode in (OP_READ_SCENE_LONG_RESP, OP_READ_SCENE_RESP) and p.payload[:1] == bytes([zone])

    try:
        reply = await request(
            bus, target, packet.opcode, packet.payload, OP_READ_SCENE_LONG_RESP, retries=retries,
            match=matches,
        )
    except (TimeoutError, asyncio.TimeoutError):
        try:
            reply = await request(
                bus, target, packet.opcode, packet.payload, OP_READ_SCENE_RESP, retries=0, match=matches,
            )
        except (TimeoutError, asyncio.TimeoutError):
            return None
    return parse_scene(reply.payload, reply.opcode)


async def write_scene(
    bus: SmartG4Bus, target: DeviceAddress, zone: int, scene: int, runtime: float, levels: Sequence[int],
    long: bool = False,
) -> bool:
    return await _acked(bus, build_write_scene(target, zone, scene, runtime, levels, long=long), OP_WRITE_SCENE_RESP)


def preview_scene(
    bus: SmartG4Bus, target: DeviceAddress, zone: int, scene: int,
    runtime: float | None = None, levels: Sequence[int] | None = None,
) -> None:
    """Fire-and-forget, like the vendor."""
    packet = build_preview_scene(target, zone, scene, runtime, levels)
    bus.send(target, packet.opcode, payload=packet.payload)


async def end_preview_scene(bus: SmartG4Bus, target: DeviceAddress, zone: int, scene: int) -> bool:
    return await _acked(bus, build_end_preview_scene(target, zone, scene), OP_END_PREVIEW_SCENE_RESP)


# ---------------------------------------------------------------------------
# Scene / zone / sequence remarks (names)
# ---------------------------------------------------------------------------


def build_read_scene_name(
    target: DeviceAddress, zone: int, scene: int, source: DeviceAddress = DEFAULT_SOURCE
) -> Packet:
    """0xF024 ``[zone, scene]`` → 0xF025 ``[zone, scene, name20]`` (TfrmMain.ReadQueRemark)."""
    return _packet(target, OP_READ_SCENE_REMARK, bytes([_byte(zone, "zone"), _byte(scene, "scene")]), source)


def build_write_scene_name(
    target: DeviceAddress, zone: int, scene: int, name: str, source: DeviceAddress = DEFAULT_SOURCE
) -> Packet:
    """0xF026 ``[zone, scene, name20]`` (22 bytes) → ack 0xF027 (TfrmMain.ModifyQueRemark)."""
    return _packet(
        target, OP_WRITE_SCENE_REMARK,
        bytes([_byte(zone, "zone"), _byte(scene, "scene")]) + encode_name(name), source,
    )


def parse_scene_name(payload: bytes) -> tuple[int, int, str | None]:
    """0xF025 ``[zone, scene, name20]`` → ``(zone, scene, name)``."""
    if len(payload) < 2:
        raise ValueError("0xF025 payload too short")
    return payload[0], payload[1], decode_name(payload[2:2 + NAME_LEN])


def build_read_zone_name(target: DeviceAddress, zone: int, source: DeviceAddress = DEFAULT_SOURCE) -> Packet:
    """0xF00A ``[zone]`` → 0xF00B ``[zone, name20]`` (TfrmMain.ReadZoneRemark; live-confirmed)."""
    return _packet(target, OP_READ_ZONE_REMARK, bytes([_byte(zone, "zone")]), source)


def build_write_zone_name(
    target: DeviceAddress, zone: int, name: str, source: DeviceAddress = DEFAULT_SOURCE
) -> Packet:
    """0xF00C ``[zone, name20]`` (21 bytes) → ack 0xF00D (TfrmMain.ModifyZoneRemark)."""
    return _packet(target, OP_WRITE_ZONE_REMARK, bytes([_byte(zone, "zone")]) + encode_name(name), source)


def parse_zone_name(payload: bytes) -> tuple[int, str | None]:
    """0xF00B ``[zone, name20]`` → ``(zone, name)``; a missing zone answers 0xF5 in the zone byte."""
    if not payload:
        raise ValueError("empty 0xF00B payload")
    return payload[0], decode_name(payload[1:1 + NAME_LEN])


def build_read_sequence_name(
    target: DeviceAddress, zone: int, sequence: int, source: DeviceAddress = DEFAULT_SOURCE
) -> Packet:
    """0xF028 ``[zone, sequence]`` → 0xF029 ``[zone, sequence, name20]`` (TfrmMain.ReadSeriesRemark)."""
    return _packet(
        target, OP_READ_SEQUENCE_REMARK, bytes([_byte(zone, "zone"), _byte(sequence, "sequence")]), source
    )


def build_write_sequence_name(
    target: DeviceAddress, zone: int, sequence: int, name: str, source: DeviceAddress = DEFAULT_SOURCE
) -> Packet:
    """0xF030 ``[zone, sequence, name20]`` (22 bytes) → ack 0xF031 (TfrmMain.ModifySeriesRemark)."""
    return _packet(
        target, OP_WRITE_SEQUENCE_REMARK,
        bytes([_byte(zone, "zone"), _byte(sequence, "sequence")]) + encode_name(name), source,
    )


def parse_sequence_name(payload: bytes) -> tuple[int, int, str | None]:
    """0xF029 ``[zone, sequence, name20]`` → ``(zone, sequence, name)``."""
    if len(payload) < 2:
        raise ValueError("0xF029 payload too short")
    return payload[0], payload[1], decode_name(payload[2:2 + NAME_LEN])


async def read_scene_name(
    bus: SmartG4Bus, target: DeviceAddress, zone: int, scene: int, retries: int = 3
) -> str | None:
    reply = await _reply(
        bus, build_read_scene_name(target, zone, scene), OP_READ_SCENE_REMARK_RESP,
        timeout=1.0, retries=retries, match=lambda p: p.payload[:2] == bytes([zone, scene]),
    )
    return None if reply is None else parse_scene_name(reply.payload)[2]


async def write_scene_name(bus: SmartG4Bus, target: DeviceAddress, zone: int, scene: int, name: str) -> bool:
    """Write a scene name; verify by reading it back (modules ack late or not at all)."""
    name = clean(name)
    await _acked(bus, build_write_scene_name(target, zone, scene, name), OP_WRITE_SCENE_REMARK_RESP)
    await asyncio.sleep(0.3)
    stored = await read_scene_name(bus, target, zone, scene)
    return stored == name or (not name and stored is None)


async def read_zone_name(bus: SmartG4Bus, target: DeviceAddress, zone: int, retries: int = 3) -> str | None:
    """Zone name via the registered 0xF00A command (same style as naming.py)."""
    try:
        packet = await bus.request(
            target, OP_READ_ZONE_REMARK, {"zone": zone}, timeout=1.0, retries=retries,
            match=lambda p: p.payload[:1] == bytes([zone]),
        )
    except (TimeoutError, asyncio.TimeoutError):
        return None
    return parse_zone_name(packet.payload)[1]


async def read_zone_names(bus: SmartG4Bus, target: DeviceAddress, count: int) -> list[str | None]:
    """TfrmMain.ReadAllZoneRemark: ReadZoneRemark for zones 1..count, in order."""
    names: list[str | None] = []
    for zone in range(1, count + 1):
        names.append(await read_zone_name(bus, target, zone))
        await asyncio.sleep(0.05)
    return names


async def write_zone_name(bus: SmartG4Bus, target: DeviceAddress, zone: int, name: str) -> bool:
    name = clean(name)
    try:
        await bus.request(target, OP_WRITE_ZONE_REMARK, {"zone": zone, "remark": name}, timeout=2.0, retries=2)
    except (TimeoutError, asyncio.TimeoutError):
        pass
    await asyncio.sleep(0.3)
    stored = await read_zone_name(bus, target, zone)
    return stored == name or (not name and stored is None)


async def read_sequence_name(
    bus: SmartG4Bus, target: DeviceAddress, zone: int, sequence: int, retries: int = 3
) -> str | None:
    reply = await _reply(
        bus, build_read_sequence_name(target, zone, sequence), OP_READ_SEQUENCE_REMARK_RESP,
        timeout=1.0, retries=retries, match=lambda p: p.payload[:2] == bytes([zone, sequence]),
    )
    return None if reply is None else parse_sequence_name(reply.payload)[2]


async def write_sequence_name(
    bus: SmartG4Bus, target: DeviceAddress, zone: int, sequence: int, name: str
) -> bool:
    name = clean(name)
    await _acked(bus, build_write_sequence_name(target, zone, sequence, name), OP_WRITE_SEQUENCE_REMARK_RESP)
    await asyncio.sleep(0.3)
    stored = await read_sequence_name(bus, target, zone, sequence)
    return stored == name or (not name and stored is None)


# ---------------------------------------------------------------------------
# Running scene of every zone (SDK only)
# ---------------------------------------------------------------------------


def build_read_running_scenes(target: DeviceAddress, source: DeviceAddress = DEFAULT_SOURCE) -> Packet:
    """0xF078, empty → 0xF079 (SDK Read_Scene_All_Zones_Running; not used by the vendor tool).

    # UNVERIFIED layout: presumably the current scene number of each zone,
    zone 1 first (possibly preceded by a zone count).
    """
    return _packet(target, OP_READ_RUNNING_SCENES, b"", source)


def parse_running_scenes(payload: bytes) -> list[int]:
    """0xF079 → raw bytes (scene per zone).  # UNVERIFIED"""
    return list(payload)


async def read_running_scenes(bus: SmartG4Bus, target: DeviceAddress, retries: int = 2) -> list[int] | None:
    reply = await _reply(bus, build_read_running_scenes(target), OP_READ_RUNNING_SCENES_RESP, retries=retries)
    return None if reply is None else parse_running_scenes(reply.payload)


# ---------------------------------------------------------------------------
# Sequences ("Series")
# ---------------------------------------------------------------------------


def build_read_zones_with_sequences(target: DeviceAddress, source: DeviceAddress = DEFAULT_SOURCE) -> Packet:
    """0x001C, empty → 0x001D (TfrmMain.ReadWhichZoneHasSeries).

    # UNVERIFIED: the request opcode is not visible in the decompile (only
    the awaited reply 0x001D is); 0x001C is assumed from the even/odd
    request/response convention. Reply layout unknown — returned raw.
    """
    return _packet(target, OP_READ_ZONES_WITH_SEQUENCES, b"", source)


def build_write_zone_has_sequences(
    target: DeviceAddress, zone: int, source: DeviceAddress = DEFAULT_SOURCE
) -> Packet:
    """0x001E ``[zone]`` → ack 0x001F (TfrmMain.ModifyWhichZoneHasSeries).

    Tells the module which zone the sequence pool belongs to (the vendor's
    sequence editor calls it before adding sequences to a zone).
    """
    return _packet(target, OP_WRITE_ZONE_HAS_SEQUENCES, bytes([_byte(zone, "zone")]), source)


def parse_zones_with_sequences(payload: bytes) -> list[int]:
    """0x001D → raw bytes.  # UNVERIFIED (probably ``[count, zone...]`` or one flag per zone)."""
    return list(payload)


def build_read_sequence(
    target: DeviceAddress, zone: int, sequence: int, source: DeviceAddress = DEFAULT_SOURCE
) -> Packet:
    """0x0012 ``[zone, sequence]`` → 0x0013 (SDK Read_Sequence_Running).

    Reads the configuration TfrmMain.ModifySeries writes (mode, times,
    steps); TfrmMain.ShowSeries renders exactly those three fields from
    the reply.
    """
    return _packet(target, OP_READ_SEQUENCE, bytes([_byte(zone, "zone"), _byte(sequence, "sequence")]), source)


def build_write_sequence(
    target: DeviceAddress, zone: int, sequence: int, mode: int, times: int, steps: int,
    source: DeviceAddress = DEFAULT_SOURCE,
) -> Packet:
    """0x0018 ``[zone, sequence, mode, times, steps]`` → ack 0x0019 (TfrmMain.ModifySeries).

    ``mode`` per :data:`SEQUENCE_MODES`; ``times`` 0 = unlimited, else
    1..99 (frmEditSeriesModeAndTotalsteps: "Running times must be within
    0-%"); ``steps`` 1..12 or 1..99 depending on the module ("Step number
    must be within 1-%", TfrmMain.ShowSeries clamps to 12 for the smaller
    relays).  # UNVERIFIED: the order of the last three bytes follows the
    editor's field order (Mode, Times, Step totality) and the Delphi
    argument order; the decompile only shows them as three opaque bytes
    after ``[zone, sequence]``.
    """
    if mode not in SEQUENCE_MODES:
        raise ValueError(f"mode must be one of {sorted(SEQUENCE_MODES)}")
    if not 0 <= times <= 99:
        raise ValueError("times must be 0 (unlimited) or 1..99")
    if not 1 <= steps <= 99:
        raise ValueError("steps must be 1..99")
    payload = bytes([_byte(zone, "zone"), _byte(sequence, "sequence"), mode, times, steps])
    return _packet(target, OP_WRITE_SEQUENCE, payload, source)


def parse_sequence(payload: bytes) -> SequenceConfig:
    """0x0013 ``[zone, sequence, mode, times, steps]``.  # UNVERIFIED (mirrors 0x0018)"""
    if len(payload) < 5:
        raise ValueError(f"0x0013 payload too short: {len(payload)}")
    return SequenceConfig(zone=payload[0], sequence=payload[1], mode=payload[2], times=payload[3], steps=payload[4])


def build_read_sequences_of_zone(target: DeviceAddress, source: DeviceAddress = DEFAULT_SOURCE) -> Packet:
    """0x0291, empty → 0x0292 (TfrmMain.ReadSeriesOfZone, vendor-only).

    # UNVERIFIED semantics: the vendor sends no zone byte and sets no
    timeout message, so this is probably a whole-module sequence listing.
    Reply returned raw.
    """
    return _packet(target, OP_READ_SEQUENCES_OF_ZONE, b"", source)


def build_read_sequence_total(target: DeviceAddress, zone: int, source: DeviceAddress = DEFAULT_SOURCE) -> Packet:
    """0xF067 ``[zone]`` → 0xF068 (TfrmMain.ReadSeriesTotal, "Reading total Sequences")."""
    return _packet(target, OP_READ_SEQUENCE_TOTAL, bytes([_byte(zone, "zone")]), source)


def parse_sequence_total(payload: bytes) -> tuple[int | None, int]:
    """0xF068 → ``(zone, total)``; ``(None, total)`` if the module answers a single byte.  # UNVERIFIED"""
    if not payload:
        raise ValueError("empty 0xF068 payload")
    if len(payload) == 1:
        return None, payload[0]
    return payload[0], payload[1]


def build_read_step(
    target: DeviceAddress, zone: int, sequence: int, step: int, source: DeviceAddress = DEFAULT_SOURCE
) -> Packet:
    """0x0014 ``[zone, sequence, step]`` → 0x0015 (TfrmMain.ReadStepOfSeries; SDK Read_Sequence_Detail)."""
    return _packet(
        target, OP_READ_STEP,
        bytes([_byte(zone, "zone"), _byte(sequence, "sequence"), _byte(step, "step")]), source,
    )


def build_write_step(
    target: DeviceAddress, zone: int, sequence: int, step: int, scene: int, interval: float,
    source: DeviceAddress = DEFAULT_SOURCE, long: bool = False,
) -> Packet:
    """0x0016 ``[zone, sequence, step, scene, tenths_hi, tenths_lo]`` → ack 0x0017.

    TfrmMain.ModifyStepOfSeries: the 16-bit time is ``minutes * 600 +
    seconds * 10 + tenths`` (TfrmDBToNet.DownloadStep feeds it from
    QtyIntervalMinute / Second / TenthSecond). ``long=True`` writes the
    scene as 16 bits: ``[zone, sequence, step, scene_hi, scene_lo, tenths16]``.
    """
    head = bytes([_byte(zone, "zone"), _byte(sequence, "sequence"), _byte(step, "step")])
    scene_bytes = _word(scene, "scene") if long else bytes([_byte(scene, "scene")])
    return _packet(target, OP_WRITE_STEP, head + scene_bytes + _word(_tenths(interval), "interval"), source)


def parse_step(payload: bytes) -> SequenceStep:
    """0x0015 ``[zone, sequence, step, scene, tenths_hi, tenths_lo]``.  # UNVERIFIED (mirrors 0x0016)

    A 7-byte reply is read as the long form (16-bit scene).
    """
    if len(payload) < 6:
        raise ValueError(f"0x0015 payload too short: {len(payload)}")
    if len(payload) >= 7:
        return SequenceStep(
            zone=payload[0], sequence=payload[1], step=payload[2],
            scene=int.from_bytes(payload[3:5], "big"),
            interval=int.from_bytes(payload[5:7], "big") / 10,
        )
    return SequenceStep(
        zone=payload[0], sequence=payload[1], step=payload[2], scene=payload[3],
        interval=int.from_bytes(payload[4:6], "big") / 10,
    )


def build_add_sequence(
    target: DeviceAddress, zone: int, sequence: int, source: DeviceAddress = DEFAULT_SOURCE
) -> Packet:
    """0xD006 ``[zone, sequence]`` → ack 0xD007 (TfrmMain.AddNewSeries, frmAddNewSeries).

    # UNVERIFIED: the vendor splits one 16-bit argument into ``[hi, lo]``;
    ``zone << 8 | sequence`` is the assumed packing (the dialog is "Add
    sequence in current area" with "Input new-added sequence no.").
    """
    return _packet(target, OP_ADD_SEQUENCE, bytes([_byte(zone, "zone"), _byte(sequence, "sequence")]), source)


def build_delete_sequence(
    target: DeviceAddress, zone: int, sequence: int, source: DeviceAddress = DEFAULT_SOURCE
) -> Packet:
    """0xF072 ``[zone, sequence]`` → ack 0xF073 (TfrmMain.DeleteSeries)."""
    return _packet(target, OP_DELETE_SEQUENCE, bytes([_byte(zone, "zone"), _byte(sequence, "sequence")]), source)


def build_free_sequence(
    target: DeviceAddress, zone: int, sequence: int, source: DeviceAddress = DEFAULT_SOURCE
) -> Packet:
    """0xF06B ``[zone, sequence]`` → ack 0xF06C (TfrmMain.FreeRoomSeries).

    "Inactivate sequence space": releases the sequence's memory slot; the
    sequence stays listed but is unusable until restored.
    """
    return _packet(target, OP_FREE_SEQUENCE, bytes([_byte(zone, "zone"), _byte(sequence, "sequence")]), source)


def build_restore_sequence(
    target: DeviceAddress, zone: int, sequence: int, source: DeviceAddress = DEFAULT_SOURCE
) -> Packet:
    """0xF06E ``[zone, sequence]`` → ack 0xF06F (TfrmMain.ResumeSeries, "Restore inactivated sequence")."""
    return _packet(target, OP_RESTORE_SEQUENCE, bytes([_byte(zone, "zone"), _byte(sequence, "sequence")]), source)


def build_read_free_sequence_slots(target: DeviceAddress, source: DeviceAddress = DEFAULT_SOURCE) -> Packet:
    """0xF070, empty → 0xF071 (TfrmMain.ReadSeriesLeftCountRoom, "surplus Sequence space")."""
    return _packet(target, OP_READ_FREE_SEQUENCE_SLOTS, b"", source)


def parse_free_sequence_slots(payload: bytes) -> int:
    """0xF071 ``[count]`` → free slots.  # UNVERIFIED (single byte assumed)"""
    if not payload:
        raise ValueError("empty 0xF071 payload")
    return payload[0]


async def read_zones_with_sequences(bus: SmartG4Bus, target: DeviceAddress, retries: int = 2) -> list[int] | None:
    reply = await _reply(bus, build_read_zones_with_sequences(target), OP_READ_ZONES_WITH_SEQUENCES_RESP, retries=retries)
    return None if reply is None else parse_zones_with_sequences(reply.payload)


async def write_zone_has_sequences(bus: SmartG4Bus, target: DeviceAddress, zone: int) -> bool:
    return await _acked(bus, build_write_zone_has_sequences(target, zone), OP_WRITE_ZONE_HAS_SEQUENCES_RESP)


async def read_sequence(
    bus: SmartG4Bus, target: DeviceAddress, zone: int, sequence: int, retries: int = 2
) -> SequenceConfig | None:
    reply = await _reply(
        bus, build_read_sequence(target, zone, sequence), OP_READ_SEQUENCE_RESP, retries=retries,
        match=lambda p: p.payload[:2] == bytes([zone, sequence]),
    )
    return None if reply is None else parse_sequence(reply.payload)


async def write_sequence(
    bus: SmartG4Bus, target: DeviceAddress, zone: int, sequence: int, mode: int, times: int, steps: int
) -> bool:
    return await _acked(bus, build_write_sequence(target, zone, sequence, mode, times, steps), OP_WRITE_SEQUENCE_RESP)


async def read_sequences_of_zone(bus: SmartG4Bus, target: DeviceAddress, retries: int = 2) -> list[int] | None:
    reply = await _reply(bus, build_read_sequences_of_zone(target), OP_READ_SEQUENCES_OF_ZONE_RESP, retries=retries)
    return None if reply is None else list(reply.payload)


async def read_sequence_total(bus: SmartG4Bus, target: DeviceAddress, zone: int, retries: int = 2) -> int | None:
    reply = await _reply(bus, build_read_sequence_total(target, zone), OP_READ_SEQUENCE_TOTAL_RESP, retries=retries)
    return None if reply is None else parse_sequence_total(reply.payload)[1]


async def read_step(
    bus: SmartG4Bus, target: DeviceAddress, zone: int, sequence: int, step: int, retries: int = 2
) -> SequenceStep | None:
    reply = await _reply(
        bus, build_read_step(target, zone, sequence, step), OP_READ_STEP_RESP, retries=retries,
        match=lambda p: p.payload[:3] == bytes([zone, sequence, step]),
    )
    return None if reply is None else parse_step(reply.payload)


async def read_steps(
    bus: SmartG4Bus, target: DeviceAddress, zone: int, sequence: int, count: int
) -> list[SequenceStep | None]:
    """Read steps 1..count of a sequence (None where no reply came)."""
    steps: list[SequenceStep | None] = []
    for step in range(1, count + 1):
        steps.append(await read_step(bus, target, zone, sequence, step))
        await asyncio.sleep(0.05)
    return steps


async def write_step(
    bus: SmartG4Bus, target: DeviceAddress, zone: int, sequence: int, step: int, scene: int, interval: float,
    long: bool = False,
) -> bool:
    return await _acked(
        bus, build_write_step(target, zone, sequence, step, scene, interval, long=long), OP_WRITE_STEP_RESP
    )


async def add_sequence(bus: SmartG4Bus, target: DeviceAddress, zone: int, sequence: int) -> bool:
    return await _acked(bus, build_add_sequence(target, zone, sequence), OP_ADD_SEQUENCE_RESP)


async def delete_sequence(bus: SmartG4Bus, target: DeviceAddress, zone: int, sequence: int) -> bool:
    return await _acked(bus, build_delete_sequence(target, zone, sequence), OP_DELETE_SEQUENCE_RESP)


async def free_sequence(bus: SmartG4Bus, target: DeviceAddress, zone: int, sequence: int) -> bool:
    return await _acked(bus, build_free_sequence(target, zone, sequence), OP_FREE_SEQUENCE_RESP)


async def restore_sequence(bus: SmartG4Bus, target: DeviceAddress, zone: int, sequence: int) -> bool:
    return await _acked(bus, build_restore_sequence(target, zone, sequence), OP_RESTORE_SEQUENCE_RESP)


async def read_free_sequence_slots(bus: SmartG4Bus, target: DeviceAddress, retries: int = 2) -> int | None:
    reply = await _reply(bus, build_read_free_sequence_slots(target), OP_READ_FREE_SEQUENCE_SLOTS_RESP, retries=retries)
    return None if reply is None else parse_free_sequence_slots(reply.payload)


__all__ = [name for name in dir() if name.startswith(("OP_", "SEQUENCE_", "build_", "parse_", "read_", "write_"))] + [
    "SceneLevels", "SequenceConfig", "SequenceStep",
    "preview_scene", "end_preview_scene", "add_sequence", "delete_sequence",
    "free_sequence", "restore_sequence",
]
