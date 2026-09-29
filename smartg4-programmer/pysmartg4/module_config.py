"""Per-channel and per-device configuration of dimmer / relay modules.

Everything here was recovered from the Ghidra decompilation of the vendor's
"Smart Cloud Configuration V16.38" tool (the function names cited below are
its Delphi debug symbols) and cross-checked against the opcode table shipped
inside the official SBUS.dll SDK (``docs/opcodes.json``). All frames are
PLAIN 0xAAAA S-BUS frames (:class:`~pysmartg4.packet.Packet`); none of them
needs the vendor's encrypted "frame cipher".

A word of warning about ``docs/smartcloud_method_opcodes_raw.txt``: that
quick table is shifted by one function (e.g. it lists 0xF03F for
``ReadChnsTurnOnDelayTime`` while the decompile sends 0xF04D and 0xF03F is
``ReadChnsPowerOnDelayTime``). Every opcode in this module was read straight
from the decompiled ``TfrmMain.*`` routine instead.

Confidence, per family (details in ``docs/features/module_config.md``):

============================  =====================  =====================
feature                       request (vendor func)  response / layout
============================  =====================  =====================
channel load type             0xF012 / 0xF014        0xF013 [type/ch]  HIGH
channel low / high limit      0xF016 / 0xF018        0xF017            HIGH/MED
channel max level             0xF020 / 0xF022        0xF021 [lvl/ch]   HIGH/MED
switching-on delay (s)        0xF04D / 0xF04F        0xF04E [s/ch]     HIGH/MED
  "new relay" variant         0xE908 / 0xE90A        0xE909 / 0xE90B   HIGH/LOW
protection delay (min)        0xF03F / 0xF041        0xF040 [min/ch]   HIGH/MED
channel start position        0x03C1 / 0x03C3        0x03C2            MED/LOW
channel dimming attribute     0x1008 / 0x1009        0xF089 / 0xF08B   LOW
power-on resume flag          0xF051 / 0xD203        0xF052 / 0xD204   HIGH/LOW
power-on resume scene         0xF059 / 0xF057        0xF05A / 0xF058   HIGH/LOW
load info / test / power      0xE027 0xE029 0xE025   +1                HIGH/LOW
zone table ("device config")  0x0004 / 0x0006        0x0005 / 0x0007   HIGH/MED
network parameters            0xF037 / 0xF039        0xF038 / 0xF03A   HIGH/MED
MAC / address-by-MAC          0xF001 / 0xF005        0xF002 / 0xF006   HIGH
scan online (MAC + name)      0xF003                 0xF004            HIGH (live)
device online check           0xF065                 0xF066            HIGH
timer channel enable          0xD02C / 0xD02E        0xD02D / 0xD02F   HIGH (timer)
============================  =====================  =====================

"HIGH" = opcode and payload read straight off the decompile (or already
confirmed live); "MED" = opcode certain, response layout inferred from the
matching write payload; "LOW" = see the ``# UNVERIFIED`` markers.

Reading the vendor code: every ``TfrmMain.Read*``/``Modify*`` routine builds
a byte buffer, calls ``TfrmMain.SendAddBuf`` with a 16-bit opcode immediate
and then spins until the global "last received opcode" equals the response
code, retrying three times with a 2 s timeout. The helpers below do the same
thing on top of :class:`~pysmartg4.bus.SmartG4Bus`.

Most of these opcodes have no ``response`` entry in :mod:`pysmartg4.commands`
yet, so :meth:`SmartG4Bus.request` cannot be used for them; :func:`request`
below implements the same send-and-await-matching-reply logic through the
public ``on_packet``/``send`` API only.

Many vendor routines have a second, "long" branch (opcodes 0x10xx, e.g.
0x1002 for load type, 0x1004 for limits, 0x1006 for max level) used for
modules with more than 255 channels or DALI gateways; those carry a 16-bit
length prefix and are not implemented here except where the vendor has NO
plain variant (dimming attribute, 0x1008/0x1009).
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any, Callable, Sequence

from .bus import SmartG4Bus
from .naming import decode_name
from .packet import BROADCAST, DeviceAddress, Packet

# Placeholder source used by the pure ``build_*`` helpers; the bus stamps
# its own sender address / type / signature when it actually transmits.
DEFAULT_SOURCE = DeviceAddress(0xEE, 0xEE)

# ---------------------------------------------------------------------------
# Opcodes
# ---------------------------------------------------------------------------

# TfrmMain.ReadChnsLoadType / ModifyChnsLoadType (SDK: Read/Modify_Channel_Type)
OP_READ_LOAD_TYPE = 0xF012
OP_READ_LOAD_TYPE_RESP = 0xF013
OP_WRITE_LOAD_TYPE = 0xF014
OP_WRITE_LOAD_TYPE_RESP = 0xF015

# TfrmMain.ReadChnsLimit / ModifyChnsLimit (SDK: Read/Write_Channel_Limit)
OP_READ_LIMIT = 0xF016
OP_READ_LIMIT_RESP = 0xF017
OP_WRITE_LIMIT = 0xF018
OP_WRITE_LIMIT_RESP = 0xF019
LIMIT_LOW = 0   # "Lower limit (%)"  — ReadChnsLimit sends 0 for the low table
LIMIT_HIGH = 1  # "Higher limit (%)" — ReadChnsLimit sends 1 for the high table

# TfrmMain.ReadChnsMaxLevel / ModifyChnsMaxLevel ("Max level of higher limit")
OP_READ_MAX_LEVEL = 0xF020
OP_READ_MAX_LEVEL_RESP = 0xF021
OP_WRITE_MAX_LEVEL = 0xF022
OP_WRITE_MAX_LEVEL_RESP = 0xF023

# TfrmMain.ReadChnsTurnOnDelayTime / ModifyChnsTurnOnDelayTime
# (SDK: Read/Modify_Delay_Of_Turn_On_Channel) — "Switching-on delay (s)".
OP_READ_TURN_ON_DELAY = 0xF04D
OP_READ_TURN_ON_DELAY_RESP = 0xF04E
OP_WRITE_TURN_ON_DELAY = 0xF04F
OP_WRITE_TURN_ON_DELAY_RESP = 0xF050

# TfrmMain.ReadChnsPowerOnDelayTime / ModifyChnsPowerOnDelayTime
# (SDK: Read/Modify_Safeguard_Time_Of_Channel) — "Protection delay (min)".
OP_READ_PROTECTION_DELAY = 0xF03F
OP_READ_PROTECTION_DELAY_RESP = 0xF040
OP_WRITE_PROTECTION_DELAY = 0xF041
OP_WRITE_PROTECTION_DELAY_RESP = 0xF042

# "New relay" modules (the vendor's FUN_0126633c(device_type) test, the
# same family as ReadNewRelayFunction 0xE800): both delays go through one
# selector-prefixed opcode pair instead. Selector 3 = switching-on delay,
# 4 = protection delay.
OP_NEW_RELAY_READ_DELAY = 0xE908
OP_NEW_RELAY_READ_DELAY_RESP = 0xE909
OP_NEW_RELAY_WRITE_DELAY = 0xE90A
OP_NEW_RELAY_WRITE_DELAY_RESP = 0xE90B
NEW_RELAY_TURN_ON_DELAY = 3
NEW_RELAY_PROTECTION_DELAY = 4

# TfrmMain.ReadStartPos / ModifyChnsStartPos (frmEditChnsStarPos)
OP_READ_START_POS = 0x03C1
OP_READ_START_POS_RESP = 0x03C2
OP_WRITE_START_POS = 0x03C3
OP_WRITE_START_POS_RESP = 0x03C4  # UNVERIFIED: vendor does not wait for it

# TfrmMain.ReadChnsChange / ModifyChnsChange ("Changing attribute",
# frmEditChnsChange "Modify dimming attribute"). The vendor has NO plain
# 0xF0xx variant here: it sends the length-prefixed 0x10xx form and waits
# for a 0xF0xx reply.  # UNVERIFIED on real hardware.
OP_READ_CHANNEL_ATTR = 0x1008
OP_READ_CHANNEL_ATTR_RESP = 0xF089
OP_WRITE_CHANNEL_ATTR = 0x1009
OP_WRITE_CHANNEL_ATTR_RESP = 0xF08B
CHANNEL_ATTR_BREAK = 0     # lang_en.ini [ChnsChange] 0 = "Break" (switch)
CHANNEL_ATTR_GRADUAL = 1   # 1 = "Gradual change" (dim / fade)

# TfrmMain.ReadPowerOnResumeQueFlag (SDK: Read_Power_On) /
# ModifyPowerOnResumeQueFlag ("re-electrified restored scene mark").
OP_READ_POWER_ON_FLAG = 0xF051
OP_READ_POWER_ON_FLAG_RESP = 0xF052
OP_WRITE_POWER_ON_FLAG = 0xD203          # vendor tool
OP_WRITE_POWER_ON_FLAG_RESP = 0xD204
OP_WRITE_POWER_ON_FLAG_SDK = 0xF053      # SDK: Write_Power_On (ack 0xF054)
OP_WRITE_POWER_ON_FLAG_SDK_RESP = 0xF054
# TfrmMain.ReadMultiSensorPowerOnResume — the read that pairs with 0xD203
# (frmEditPoweronResume: "No restore" / "Restore to previous status").
OP_READ_POWER_ON_FLAG_MULTISENSOR = 0xD201
OP_READ_POWER_ON_FLAG_MULTISENSOR_RESP = 0xD202

# TfrmMain.ReadPowerOnResumeQue / ModifyPowerOnResumeQue ("Scene Resume").
OP_READ_POWER_ON_SCENE = 0xF059          # vendor tool
OP_READ_POWER_ON_SCENE_RESP = 0xF05A
OP_READ_POWER_ON_SCENE_SDK = 0xF055      # SDK: Read_Scene_Power_On
OP_READ_POWER_ON_SCENE_SDK_RESP = 0xF056
OP_WRITE_POWER_ON_SCENE = 0xF057         # SDK: Modify_Scene_Power_On
OP_WRITE_POWER_ON_SCENE_RESP = 0xF058

# TfrmMain.ReadLoadInfo / StartLoadTest / ReadLoadPower
OP_READ_LOAD_INFO = 0xE027
OP_READ_LOAD_INFO_RESP = 0xE028
OP_START_LOAD_TEST = 0xE029
OP_START_LOAD_TEST_RESP = 0xE02A
OP_READ_LOAD_POWER = 0xE025
OP_READ_LOAD_POWER_RESP = 0xE026

# TfrmMain.ReadDeviceConfig / ModifyDeviceConfig — the channel→zone table
# (SDK: Read_Setting_Zones / Make_Zones_Dimmer).
OP_READ_ZONES = 0x0004
OP_READ_ZONES_RESP = 0x0005
OP_WRITE_ZONES = 0x0006
OP_WRITE_ZONES_RESP = 0x0007

# TfrmMain.ReadDeviceNetInfo / ModifyNetInfo
# (SDK: Read/Write_QueControler_IP_Parameter)
OP_READ_NET_INFO = 0xF037
OP_READ_NET_INFO_RESP = 0xF038
OP_WRITE_NET_INFO = 0xF039
OP_WRITE_NET_INFO_RESP = 0xF03A

# TfrmMain.ModifyDeviceMAC (SDK: Mac_Address_Modify)
OP_WRITE_MAC = 0xF001
OP_WRITE_MAC_RESP = 0xF002
# TfrmMain.ReadBroadcastMAC / ReadAllOnLineDevice (SDK: Mac_Address_Read)
OP_READ_MAC = 0xF003
OP_READ_MAC_RESP = 0xF004
# TfrmMain.ModifyObjSubNetIDAndObjDeviceID (SDK: Modify_ID_By_Mac)
OP_MODIFY_ADDRESS_BY_MAC = 0xF005
OP_MODIFY_ADDRESS_BY_MAC_RESP = 0xF006
# TfrmMain.CheckDeviceOnLine (SDK: Deivce_On_Line)
OP_CHECK_ONLINE = 0xF065
OP_CHECK_ONLINE_RESP = 0xF066

# TfrmMain.ReadChannelEnable / ModifyTimerChannelEnable — these are TIMER
# module opcodes (0xD0xx family, frmTimer / frmEditChannelEnable), not
# dimmer/relay ones. Mapped here because the vendor's dimmer/relay form
# calls them; the timer feature owns the semantics.
OP_TIMER_READ_CHANNEL_ENABLE = 0xD02C
OP_TIMER_READ_CHANNEL_ENABLE_RESP = 0xD02D
OP_TIMER_WRITE_CHANNEL_ENABLE = 0xD02E
OP_TIMER_WRITE_CHANNEL_ENABLE_RESP = 0xD02F

MAC_LEN = 8

# Channel load types as stored by the vendor DB for dimmer/relay modules
# (docs/vendor_db/defChnsLoadType.csv). The value is a free "remark" for the
# installer; modules do not act on it.
LOAD_TYPES: dict[int, str] = {
    0: "Undefined",
    1: "Lamp",
    2: "Floor heating valve",
    3: "Floor heating pump",
    4: "Curtain motors",
    5: "Compressor",
    6: "HVAC",
    7: "Fan / valve",
}

# The LED-driver form (TfrmMain.ShowChnsLoadType, device type 0x65) uses a
# different, electrical, table for the same 0xF013 bytes.
LED_DRIVER_LOAD_TYPES: dict[int, str] = {
    0: "Undefined",
    1: "Incandescent lamp",
    2: "Magnetic low-voltage lamp",
    3: "Electronic low-voltage lamp",
    4: "Fluorescent lamp",
    5: "Neon / cold cathode lamp",
    6: "High-intensity discharge lamp (non-dim)",
}

# Power-on resume modes (S-BUS programming guide 3-8 "Scene Resume":
# "Resume the same scene before power off" / "specify scene"; the vendor
# form frmSetPowerOnResumeQue has "Resume Mode", "Scene No." and "Delay
# Time" per area). Which byte value maps to which mode is inferred from
# the guide's ordering.  # UNVERIFIED
POWER_ON_RESUME_OFF = 0        # no restore (all channels stay off)
POWER_ON_RESUME_PREVIOUS = 1   # "Resume the same scene before power off"
POWER_ON_RESUME_SCENE = 2      # "specify scene" — see write_power_on_scenes


# ---------------------------------------------------------------------------
# Generic send-and-wait (public bus API only)
# ---------------------------------------------------------------------------


async def request(
    bus: SmartG4Bus,
    target: DeviceAddress,
    opcode: int,
    payload: bytes,
    response: int,
    *,
    timeout: float = 2.0,
    retries: int = 2,
    match: Callable[[Packet], bool] | None = None,
) -> Packet:
    """Send ``opcode``/``payload`` to ``target`` and await ``response``.

    Mirrors :meth:`SmartG4Bus.request` (same retry/timeout semantics as the
    vendor tool: 3 attempts of 2 s) but takes the response opcode explicitly,
    because :mod:`pysmartg4.commands` has no entries for most of the opcodes
    in this module. Uses only ``bus.on_packet`` and ``bus.send``.
    """

    def matches(packet: Packet) -> bool:
        return (
            packet.opcode == response
            and (target.is_broadcast or packet.source == target)
            and (match is None or match(packet))
        )

    last_error: Exception | None = None
    for _ in range(retries + 1):
        loop = asyncio.get_running_loop()
        future: asyncio.Future[Packet] = loop.create_future()

        def deliver(packet: Packet, _parsed: dict[str, Any] | None) -> None:
            if not future.done() and matches(packet):
                future.set_result(packet)

        unsubscribe = bus.on_packet(deliver)
        try:
            bus.send(target, opcode, payload=payload)
            return await asyncio.wait_for(future, timeout)
        except asyncio.TimeoutError as err:
            last_error = err
        finally:
            unsubscribe()
    raise TimeoutError(
        f"no response {response:#06x} to {opcode:#06x} from {target} "
        f"after {retries + 1} attempts"
    ) from last_error


async def _acked(bus: SmartG4Bus, packet: Packet, response: int, **kw: Any) -> bool:
    """Send a built frame and report whether the module acked it."""
    try:
        await request(bus, packet.target, packet.opcode, packet.payload, response, **kw)
        return True
    except (TimeoutError, asyncio.TimeoutError):
        return False


async def _reply(bus: SmartG4Bus, packet: Packet, response: int, **kw: Any) -> Packet | None:
    """Send a built frame and return the matching reply, or None on timeout."""
    try:
        return await request(bus, packet.target, packet.opcode, packet.payload, response, **kw)
    except (TimeoutError, asyncio.TimeoutError):
        return None


def _packet(target: DeviceAddress, opcode: int, payload: bytes, source: DeviceAddress) -> Packet:
    return Packet(opcode=opcode, source=source, target=target, payload=bytes(payload))


def _channel_bytes(values: Sequence[int], name: str, maximum: int = 255) -> bytes:
    if not values:
        raise ValueError(f"{name}: need at least one channel value")
    out = bytearray()
    for i, value in enumerate(values, start=1):
        if not 0 <= int(value) <= maximum:
            raise ValueError(f"{name}: channel {i} value {value} not in 0..{maximum}")
        out.append(int(value))
    return bytes(out)


# ---------------------------------------------------------------------------
# Per-channel byte tables (load type, limits, max level, delays, start pos)
#
# The vendor writes each of these as ONE BYTE PER CHANNEL, channel 1 first,
# with no header (TfrmDBToNet.DownloadChns copies tblChns.LoadType /
# QtyMaxLevel / QtyTurnOnDelayTime / QtyPowerOnDelayTime straight into the
# frame; ModifyChnsLoadType's plain branch sends exactly N bytes with
# 0xF014). The read responses are assumed to use the same shape; 0xF013 is
# confirmed by TfrmMain.ShowChnsLoadType, which maps payload[0..3] to
# channels 1..4.
# ---------------------------------------------------------------------------


def parse_channel_table(payload: bytes) -> list[int]:
    """One byte per channel, channel 1 first (0xF013/0xF021/0xF04E/0xF040/0x03C2)."""
    return list(payload)


# -- load type ---------------------------------------------------------------


def build_read_load_types(target: DeviceAddress, source: DeviceAddress = DEFAULT_SOURCE) -> Packet:
    """0xF012, empty payload → 0xF013 ``[type_ch1, type_ch2, ...]`` (TfrmMain.ReadChnsLoadType)."""
    return _packet(target, OP_READ_LOAD_TYPE, b"", source)


def build_write_load_types(
    target: DeviceAddress, types: Sequence[int], source: DeviceAddress = DEFAULT_SOURCE
) -> Packet:
    """0xF014 ``[type_ch1, ...]`` → ack 0xF015 (TfrmMain.ModifyChnsLoadType, plain branch)."""
    return _packet(target, OP_WRITE_LOAD_TYPE, _channel_bytes(types, "load type"), source)


async def read_load_types(bus: SmartG4Bus, target: DeviceAddress, retries: int = 2) -> list[int] | None:
    reply = await _reply(bus, build_read_load_types(target), OP_READ_LOAD_TYPE_RESP, retries=retries)
    return None if reply is None else parse_channel_table(reply.payload)


async def write_load_types(bus: SmartG4Bus, target: DeviceAddress, types: Sequence[int]) -> bool:
    return await _acked(bus, build_write_load_types(target, types), OP_WRITE_LOAD_TYPE_RESP)


# -- low / high limit ---------------------------------------------------------


@dataclass
class ChannelLimits:
    kind: int                      # LIMIT_LOW or LIMIT_HIGH
    values: list[int]              # percent per channel, channel 1 first

    def as_dict(self) -> dict[str, Any]:
        return {"kind": "high" if self.kind == LIMIT_HIGH else "low", "values": self.values}


def build_read_limits(
    target: DeviceAddress, kind: int, source: DeviceAddress = DEFAULT_SOURCE
) -> Packet:
    """0xF016 ``[kind]`` → 0xF017 (TfrmMain.ReadChnsLimit, plain branch).

    ``kind`` is :data:`LIMIT_LOW` (0) or :data:`LIMIT_HIGH` (1): the vendor
    sends byte 1 when its timeout text is "Reading channels higher limit"
    (00953) and 0 for "lower limit" (00952).
    """
    if kind not in (LIMIT_LOW, LIMIT_HIGH):
        raise ValueError("kind must be LIMIT_LOW or LIMIT_HIGH")
    return _packet(target, OP_READ_LIMIT, bytes([kind]), source)


def build_write_limits(
    target: DeviceAddress, kind: int, values: Sequence[int], source: DeviceAddress = DEFAULT_SOURCE
) -> Packet:
    """0xF018 ``[kind, pct_ch1, ..., pct_chN, 0, 0]`` → ack 0xF019 (TfrmMain.ModifyChnsLimit).

    TfrmDBToNet.DownloadChns builds ``[0, QtyLowLimit...]`` / ``[1,
    QtyHighLimit...]``; ModifyChnsLimit allocates ``N + 3`` bytes and only
    fills ``N + 1``, so two zero bytes trail the table on the wire. They are
    reproduced here because that is exactly what the modules were
    programmed with.
    """
    if kind not in (LIMIT_LOW, LIMIT_HIGH):
        raise ValueError("kind must be LIMIT_LOW or LIMIT_HIGH")
    table = _channel_bytes(values, "limit", maximum=100)
    return _packet(target, OP_WRITE_LIMIT, bytes([kind]) + table + b"\x00\x00", source)


def parse_limits(payload: bytes) -> ChannelLimits:
    """0xF017 ``[kind, pct_ch1, ...]``.

    # UNVERIFIED: the leading ``kind`` byte is inferred from the request /
    write layouts (TfrmMain.ShowChnsLimit is register-mangled in the
    decompile). If a module answers without it, ``kind`` will read as the
    first channel's limit — check ``len(values)`` against the channel count.
    """
    if not payload:
        raise ValueError("empty 0xF017 payload")
    return ChannelLimits(kind=payload[0], values=list(payload[1:]))


async def read_limits(
    bus: SmartG4Bus, target: DeviceAddress, kind: int, retries: int = 2
) -> ChannelLimits | None:
    reply = await _reply(
        bus, build_read_limits(target, kind), OP_READ_LIMIT_RESP, retries=retries,
        match=lambda p: not p.payload or p.payload[0] == kind,
    )
    return None if reply is None else parse_limits(reply.payload)


async def write_limits(bus: SmartG4Bus, target: DeviceAddress, kind: int, values: Sequence[int]) -> bool:
    return await _acked(bus, build_write_limits(target, kind, values), OP_WRITE_LIMIT_RESP)


# -- max level ---------------------------------------------------------------


def build_read_max_levels(target: DeviceAddress, source: DeviceAddress = DEFAULT_SOURCE) -> Packet:
    """0xF020, empty → 0xF021 ``[pct_ch1, ...]`` (TfrmMain.ReadChnsMaxLevel)."""
    return _packet(target, OP_READ_MAX_LEVEL, b"", source)


def build_write_max_levels(
    target: DeviceAddress, values: Sequence[int], source: DeviceAddress = DEFAULT_SOURCE
) -> Packet:
    """0xF022 ``[pct_ch1, ...]`` (TfrmMain.ModifyChnsMaxLevel; the vendor fires and forgets)."""
    return _packet(target, OP_WRITE_MAX_LEVEL, _channel_bytes(values, "max level", maximum=100), source)


async def read_max_levels(bus: SmartG4Bus, target: DeviceAddress, retries: int = 2) -> list[int] | None:
    reply = await _reply(bus, build_read_max_levels(target), OP_READ_MAX_LEVEL_RESP, retries=retries)
    return None if reply is None else parse_channel_table(reply.payload)


async def write_max_levels(bus: SmartG4Bus, target: DeviceAddress, values: Sequence[int]) -> bool:
    """Write and verify by reading back (the vendor never waits for 0xF023)."""
    bus.send(target, OP_WRITE_MAX_LEVEL, payload=build_write_max_levels(target, values).payload)
    await asyncio.sleep(0.3)
    stored = await read_max_levels(bus, target)
    return stored is not None and stored[: len(values)] == [int(v) for v in values]


# -- switching-on delay (seconds) ------------------------------------------------


def build_read_turn_on_delays(
    target: DeviceAddress, source: DeviceAddress = DEFAULT_SOURCE, new_relay: bool = False
) -> Packet:
    """0xF04D, empty → 0xF04E ``[seconds_ch1, ...]`` (TfrmMain.ReadChnsTurnOnDelayTime).

    With ``new_relay=True`` the vendor's other branch is used instead:
    0xE908 ``[3]`` → 0xE909 (selector 3 = switching-on delay).
    """
    if new_relay:
        return _packet(target, OP_NEW_RELAY_READ_DELAY, bytes([NEW_RELAY_TURN_ON_DELAY]), source)
    return _packet(target, OP_READ_TURN_ON_DELAY, b"", source)


def build_write_turn_on_delays(
    target: DeviceAddress, seconds: Sequence[int], source: DeviceAddress = DEFAULT_SOURCE,
    new_relay: bool = False,
) -> Packet:
    """0xF04F ``[seconds_ch1, ...]`` → ack 0xF050 (TfrmMain.ModifyChnsTurnOnDelayTime).

    The guide documents 0-25 s per relay channel; the module stores a byte.
    ``new_relay=True``: 0xE90A ``[3, seconds_ch1, ...]`` → ack 0xE90B.
    """
    table = _channel_bytes(seconds, "turn-on delay")
    if new_relay:
        return _packet(target, OP_NEW_RELAY_WRITE_DELAY, bytes([NEW_RELAY_TURN_ON_DELAY]) + table, source)
    return _packet(target, OP_WRITE_TURN_ON_DELAY, table, source)


def parse_new_relay_delays(payload: bytes) -> tuple[int, list[int]]:
    """0xE909 ``[selector, value_ch1, ...]`` → ``(selector, values)``.  # UNVERIFIED

    Assumed to echo the selector byte the request carried (3 or 4).
    """
    if not payload:
        raise ValueError("empty 0xE909 payload")
    return payload[0], list(payload[1:])


async def read_turn_on_delays(
    bus: SmartG4Bus, target: DeviceAddress, retries: int = 2, new_relay: bool = False
) -> list[int] | None:
    packet = build_read_turn_on_delays(target, new_relay=new_relay)
    if new_relay:
        reply = await _reply(
            bus, packet, OP_NEW_RELAY_READ_DELAY_RESP, retries=retries,
            match=lambda p: not p.payload or p.payload[0] == NEW_RELAY_TURN_ON_DELAY,
        )
        return None if reply is None else parse_new_relay_delays(reply.payload)[1]
    reply = await _reply(bus, packet, OP_READ_TURN_ON_DELAY_RESP, retries=retries)
    return None if reply is None else parse_channel_table(reply.payload)


async def write_turn_on_delays(
    bus: SmartG4Bus, target: DeviceAddress, seconds: Sequence[int], new_relay: bool = False
) -> bool:
    packet = build_write_turn_on_delays(target, seconds, new_relay=new_relay)
    response = OP_NEW_RELAY_WRITE_DELAY_RESP if new_relay else OP_WRITE_TURN_ON_DELAY_RESP
    return await _acked(bus, packet, response)


# -- protection ("safeguard" / power-on) delay (minutes) --------------------------


def build_read_protection_delays(
    target: DeviceAddress, source: DeviceAddress = DEFAULT_SOURCE, new_relay: bool = False
) -> Packet:
    """0xF03F, empty → 0xF040 ``[minutes_ch1, ...]`` (TfrmMain.ReadChnsPowerOnDelayTime).

    ``new_relay=True``: 0xE908 ``[4]`` → 0xE909 (selector 4 = protection delay).
    """
    if new_relay:
        return _packet(target, OP_NEW_RELAY_READ_DELAY, bytes([NEW_RELAY_PROTECTION_DELAY]), source)
    return _packet(target, OP_READ_PROTECTION_DELAY, b"", source)


def build_write_protection_delays(
    target: DeviceAddress, minutes: Sequence[int], source: DeviceAddress = DEFAULT_SOURCE,
    new_relay: bool = False,
) -> Packet:
    """0xF041 ``[minutes_ch1, ...]`` → ack 0xF042 (TfrmMain.ModifyChnsPowerOnDelayTime).

    "Protection delay (min)", 0-60 per the programming guide.
    ``new_relay=True``: 0xE90A ``[4, minutes_ch1, ...]`` → ack 0xE90B.
    """
    table = _channel_bytes(minutes, "protection delay")
    if new_relay:
        return _packet(target, OP_NEW_RELAY_WRITE_DELAY, bytes([NEW_RELAY_PROTECTION_DELAY]) + table, source)
    return _packet(target, OP_WRITE_PROTECTION_DELAY, table, source)


async def read_protection_delays(
    bus: SmartG4Bus, target: DeviceAddress, retries: int = 2, new_relay: bool = False
) -> list[int] | None:
    packet = build_read_protection_delays(target, new_relay=new_relay)
    if new_relay:
        reply = await _reply(
            bus, packet, OP_NEW_RELAY_READ_DELAY_RESP, retries=retries,
            match=lambda p: not p.payload or p.payload[0] == NEW_RELAY_PROTECTION_DELAY,
        )
        return None if reply is None else parse_new_relay_delays(reply.payload)[1]
    reply = await _reply(bus, packet, OP_READ_PROTECTION_DELAY_RESP, retries=retries)
    return None if reply is None else parse_channel_table(reply.payload)


async def write_protection_delays(
    bus: SmartG4Bus, target: DeviceAddress, minutes: Sequence[int], new_relay: bool = False
) -> bool:
    packet = build_write_protection_delays(target, minutes, new_relay=new_relay)
    response = OP_NEW_RELAY_WRITE_DELAY_RESP if new_relay else OP_WRITE_PROTECTION_DELAY_RESP
    return await _acked(bus, packet, response)


# -- start position ------------------------------------------------------------


def build_read_start_positions(target: DeviceAddress, source: DeviceAddress = DEFAULT_SOURCE) -> Packet:
    """0x03C1, empty → 0x03C2 (TfrmMain.ReadStartPos).

    # UNVERIFIED: the response is assumed to be one byte per channel like
    the write; the semantics ("start position" of a dimmer channel) come
    only from the form name frmEditChnsStarPos.
    """
    return _packet(target, OP_READ_START_POS, b"", source)


def build_write_start_positions(
    target: DeviceAddress, values: Sequence[int], source: DeviceAddress = DEFAULT_SOURCE
) -> Packet:
    """0x03C3 ``[pos_ch1, ...]`` (TfrmMain.ModifyChnsStartPos; not acked by the vendor)."""
    return _packet(target, OP_WRITE_START_POS, _channel_bytes(values, "start position"), source)


async def read_start_positions(bus: SmartG4Bus, target: DeviceAddress, retries: int = 2) -> list[int] | None:
    reply = await _reply(bus, build_read_start_positions(target), OP_READ_START_POS_RESP, retries=retries)
    return None if reply is None else parse_channel_table(reply.payload)


async def write_start_positions(bus: SmartG4Bus, target: DeviceAddress, values: Sequence[int]) -> bool:
    bus.send(target, OP_WRITE_START_POS, payload=build_write_start_positions(target, values).payload)
    await asyncio.sleep(0.3)
    stored = await read_start_positions(bus, target)
    return stored is not None and stored[: len(values)] == [int(v) for v in values]


# -- dimming ("changing") attribute --------------------------------------------------


def build_read_channel_attributes(target: DeviceAddress, source: DeviceAddress = DEFAULT_SOURCE) -> Packet:
    """0x1008 ``[0, 0]`` → 0xF089 (TfrmMain.ReadChnsChange).  # UNVERIFIED

    The two bytes are a 16-bit big-endian length prefix (0 for a read), the
    convention of the vendor's whole 0x10xx opcode family. The vendor polls
    for 0xF089 as the reply (0x1111 for device type 0x200).
    """
    return _packet(target, OP_READ_CHANNEL_ATTR, b"\x00\x00", source)


def build_write_channel_attributes(
    target: DeviceAddress, values: Sequence[int], source: DeviceAddress = DEFAULT_SOURCE
) -> Packet:
    """0x1009 ``[len_hi, len_lo, attr_ch1, ...]`` → 0xF08B (TfrmMain.ModifyChnsChange).  # UNVERIFIED

    ``len`` is the total buffer length including the prefix (``N + 2`` —
    exactly what ModifyChnsChange writes with ``iStack_10 = param_4 + 2``).
    Values: :data:`CHANNEL_ATTR_BREAK` (0) / :data:`CHANNEL_ATTR_GRADUAL` (1).
    """
    table = _channel_bytes(values, "channel attribute")
    length = len(table) + 2
    return _packet(target, OP_WRITE_CHANNEL_ATTR, bytes([length >> 8, length & 0xFF]) + table, source)


def parse_channel_attributes(payload: bytes) -> list[int]:
    """0xF089 → per-channel attribute bytes, stripping a 16-bit length prefix if present.  # UNVERIFIED"""
    if len(payload) >= 2 and int.from_bytes(payload[:2], "big") in (len(payload), len(payload) - 2):
        return list(payload[2:])
    return list(payload)


async def read_channel_attributes(bus: SmartG4Bus, target: DeviceAddress, retries: int = 2) -> list[int] | None:
    reply = await _reply(bus, build_read_channel_attributes(target), OP_READ_CHANNEL_ATTR_RESP, retries=retries)
    return None if reply is None else parse_channel_attributes(reply.payload)


async def write_channel_attributes(bus: SmartG4Bus, target: DeviceAddress, values: Sequence[int]) -> bool:
    return await _acked(bus, build_write_channel_attributes(target, values), OP_WRITE_CHANNEL_ATTR_RESP)


# ---------------------------------------------------------------------------
# Power-on resume ("Scene Resume")
# ---------------------------------------------------------------------------


def build_read_power_on_flag(
    target: DeviceAddress, source: DeviceAddress = DEFAULT_SOURCE, multisensor: bool = False
) -> Packet:
    """0xF051, empty → 0xF052 ``[mode]`` (TfrmMain.ReadPowerOnResumeQueFlag, SDK Read_Power_On).

    ``multisensor=True`` sends 0xD201 → 0xD202 instead
    (TfrmMain.ReadMultiSensorPowerOnResume), the read that pairs with the
    vendor's 0xD203 write.
    """
    if multisensor:
        return _packet(target, OP_READ_POWER_ON_FLAG_MULTISENSOR, b"", source)
    return _packet(target, OP_READ_POWER_ON_FLAG, b"", source)


def build_write_power_on_flag(
    target: DeviceAddress, mode: int, source: DeviceAddress = DEFAULT_SOURCE, sdk: bool = False
) -> Packet:
    """``[mode]`` → vendor 0xD203 (ack 0xD204) or, with ``sdk=True``, SDK 0xF053 (ack 0xF054).

    TfrmMain.ModifyPowerOnResumeQueFlag sends an opaque caller-built array
    with opcode 0xD203; the SDK's Write_Power_On is 0xF053. Both are offered.
    # UNVERIFIED: a single mode byte is assumed (the vendor form
    frmEditPoweronResume has one choice: "No restore before power off" /
    "Restore to previous status after power on").
    """
    if not 0 <= mode <= 255:
        raise ValueError("mode must fit in a byte")
    opcode = OP_WRITE_POWER_ON_FLAG_SDK if sdk else OP_WRITE_POWER_ON_FLAG
    return _packet(target, opcode, bytes([mode]), source)


def parse_power_on_flag(payload: bytes) -> int:
    """0xF052 / 0xD202 ``[mode]``."""
    if not payload:
        raise ValueError("empty power-on flag payload")
    return payload[0]


async def read_power_on_flag(
    bus: SmartG4Bus, target: DeviceAddress, retries: int = 2, multisensor: bool = False
) -> int | None:
    packet = build_read_power_on_flag(target, multisensor=multisensor)
    response = OP_READ_POWER_ON_FLAG_MULTISENSOR_RESP if multisensor else OP_READ_POWER_ON_FLAG_RESP
    reply = await _reply(bus, packet, response, retries=retries)
    return None if reply is None else parse_power_on_flag(reply.payload)


async def write_power_on_flag(bus: SmartG4Bus, target: DeviceAddress, mode: int, sdk: bool = False) -> bool:
    packet = build_write_power_on_flag(target, mode, sdk=sdk)
    response = OP_WRITE_POWER_ON_FLAG_SDK_RESP if sdk else OP_WRITE_POWER_ON_FLAG_RESP
    return await _acked(bus, packet, response)


def build_read_power_on_scenes(
    target: DeviceAddress, source: DeviceAddress = DEFAULT_SOURCE, sdk: bool = False
) -> Packet:
    """Vendor 0xF059 → 0xF05A, or SDK 0xF055 → 0xF056 (Read_Scene_Power_On); empty payload.

    TfrmMain.ReadPowerOnResumeQue uses 0xF059 (and stores 0x17 as the
    calling form id). Response: the per-area resume table.  # UNVERIFIED
    layout — the vendor form frmSetPowerOnResumeQue edits "Resume Mode",
    "Scene No." and "Delay Time" per area, so expect three bytes per zone;
    :func:`parse_power_on_scenes` returns the raw bytes.
    """
    return _packet(target, OP_READ_POWER_ON_SCENE_SDK if sdk else OP_READ_POWER_ON_SCENE, b"", source)


def build_write_power_on_scenes(
    target: DeviceAddress, table: Sequence[int], source: DeviceAddress = DEFAULT_SOURCE
) -> Packet:
    """0xF057 ``[table...]`` → ack 0xF058 (TfrmMain.ModifyPowerOnResumeQue, SDK Modify_Scene_Power_On).

    The vendor passes an opaque caller-built array straight through, so
    ``table`` is sent verbatim.  # UNVERIFIED — candidate layout, from the
    frmSetPowerOnResumeQue fields, is ``[mode, scene, delay]`` per zone
    (zone 1 first), or a single ``[zone, mode, scene, delay]`` entry.
    Write what you read back from :func:`read_power_on_scenes`, edited.
    """
    return _packet(target, OP_WRITE_POWER_ON_SCENE, _channel_bytes(table, "power-on table"), source)


def parse_power_on_scenes(payload: bytes) -> list[int]:
    """0xF05A / 0xF056: raw per-zone resume table.  # UNVERIFIED"""
    return list(payload)


async def read_power_on_scenes(
    bus: SmartG4Bus, target: DeviceAddress, retries: int = 2, sdk: bool = False
) -> list[int] | None:
    packet = build_read_power_on_scenes(target, sdk=sdk)
    response = OP_READ_POWER_ON_SCENE_SDK_RESP if sdk else OP_READ_POWER_ON_SCENE_RESP
    reply = await _reply(bus, packet, response, retries=retries)
    return None if reply is None else parse_power_on_scenes(reply.payload)


async def write_power_on_scenes(bus: SmartG4Bus, target: DeviceAddress, table: Sequence[int]) -> bool:
    return await _acked(bus, build_write_power_on_scenes(target, table), OP_WRITE_POWER_ON_SCENE_RESP)


# ---------------------------------------------------------------------------
# Load information / load test (relays with "load status feedback")
# ---------------------------------------------------------------------------


def build_read_load_info(target: DeviceAddress, source: DeviceAddress = DEFAULT_SOURCE) -> Packet:
    """0xE027, empty → 0xE028 (TfrmMain.ReadLoadInfo, "Reading load information").  Layout UNVERIFIED."""
    return _packet(target, OP_READ_LOAD_INFO, b"", source)


def build_start_load_test(target: DeviceAddress, source: DeviceAddress = DEFAULT_SOURCE) -> Packet:
    """0xE029, empty → 0xE02A (TfrmMain.StartLoadTest).

    The vendor warns "Load test will change the online status" — the module
    pulses its outputs to detect connected loads.
    """
    return _packet(target, OP_START_LOAD_TEST, b"", source)


def build_read_load_power(target: DeviceAddress, source: DeviceAddress = DEFAULT_SOURCE) -> Packet:
    """0xE025, empty → 0xE026 (TfrmMain.ReadLoadPower, "Reading load status monitor").  Layout UNVERIFIED."""
    return _packet(target, OP_READ_LOAD_POWER, b"", source)


def parse_load_bytes(payload: bytes) -> list[int]:
    """0xE026 / 0xE028 / 0xE02A: returned as raw per-channel bytes.  # UNVERIFIED"""
    return list(payload)


async def read_load_info(bus: SmartG4Bus, target: DeviceAddress, retries: int = 2) -> list[int] | None:
    reply = await _reply(bus, build_read_load_info(target), OP_READ_LOAD_INFO_RESP, retries=retries)
    return None if reply is None else parse_load_bytes(reply.payload)


async def start_load_test(bus: SmartG4Bus, target: DeviceAddress, retries: int = 2) -> list[int] | None:
    reply = await _reply(bus, build_start_load_test(target), OP_START_LOAD_TEST_RESP, retries=retries, timeout=5.0)
    return None if reply is None else parse_load_bytes(reply.payload)


async def read_load_power(bus: SmartG4Bus, target: DeviceAddress, retries: int = 2) -> list[int] | None:
    reply = await _reply(bus, build_read_load_power(target), OP_READ_LOAD_POWER_RESP, retries=retries)
    return None if reply is None else parse_load_bytes(reply.payload)


# ---------------------------------------------------------------------------
# Zone table ("device config"): which zone each channel belongs to
# ---------------------------------------------------------------------------


@dataclass
class ZoneConfig:
    zone_count: int
    zones: list[int]          # zone number per channel, channel 1 first

    def as_dict(self) -> dict[str, Any]:
        return {"zone_count": self.zone_count, "zones": self.zones}

    def channels_in_zone(self, zone: int) -> list[int]:
        return [i + 1 for i, z in enumerate(self.zones) if z == zone]


def build_read_zones(target: DeviceAddress, source: DeviceAddress = DEFAULT_SOURCE) -> Packet:
    """0x0004, empty → 0x0005 (TfrmMain.ReadDeviceConfig plain branch; SDK Read_Setting_Zones)."""
    return _packet(target, OP_READ_ZONES, b"", source)


def build_write_zones(
    target: DeviceAddress, zone_count: int, zones: Sequence[int], source: DeviceAddress = DEFAULT_SOURCE
) -> Packet:
    """0x0006 ``[subnet, device, zone_count, zone_ch1, ...]`` → ack 0x0007.

    TfrmMain.ModifyDeviceConfig (plain branch) puts the TARGET's own subnet
    and device id in front of the table (TfrmDBToNet.DownloadZone fills the
    table from tblChns.ZoneIndex and zone_count from ``CountZone``).
    """
    if not 0 <= zone_count <= 255:
        raise ValueError("zone_count must fit in a byte")
    table = _channel_bytes(zones, "zone")
    return _packet(
        target, OP_WRITE_ZONES, bytes([target.subnet, target.device, zone_count]) + table, source
    )


def parse_zones(payload: bytes) -> ZoneConfig:
    """0x0005 ``[zone_count, zone_ch1, zone_ch2, ...]``.

    # UNVERIFIED: mirrors the write payload minus the address echo. If the
    module echoes ``[subnet, device]`` first, ``zone_count`` will read as the
    subnet — compare with the known address before trusting it.
    """
    if not payload:
        raise ValueError("empty 0x0005 payload")
    return ZoneConfig(zone_count=payload[0], zones=list(payload[1:]))


async def read_zones(bus: SmartG4Bus, target: DeviceAddress, retries: int = 2) -> ZoneConfig | None:
    reply = await _reply(bus, build_read_zones(target), OP_READ_ZONES_RESP, retries=retries)
    return None if reply is None else parse_zones(reply.payload)


async def write_zones(bus: SmartG4Bus, target: DeviceAddress, zone_count: int, zones: Sequence[int]) -> bool:
    return await _acked(bus, build_write_zones(target, zone_count, zones), OP_WRITE_ZONES_RESP)


# ---------------------------------------------------------------------------
# Network parameters (IP-capable modules: RSIP, Zone-Beast, timers, ...)
# ---------------------------------------------------------------------------


@dataclass
class NetInfo:
    ip: str
    gateway: str
    mac: bytes           # 6 bytes ("IPMAC1..6" in the vendor DB)
    port: int
    extra: bytes = b""   # bytes 16.. of the 0xF038 payload (DMX channels/port on DMX gateways)

    def as_dict(self) -> dict[str, Any]:
        return {
            "ip": self.ip,
            "gateway": self.gateway,
            "mac": ":".join(f"{b:02x}" for b in self.mac),
            "port": self.port,
            "extra": self.extra.hex(),
        }


def _ip_bytes(text: str) -> bytes:
    parts = text.split(".")
    if len(parts) != 4:
        raise ValueError(f"bad IPv4 address {text!r}")
    return bytes(int(p) for p in parts)


def build_read_net_info(target: DeviceAddress, source: DeviceAddress = DEFAULT_SOURCE) -> Packet:
    """0xF037, empty → 0xF038 (TfrmMain.ReadDeviceNetInfo; SDK Read_QueControler_IP_Parameter)."""
    return _packet(target, OP_READ_NET_INFO, b"", source)


def build_write_net_info(
    target: DeviceAddress,
    ip: str,
    gateway: str,
    mac: bytes,
    port: int,
    extra: bytes = b"\x00\x00\x00\x00",
    source: DeviceAddress = DEFAULT_SOURCE,
) -> Packet:
    """0xF039 ``[ip4][gateway4][mac6][port_be2][extra4]`` (20 bytes) → ack 0xF03A.

    TfrmMain.ModifyNetInfo copies 14 bytes from the form (IP, RouteIP,
    IPMAC1..6 — TfrmQueControl.bitbtnModifyNetInfoClick), writes the port
    big-endian at 14..15 and four more bytes at 16..19 (zeros / stack
    leftovers for ordinary modules; DMX gateways use the 19-byte variant
    with ``[dmx_channels, dmx_port_be2]`` there).
    """
    if len(mac) != 6:
        raise ValueError("mac must be 6 bytes")
    if not 0 <= port <= 0xFFFF:
        raise ValueError("port must be 0..65535")
    extra = bytes(extra).ljust(4, b"\x00")[:4]
    payload = _ip_bytes(ip) + _ip_bytes(gateway) + bytes(mac) + bytes([port >> 8, port & 0xFF]) + extra
    return _packet(target, OP_WRITE_NET_INFO, payload, source)


def parse_net_info(payload: bytes) -> NetInfo:
    """0xF038 ``[ip4][gateway4][mac6][port_be2][extra...]``.

    # UNVERIFIED: assumed to mirror the 0xF039 write layout; the vendor's
    TfrmMain.ShowDeviceNetInfo stores the same fields (IP, RouteIP,
    IPMAC1-6, Port, DMXChannels, DMXPort) into tmpDevice but the byte
    offsets are register-mangled in the decompile.
    """
    if len(payload) < 16:
        raise ValueError(f"0xF038 payload too short: {len(payload)}")
    return NetInfo(
        ip=".".join(str(b) for b in payload[0:4]),
        gateway=".".join(str(b) for b in payload[4:8]),
        mac=bytes(payload[8:14]),
        port=int.from_bytes(payload[14:16], "big"),
        extra=bytes(payload[16:]),
    )


async def read_net_info(bus: SmartG4Bus, target: DeviceAddress, retries: int = 2) -> NetInfo | None:
    reply = await _reply(bus, build_read_net_info(target), OP_READ_NET_INFO_RESP, retries=retries)
    return None if reply is None else parse_net_info(reply.payload)


async def write_net_info(
    bus: SmartG4Bus, target: DeviceAddress, ip: str, gateway: str, mac: bytes, port: int, extra: bytes = b""
) -> bool:
    return await _acked(bus, build_write_net_info(target, ip, gateway, mac, port, extra), OP_WRITE_NET_INFO_RESP)


# ---------------------------------------------------------------------------
# MAC, bus address, online scan
# ---------------------------------------------------------------------------


def _mac8(mac: bytes | str) -> bytes:
    if isinstance(mac, str):
        mac = bytes(int(part, 16) for part in mac.replace("-", ":").split(":"))
    if len(mac) != MAC_LEN:
        raise ValueError(f"S-BUS MACs are {MAC_LEN} bytes, got {len(mac)}")
    return bytes(mac)


def build_write_mac(target: DeviceAddress, mac: bytes | str, source: DeviceAddress = DEFAULT_SOURCE) -> Packet:
    """0xF001 ``[mac8]`` → ack 0xF002 (TfrmMain.ModifyDeviceMAC; SDK Mac_Address_Modify)."""
    return _packet(target, OP_WRITE_MAC, _mac8(mac), source)


def build_modify_address_by_mac(
    mac: bytes | str,
    new_address: DeviceAddress,
    target: DeviceAddress = BROADCAST,
    source: DeviceAddress = DEFAULT_SOURCE,
) -> Packet:
    """0xF005 ``[mac8, new_subnet, new_device]`` → ack 0xF006.

    TfrmMain.ModifyObjSubNetIDAndObjDeviceID: bytes 8/9 are the NEW subnet
    and device id; the module is selected by its MAC, so the frame is
    normally broadcast (the vendor sets its target globals to the new
    address, i.e. it addresses the frame to where the device will be — send
    to ``BROADCAST`` unless you know better).
    """
    payload = _mac8(mac) + bytes([new_address.subnet, new_address.device])
    return _packet(target, OP_MODIFY_ADDRESS_BY_MAC, payload, source)


def build_read_mac(target: DeviceAddress = BROADCAST, source: DeviceAddress = DEFAULT_SOURCE) -> Packet:
    """0xF003, empty → 0xF004 ``[mac8, name20]`` (TfrmMain.ReadBroadcastMAC / ReadAllOnLineDevice).

    ReadAllOnLineDevice sends this to ``<subnet>.0xFF`` twice, one second
    apart, then collects every 0xF004 for five seconds.
    """
    return _packet(target, OP_READ_MAC, b"", source)


def build_check_online(target: DeviceAddress, source: DeviceAddress = DEFAULT_SOURCE) -> Packet:
    """0xF065, empty → 0xF066 (TfrmMain.CheckDeviceOnLine; SDK Deivce_On_Line)."""
    return _packet(target, OP_CHECK_ONLINE, b"", source)


@dataclass
class OnlineDevice:
    address: DeviceAddress
    mac: bytes
    name: str | None
    device_type: int = 0

    def as_dict(self) -> dict[str, Any]:
        return {
            "address": str(self.address),
            "mac": ":".join(f"{b:02x}" for b in self.mac),
            "name": self.name,
            "device_type": self.device_type,
        }


def parse_mac_response(payload: bytes) -> tuple[bytes, str | None]:
    """0xF004 ``[mac8, name20]`` (confirmed live; same as commands.py 0xF004)."""
    if len(payload) < MAC_LEN:
        raise ValueError(f"0xF004 payload too short: {len(payload)}")
    return bytes(payload[:MAC_LEN]), decode_name(payload[MAC_LEN:MAC_LEN + 20])


async def write_mac(bus: SmartG4Bus, target: DeviceAddress, mac: bytes | str) -> bool:
    return await _acked(bus, build_write_mac(target, mac), OP_WRITE_MAC_RESP)


async def modify_address_by_mac(
    bus: SmartG4Bus, mac: bytes | str, new_address: DeviceAddress, target: DeviceAddress = BROADCAST
) -> bool:
    """Re-address the module with ``mac`` to ``new_address`` (0xF005 → 0xF006)."""
    packet = build_modify_address_by_mac(mac, new_address, target)
    mac8 = _mac8(mac)
    try:
        await request(
            bus, target, packet.opcode, packet.payload, OP_MODIFY_ADDRESS_BY_MAC_RESP,
            match=lambda p: p.source == new_address or p.payload[:MAC_LEN] == mac8 or target != BROADCAST,
        )
        return True
    except (TimeoutError, asyncio.TimeoutError):
        return False


async def check_online(bus: SmartG4Bus, target: DeviceAddress, retries: int = 2) -> bool:
    packet = build_check_online(target)
    try:
        await request(bus, target, packet.opcode, packet.payload, OP_CHECK_ONLINE_RESP, retries=retries, timeout=1.0)
        return True
    except (TimeoutError, asyncio.TimeoutError):
        return False


async def scan_online_devices(
    bus: SmartG4Bus, subnet: int | None = None, listen: float = 5.0
) -> list[OnlineDevice]:
    """Vendor-style scan: 0xF003 to ``subnet.255`` (or 255.255), collect 0xF004s.

    Every module replies with its MAC and 20-byte name; the reply's source
    address is the module's bus address.
    """
    target = BROADCAST if subnet is None else DeviceAddress(subnet, 0xFF)
    found: dict[DeviceAddress, OnlineDevice] = {}

    def collect(packet: Packet, _parsed: dict[str, Any] | None) -> None:
        if packet.opcode != OP_READ_MAC_RESP or packet.source in found:
            return
        try:
            mac, name = parse_mac_response(packet.payload)
        except ValueError:
            return
        found[packet.source] = OnlineDevice(packet.source, mac, name, packet.source_type)

    unsubscribe = bus.on_packet(collect)
    try:
        bus.send(target, OP_READ_MAC, payload=b"")
        await asyncio.sleep(1.0)
        bus.send(target, OP_READ_MAC, payload=b"")
        await asyncio.sleep(max(0.0, listen - 1.0))
    finally:
        unsubscribe()
    return sorted(found.values(), key=lambda d: (d.address.subnet, d.address.device))


# ---------------------------------------------------------------------------
# Timer module channel enable (0xD0xx family — owned by the timer feature)
# ---------------------------------------------------------------------------


def build_timer_read_channel_enable(
    target: DeviceAddress, index: int, source: DeviceAddress = DEFAULT_SOURCE
) -> Packet:
    """0xD02C ``[index]`` → 0xD02D (TfrmMain.ReadChannelEnable, frmTimer / frmEditChannelEnable)."""
    return _packet(target, OP_TIMER_READ_CHANNEL_ENABLE, bytes([index]), source)


def build_timer_write_channel_enable(
    target: DeviceAddress, index: int, enabled: int, source: DeviceAddress = DEFAULT_SOURCE
) -> Packet:
    """0xD02E ``[index, enabled]`` → 0xD02F (TfrmMain.ModifyTimerChannelEnable).

    The decompile stores ``param_5`` first and ``param_4`` second; with the
    Delphi calling order (form, subnet, device, enable, index) that is
    ``[index, enable]``.  # UNVERIFIED which byte is which. Values per
    lang_en.ini [ChannelEnable]: 0 = Off, 1 = On.
    """
    return _packet(target, OP_TIMER_WRITE_CHANNEL_ENABLE, bytes([index, enabled]), source)


__all__ = [name for name in dir() if name.startswith(("OP_", "LIMIT_", "POWER_ON_", "NEW_RELAY_", "CHANNEL_ATTR_", "build_", "parse_", "read_", "write_"))] + [
    "ChannelLimits", "NetInfo", "OnlineDevice", "ZoneConfig",
    "LOAD_TYPES", "LED_DRIVER_LOAD_TYPES", "DEFAULT_SOURCE", "MAC_LEN",
    "request", "check_online", "modify_address_by_mac", "scan_online_devices", "start_load_test",
]
