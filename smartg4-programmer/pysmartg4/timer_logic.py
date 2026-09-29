"""Timer / Logic module protocol (Smart-G4 "SB-LOGIC" / HDL logic timer).

Everything here was recovered from the Ghidra decompilation of the vendor's
"Smart Cloud Configuration V16.38" tool. Function names quoted in the
docstrings are the Delphi debug symbols (``TfrmMain.ReadTimerDate`` etc.).
For every request the send opcode is the 16-bit immediate assigned right
before ``TfrmMain.SendAddBuf`` in that function's body and the reply opcode
is the value the function then polls for in the "last received opcode"
global (``*PTR_DAT_01321158 == 0x....``). Reply *layouts* come from the
timer response dispatcher (``FUN_00f9f1a8``) and the ``TfrmMain.Show*``
handlers it calls.

NOTE: ``docs/smartcloud_method_opcodes_raw.txt`` is shifted by one function
(each method is listed with the opcode of the *next* method in the binary);
nothing in this module is taken from that table.

All frames are PLAIN 0xAAAA S-BUS frames (:class:`~pysmartg4.packet.Packet`).
The reply opcode is always request + 1. Writes are acknowledged with a
single status byte: 0xF8 = success, 0xF5 = failure.

Confidence, per family (details in ``docs/features/timer_logic_sensors.md``):

============================  ======================  =======================
feature                       request (vendor func)   reply / layout
============================  ======================  =======================
date & time                   0xD000 / 0xD002         0xD001 8 bytes     HIGH
latitude / longitude / TZ     0xD04E / 0xD050         0xD04F 6-7 bytes   HIGH/MED
sunrise & sunset for a date   0xD066 [yy mm dd]       0xD067 4 bytes     HIGH
universal-switch snapshot     0xF12E                  0xF12F 24 bytes    HIGH
channel enable / remark       0xD02C 0xD02E 0xD054..  +1                 HIGH/MED
channel running status        0xD064 [ch]             0xD065             LOW
day modes / mode enable       0xD044 0xD046 0xD06C..  +1                 LOW
day-mode / day-type remarks   0xD040 0xD042 0xD03x    +1                 MED
groups                        0xD060 0xD062 0xD012..  +1                 MED/LOW
holidays / rest days / spans  0xD028 0xD02A 0xD024..  +1                 MED/LOW
seasons                       0xD03E / 0xD022         0xD03F / 0xD023    LOW
logic tables                  0xDA00 0xD998 0xDA38..  +1                 LOW
vacation setting              0x0116                  0x0117             LOW
============================  ======================  =======================

"HIGH" = opcode *and* payload layout read straight off the decompile (send
routine + reply handler); "MED" = opcode certain, layout inferred from the
matching write / a partially readable handler; "LOW" = opcode certain,
layout guessed (marked ``# UNVERIFIED``).

Most of these opcodes have no entry in :mod:`pysmartg4.commands`, so
:meth:`SmartG4Bus.request` cannot be used for them; :func:`request` below
implements the same send-and-await logic through the public
``on_packet``/``send`` API only.
"""

from __future__ import annotations

import asyncio
import datetime as _dt
from dataclasses import dataclass, field
from typing import Any, Callable, Sequence

from .bus import SmartG4Bus
from .naming import decode_name, encode_name
from .packet import DeviceAddress, Packet

# Placeholder source used by the pure ``build_*`` helpers; the bus stamps
# its own sender address / type / signature when it actually transmits.
DEFAULT_SOURCE = DeviceAddress(0xEE, 0xEE)

ACK_OK = 0xF8
ACK_FAIL = 0xF5

REMARK_LEN = 20

# ---------------------------------------------------------------------------
# Opcodes (request, reply = request + 1)
# ---------------------------------------------------------------------------

# TfrmMain.ReadTimerDate / ModifyTimerDate
OP_READ_DATE = 0xD000
OP_READ_DATE_RESP = 0xD001
OP_WRITE_DATE = 0xD002
OP_WRITE_DATE_RESP = 0xD003

# TfrmMain.ReadLatitudeAndLongitude / ModifyTimerLatitudeLongitude
OP_READ_LOCATION = 0xD04E
OP_READ_LOCATION_RESP = 0xD04F
OP_WRITE_LOCATION = 0xD050
OP_WRITE_LOCATION_RESP = 0xD051

# TfrmMain.ReadSunriseAndSundown
OP_READ_SUNRISE = 0xD066
OP_READ_SUNRISE_RESP = 0xD067

# TfrmMain.ReadBroadcastTimerStatus (universal switch 1..24 snapshot)
OP_READ_UNIVERSAL_SWITCHES = 0xF12E
OP_READ_UNIVERSAL_SWITCHES_RESP = 0xF12F

# TfrmMain.ReadChannelEnable / ModifyTimerChannelEnable
OP_READ_CHANNEL_ENABLE = 0xD02C
OP_READ_CHANNEL_ENABLE_RESP = 0xD02D
OP_WRITE_CHANNEL_ENABLE = 0xD02E
OP_WRITE_CHANNEL_ENABLE_RESP = 0xD02F

# TfrmMain.ReadChannelRemark / ModifyTimerChannelRemark
OP_READ_CHANNEL_REMARK = 0xD054
OP_READ_CHANNEL_REMARK_RESP = 0xD055
OP_WRITE_CHANNEL_REMARK = 0xD052
OP_WRITE_CHANNEL_REMARK_RESP = 0xD053

# TfrmMain.ReadTimerCurChannelRunStatus
OP_READ_CHANNEL_RUN_STATUS = 0xD064
OP_READ_CHANNEL_RUN_STATUS_RESP = 0xD065

# TfrmMain.ReadTimerAllModeEnable
OP_READ_ALL_MODE_ENABLE = 0xD06C
OP_READ_ALL_MODE_ENABLE_RESP = 0xD06D

# TfrmMain.ReadDayModeContent / ModifyTimerDayModeContent
OP_READ_DAY_MODE = 0xD044
OP_READ_DAY_MODE_RESP = 0xD045
OP_WRITE_DAY_MODE = 0xD046
OP_WRITE_DAY_MODE_RESP = 0xD047

# TfrmMain.ReadDayModeRemark / ModifyDayModeRemark
OP_READ_DAY_MODE_REMARK = 0xD040
OP_READ_DAY_MODE_REMARK_RESP = 0xD041
OP_WRITE_DAY_MODE_REMARK = 0xD042
OP_WRITE_DAY_MODE_REMARK_RESP = 0xD043

# TfrmMain.ReadWorkingDayRemark / ReadRestDayRemark / ReadFeastRemark and the
# three branches of TfrmMain.ModifyTimerDayRemark (kind 0 / 1 / 2)
OP_READ_WORKDAY_REMARK = 0xD030
OP_READ_WORKDAY_REMARK_RESP = 0xD031
OP_WRITE_WORKDAY_REMARK = 0xD032
OP_WRITE_WORKDAY_REMARK_RESP = 0xD033
OP_READ_RESTDAY_REMARK = 0xD034
OP_READ_RESTDAY_REMARK_RESP = 0xD035
OP_WRITE_RESTDAY_REMARK = 0xD036
OP_WRITE_RESTDAY_REMARK_RESP = 0xD037
OP_READ_HOLIDAY_REMARK = 0xD03A
OP_READ_HOLIDAY_REMARK_RESP = 0xD03B
OP_WRITE_HOLIDAY_REMARK = 0xD03C
OP_WRITE_HOLIDAY_REMARK_RESP = 0xD03D

# TfrmMain.ReadFeastTable / ModifyTimerFeast ("holiday table")
OP_READ_HOLIDAY = 0xD028
OP_READ_HOLIDAY_RESP = 0xD029
OP_WRITE_HOLIDAY = 0xD02A
OP_WRITE_HOLIDAY_RESP = 0xD02B

# TfrmMain.ReadRestDaySetup / ModifyTimerRestDay
OP_READ_RESTDAY = 0xD024
OP_READ_RESTDAY_RESP = 0xD025
OP_WRITE_RESTDAY = 0xD026
OP_WRITE_RESTDAY_RESP = 0xD027

# TfrmMain.ReadOverDayTable / ModifyTimerOverDay ("span day" table)
OP_READ_SPAN_DAY = 0xD068
OP_READ_SPAN_DAY_RESP = 0xD069
OP_WRITE_SPAN_DAY = 0xD06A
OP_WRITE_SPAN_DAY_RESP = 0xD06B

# TfrmMain.ReadSeasonInfo / ModifySeason
OP_READ_SEASON = 0xD03E
OP_READ_SEASON_RESP = 0xD03F
OP_WRITE_SEASON = 0xD022
OP_WRITE_SEASON_RESP = 0xD023

# Groups: TfrmMain.ReadCountGroup / ReadManyGroup / ReadCountGroupMember /
# ReadGroupMember / ReadGroupMemberNew / ModifyTimerGroupMember(NewVersion) /
# AddNewGroupMember / DeleteGroupMember / ReadGroupRemark /
# ModifyTimerGroupRemark / ModifyTimerGroupName / DeleteTimerGroupName
OP_READ_GROUP_COUNT = 0xD060
OP_READ_GROUP_COUNT_RESP = 0xD061
OP_READ_GROUP_PAGE = 0xD062
OP_READ_GROUP_PAGE_RESP = 0xD063
OP_READ_GROUP_MEMBER_COUNT = 0xD012
OP_READ_GROUP_MEMBER_COUNT_RESP = 0xD013
OP_READ_GROUP_MEMBER = 0xD00A
OP_READ_GROUP_MEMBER_RESP = 0xD00B
OP_READ_GROUP_MEMBER_NEW = 0xD086
OP_READ_GROUP_MEMBER_NEW_RESP = 0xD087
OP_WRITE_GROUP_MEMBER = 0xD01E
OP_WRITE_GROUP_MEMBER_RESP = 0xD01F
OP_DELETE_GROUP_MEMBER = 0xD01C
OP_DELETE_GROUP_MEMBER_RESP = 0xD01D
OP_ADD_GROUP_MEMBER = 0xD008
OP_ADD_GROUP_MEMBER_RESP = 0xD009
OP_READ_GROUP_REMARK = 0xD082
OP_READ_GROUP_REMARK_RESP = 0xD083
OP_WRITE_GROUP_REMARK = 0xD080
OP_WRITE_GROUP_REMARK_RESP = 0xD081
OP_WRITE_GROUP_NAME = 0xD018
OP_WRITE_GROUP_NAME_RESP = 0xD019
OP_DELETE_GROUP_NAME = 0xF71E
OP_DELETE_GROUP_NAME_RESP = 0xF71F

# Logic tables: TfrmMain.hdlReadLogicTimer / hdlModifyLogicTimer /
# hdlReadLogicTableRemark / LogicReadObjRemark / ReadDeviceLogicBlockRemark /
# ReadTimerModeLogicOfMonitor / ReadTimerSensorLogicOfMonitor
OP_READ_LOGIC_TIMER = 0xDA00
OP_READ_LOGIC_TIMER_RESP = 0xDA01
OP_WRITE_LOGIC_TIMER = 0xD998
OP_WRITE_LOGIC_TIMER_RESP = 0xD999
OP_READ_LOGIC_TABLE_REMARK = 0xDA38
OP_READ_LOGIC_TABLE_REMARK_RESP = 0xDA39
OP_READ_LOGIC_OBJECT_REMARK = 0xDA34
OP_READ_LOGIC_OBJECT_REMARK_RESP = 0xDA35
OP_READ_LOGIC_BLOCK_REMARK = 0xD992
OP_READ_LOGIC_BLOCK_REMARK_RESP = 0xD993
OP_READ_MODE_LOGIC_MONITOR = 0xD06E
OP_READ_MODE_LOGIC_MONITOR_RESP = 0xD06F
OP_READ_SENSOR_LOGIC_MONITOR = 0xD070
OP_READ_SENSOR_LOGIC_MONITOR_RESP = 0xD071

# TfrmMain.ReadVacationSetting — NOT a 0xD0xx opcode: the decompile sends
# 0x0116 and identifies the reply by echoed bytes rather than by opcode.
OP_READ_VACATION = 0x0116
OP_READ_VACATION_RESP = 0x0117

# TfrmMain.ReadTimeForCanUseOrNo — a motion-sensor query ("time function
# usable?"), kept here because the brief listed it with the timer family.
OP_READ_TIME_USABLE = 0xD946
OP_READ_TIME_USABLE_RESP = 0xD947

WEEKDAY_NAMES = {
    0: "Sunday", 1: "Monday", 2: "Tuesday", 3: "Wednesday",
    4: "Thursday", 5: "Friday", 6: "Saturday",
}  # UNVERIFIED numbering — the module fills the byte in, the tool never reads it


# ---------------------------------------------------------------------------
# Transport helpers
# ---------------------------------------------------------------------------


def _packet(target: DeviceAddress, opcode: int, payload: bytes, source: DeviceAddress) -> Packet:
    return Packet(opcode=opcode, source=source, target=target, payload=bytes(payload))


def _u8(value: int, name: str, maximum: int = 255) -> int:
    value = int(value)
    if not 0 <= value <= maximum:
        raise ValueError(f"{name} {value} not in 0..{maximum}")
    return value


def _s8(value: int, name: str) -> int:
    value = int(value)
    if not -128 <= value <= 127:
        raise ValueError(f"{name} {value} not in -128..127")
    return value & 0xFF


def _u16(value: int, name: str) -> bytes:
    value = int(value)
    if not 0 <= value <= 0xFFFF:
        raise ValueError(f"{name} {value} not in 0..65535")
    return bytes([(value >> 8) & 0xFF, value & 0xFF])


def _s16(value: int, name: str) -> bytes:
    value = int(value)
    if not -32768 <= value <= 32767:
        raise ValueError(f"{name} {value} not in -32768..32767")
    return (value & 0xFFFF).to_bytes(2, "big")


def _signed(byte: int) -> int:
    return byte - 256 if byte > 127 else byte


def _remark(payload: bytes, offset: int) -> str:
    return decode_name(payload[offset : offset + REMARK_LEN]) or ""


def is_ack(payload: bytes) -> bool:
    """True when a write reply carries the vendor's 0xF8 success byte."""
    return len(payload) >= 1 and payload[0] == ACK_OK


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

    Mirrors :meth:`SmartG4Bus.request` (the vendor tool also does 3 attempts
    of 2 s) but takes the reply opcode explicitly, because
    :mod:`pysmartg4.commands` has no entries for these opcodes.
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


async def _write(
    bus: SmartG4Bus, target: DeviceAddress, packet: Packet, response: int, **kw: Any
) -> bool:
    """Send a pre-built write packet and return the 0xF8 ack status."""
    try:
        reply = await request(bus, target, packet.opcode, packet.payload, response, **kw)
    except (TimeoutError, asyncio.TimeoutError):
        return False
    return is_ack(reply.payload)


# ---------------------------------------------------------------------------
# Date & time  — HIGH
#
# TfrmMain.ReadTimerDate sends 0xD000 with an empty payload and polls for
# 0xD001; the reply handler (FUN_00f9ef04, reached from the 0xD001 case of
# FUN_00f9f1a8) shows ``payload[0] + 2000`` as the year, clamps payload[1]
# to 1..12 (month), payload[2] to <=31 (day), payload[4] <=23 (hour),
# payload[5] <=59 (minute), payload[6] <=59 (second) and feeds the last
# byte to GetTimerBatteryStatusNoteFrmStatus. TfrmMain.ModifyTimerDate
# sends 0xD002 with exactly the same 8-byte shape, writing 0 into the
# weekday byte (the module recomputes it) and the trailing byte.
# ---------------------------------------------------------------------------


@dataclass
class TimerDateTime:
    year: int
    month: int
    day: int
    weekday: int
    hour: int
    minute: int
    second: int
    battery_status: int = 0  # raw byte 7; 0 observed as "ok" (UNVERIFIED enum)

    @property
    def datetime(self) -> _dt.datetime | None:
        try:
            return _dt.datetime(self.year, self.month, self.day, self.hour, self.minute, self.second)
        except ValueError:
            return None

    @classmethod
    def from_datetime(cls, value: _dt.datetime) -> "TimerDateTime":
        return cls(value.year, value.month, value.day, 0, value.hour, value.minute, value.second)


def build_read_datetime(target: DeviceAddress, source: DeviceAddress = DEFAULT_SOURCE) -> Packet:
    """0xD000, empty payload -> 0xD001 (TfrmMain.ReadTimerDate)."""
    return _packet(target, OP_READ_DATE, b"", source)


def parse_datetime(payload: bytes) -> TimerDateTime:
    """0xD001 ``[yy, mm, dd, weekday, hh, mi, ss, battery]`` (FUN_00f9ef04)."""
    if len(payload) < 7:
        raise ValueError(f"datetime reply too short: {len(payload)} bytes")
    return TimerDateTime(
        year=2000 + payload[0],
        month=payload[1],
        day=payload[2],
        weekday=payload[3],
        hour=payload[4],
        minute=payload[5],
        second=payload[6],
        battery_status=payload[7] if len(payload) > 7 else 0,
    )


def build_write_datetime(
    target: DeviceAddress, value: _dt.datetime | TimerDateTime, source: DeviceAddress = DEFAULT_SOURCE
) -> Packet:
    """0xD002 ``[yy, mm, dd, 0, hh, mi, ss, 0]`` -> 0xD003 (TfrmMain.ModifyTimerDate).

    The tool's caller (TfrmTimer, at 0x00fc9d99) splits its date picker into
    year/month/day and reads three edits for hour/minute/second; the byte
    order is exactly the read layout with weekday and byte 7 zeroed.
    """
    if isinstance(value, _dt.datetime):
        value = TimerDateTime.from_datetime(value)
    year = value.year - 2000 if value.year >= 2000 else value.year
    payload = bytes(
        [
            _u8(year, "year", 99),
            _u8(value.month, "month", 12),
            _u8(value.day, "day", 31),
            0,
            _u8(value.hour, "hour", 23),
            _u8(value.minute, "minute", 59),
            _u8(value.second, "second", 59),
            0,
        ]
    )
    return _packet(target, OP_WRITE_DATE, payload, source)


async def read_datetime(bus: SmartG4Bus, target: DeviceAddress, **kw: Any) -> TimerDateTime | None:
    try:
        reply = await request(bus, target, OP_READ_DATE, b"", OP_READ_DATE_RESP, **kw)
    except (TimeoutError, asyncio.TimeoutError):
        return None
    return parse_datetime(reply.payload)


async def write_datetime(
    bus: SmartG4Bus, target: DeviceAddress, value: _dt.datetime | TimerDateTime, **kw: Any
) -> bool:
    """Set the module clock. Returns True on the 0xF8 ack."""
    return await _write(bus, target, build_write_datetime(target, value), OP_WRITE_DATE_RESP, **kw)


# ---------------------------------------------------------------------------
# Latitude / longitude / time zone  — HIGH (read) / MED (write tail)
#
# TfrmMain.ReadLatitudeAndLongitude: 0xD04E, empty -> 0xD04F. The handler
# TfrmMain.ShowLatitudeAndLongitude takes payload[0] as a signed latitude
# degree (sign -> N/S radio, abs -> edit), payload[1] latitude minutes,
# payload[2..3] as a signed 16-bit longitude degree (sign -> E/W radio),
# payload[4] longitude minutes and payload[5] as a signed value that is
# looked up in the time-zone combo (0x61c); a further value lands in the
# edit 0x628 which the write side fills from "tz minutes".
#
# TfrmMain.ModifyTimerLatitudeLongitude: 0xD050 -> 0xD051, 7 bytes
# ``[lat_deg, lat_min, lon_deg_hi, lon_deg_lo, lon_min, tz_hours, tz_minutes]``
# — the caller (0x00fc8c5a) signs every component with the N/S / E/W radio
# and negates tz_minutes when tz_hours is negative.
# ---------------------------------------------------------------------------


@dataclass
class TimerLocation:
    latitude_deg: int      # signed, north positive
    latitude_min: int
    longitude_deg: int     # signed, east positive
    longitude_min: int
    tz_hours: int = 0      # signed
    tz_minutes: int = 0    # signed, same sign as tz_hours

    @property
    def latitude(self) -> float:
        sign = -1 if self.latitude_deg < 0 else 1
        return sign * (abs(self.latitude_deg) + abs(self.latitude_min) / 60)

    @property
    def longitude(self) -> float:
        sign = -1 if self.longitude_deg < 0 else 1
        return sign * (abs(self.longitude_deg) + abs(self.longitude_min) / 60)

    @classmethod
    def from_decimal(
        cls, latitude: float, longitude: float, tz_hours: int = 0, tz_minutes: int = 0
    ) -> "TimerLocation":
        def split(value: float) -> tuple[int, int]:
            sign = -1 if value < 0 else 1
            deg = int(abs(value))
            minutes = int(round((abs(value) - deg) * 60))
            if minutes == 60:
                deg, minutes = deg + 1, 0
            return sign * deg, sign * minutes

        lat_d, lat_m = split(latitude)
        lon_d, lon_m = split(longitude)
        return cls(lat_d, lat_m, lon_d, lon_m, tz_hours, tz_minutes)


def build_read_location(target: DeviceAddress, source: DeviceAddress = DEFAULT_SOURCE) -> Packet:
    """0xD04E, empty payload -> 0xD04F (TfrmMain.ReadLatitudeAndLongitude)."""
    return _packet(target, OP_READ_LOCATION, b"", source)


def parse_location(payload: bytes) -> TimerLocation:
    """0xD04F ``[lat_deg, lat_min, lon_deg16, lon_min, tz_h, (tz_m)]``.

    Sign handling per TfrmMain.ShowLatitudeAndLongitude; the seventh byte
    is UNVERIFIED (present in the write, not clearly read by the handler).
    """
    if len(payload) < 5:
        raise ValueError(f"location reply too short: {len(payload)} bytes")
    lon = int.from_bytes(payload[2:4], "big", signed=True)
    return TimerLocation(
        latitude_deg=_signed(payload[0]),
        latitude_min=_signed(payload[1]),
        longitude_deg=lon,
        longitude_min=_signed(payload[4]),
        tz_hours=_signed(payload[5]) if len(payload) > 5 else 0,
        tz_minutes=_signed(payload[6]) if len(payload) > 6 else 0,
    )


def build_write_location(
    target: DeviceAddress, location: TimerLocation, source: DeviceAddress = DEFAULT_SOURCE
) -> Packet:
    """0xD050 7 bytes -> 0xD051 (TfrmMain.ModifyTimerLatitudeLongitude)."""
    payload = (
        bytes([_s8(location.latitude_deg, "latitude_deg"), _s8(location.latitude_min, "latitude_min")])
        + _s16(location.longitude_deg, "longitude_deg")
        + bytes(
            [
                _s8(location.longitude_min, "longitude_min"),
                _s8(location.tz_hours, "tz_hours"),
                _s8(location.tz_minutes, "tz_minutes"),
            ]
        )
    )
    return _packet(target, OP_WRITE_LOCATION, payload, source)


async def read_location(bus: SmartG4Bus, target: DeviceAddress, **kw: Any) -> TimerLocation | None:
    try:
        reply = await request(bus, target, OP_READ_LOCATION, b"", OP_READ_LOCATION_RESP, **kw)
    except (TimeoutError, asyncio.TimeoutError):
        return None
    return parse_location(reply.payload)


async def write_location(
    bus: SmartG4Bus, target: DeviceAddress, location: TimerLocation, **kw: Any
) -> bool:
    return await _write(bus, target, build_write_location(target, location), OP_WRITE_LOCATION_RESP, **kw)


# ---------------------------------------------------------------------------
# Sunrise / sunset  — HIGH
#
# TfrmMain.ReadSunriseAndSundown: 0xD066 ``[yy, mm, dd]`` -> 0xD067. The
# caller (0x00fcc004) first reads the module clock, then passes the last two
# digits of the year, the month and the day. TfrmMain.ShowSunriseAndSundown
# formats payload[0]:payload[1] as "Sunrise (hh mm)" and payload[2]:payload[3]
# as "Sundown (hh mm)".
# ---------------------------------------------------------------------------


@dataclass
class SunTimes:
    sunrise: _dt.time
    sunset: _dt.time


def build_read_sun_times(
    target: DeviceAddress, date: _dt.date, source: DeviceAddress = DEFAULT_SOURCE
) -> Packet:
    """0xD066 ``[yy, mm, dd]`` -> 0xD067 (TfrmMain.ReadSunriseAndSundown)."""
    payload = bytes([_u8(date.year % 100, "year"), _u8(date.month, "month", 12), _u8(date.day, "day", 31)])
    return _packet(target, OP_READ_SUNRISE, payload, source)


def parse_sun_times(payload: bytes) -> SunTimes:
    """0xD067 ``[rise_hh, rise_mm, set_hh, set_mm]`` (TfrmMain.ShowSunriseAndSundown)."""
    if len(payload) < 4:
        raise ValueError(f"sunrise reply too short: {len(payload)} bytes")
    return SunTimes(
        sunrise=_dt.time(payload[0] % 24, payload[1] % 60),
        sunset=_dt.time(payload[2] % 24, payload[3] % 60),
    )


async def read_sun_times(
    bus: SmartG4Bus, target: DeviceAddress, date: _dt.date | None = None, **kw: Any
) -> SunTimes | None:
    date = date or _dt.date.today()
    packet = build_read_sun_times(target, date)
    try:
        reply = await request(bus, target, OP_READ_SUNRISE, packet.payload, OP_READ_SUNRISE_RESP, **kw)
    except (TimeoutError, asyncio.TimeoutError):
        return None
    return parse_sun_times(reply.payload)


# ---------------------------------------------------------------------------
# Universal switch snapshot  — HIGH
#
# TfrmMain.ReadBroadcastTimerStatus sends 0xF12E with an empty payload and
# does not wait; the 0xF12F case of FUN_00f9f1a8 walks payload[0..23] and
# stores byte i as the status of universal switch i+1 (tmpUniversalSwitch).
# ---------------------------------------------------------------------------


def build_read_universal_switches(target: DeviceAddress, source: DeviceAddress = DEFAULT_SOURCE) -> Packet:
    """0xF12E, empty payload -> 0xF12F (TfrmMain.ReadBroadcastTimerStatus)."""
    return _packet(target, OP_READ_UNIVERSAL_SWITCHES, b"", source)


def parse_universal_switches(payload: bytes) -> dict[int, bool]:
    """0xF12F: one status byte per universal switch, switch 1 first (24 max)."""
    return {index + 1: value != 0 for index, value in enumerate(payload[:24])}


async def read_universal_switches(
    bus: SmartG4Bus, target: DeviceAddress, **kw: Any
) -> dict[int, bool] | None:
    try:
        reply = await request(
            bus, target, OP_READ_UNIVERSAL_SWITCHES, b"", OP_READ_UNIVERSAL_SWITCHES_RESP, **kw
        )
    except (TimeoutError, asyncio.TimeoutError):
        return None
    return parse_universal_switches(reply.payload)


# ---------------------------------------------------------------------------
# Timer channels  — HIGH (enable) / MED (remark) / LOW (running status)
# ---------------------------------------------------------------------------


def build_read_channel_enable(
    target: DeviceAddress, channel: int, source: DeviceAddress = DEFAULT_SOURCE
) -> Packet:
    """0xD02C ``[channel]`` -> 0xD02D ``[channel, enabled]`` (TfrmMain.ReadChannelEnable)."""
    return _packet(target, OP_READ_CHANNEL_ENABLE, bytes([_u8(channel, "channel")]), source)


def parse_channel_enable(payload: bytes) -> tuple[int, bool]:
    """0xD02D ``[channel, enabled]`` (TfrmMain.ShowChannelEnable)."""
    if len(payload) < 2:
        raise ValueError("channel enable reply too short")
    return payload[0], payload[1] != 0


def build_write_channel_enable(
    target: DeviceAddress, channel: int, enabled: bool, source: DeviceAddress = DEFAULT_SOURCE
) -> Packet:
    """0xD02E ``[channel, enabled]`` -> 0xD02F (TfrmMain.ModifyTimerChannelEnable).

    The decompile stores ``param_5`` then ``param_4``; with the Delphi
    declaration order (subnet, device, enabled, channel) that is
    ``[channel, enabled]``.  # UNVERIFIED which byte is which
    """
    return _packet(
        target, OP_WRITE_CHANNEL_ENABLE, bytes([_u8(channel, "channel"), 1 if enabled else 0]), source
    )


def build_read_channel_remark(
    target: DeviceAddress, channel: int, source: DeviceAddress = DEFAULT_SOURCE
) -> Packet:
    """0xD054 ``[channel]`` -> 0xD055 (TfrmMain.ReadChannelRemark)."""
    return _packet(target, OP_READ_CHANNEL_REMARK, bytes([_u8(channel, "channel")]), source)


def parse_channel_remark(payload: bytes) -> tuple[int, str]:
    """0xD055 -> (channel, remark).

    TfrmMain.ShowChannelRemark extracts a 20-byte remark starting at
    payload offset 0 (FUN_01277b14(buf, len, 0, out, 20)) and takes the
    channel from the byte that follows; a ``[channel, remark20]`` reply is
    handled too.  # UNVERIFIED which of the two shapes the module sends
    """
    if len(payload) >= REMARK_LEN + 1 and decode_name(payload[1 : REMARK_LEN + 1]) and payload[0] < 0x20:
        return payload[0], _remark(payload, 1)
    remark = _remark(payload, 0)
    channel = payload[REMARK_LEN] if len(payload) > REMARK_LEN else 0
    return channel, remark


def build_write_channel_remark(
    target: DeviceAddress, channel: int, remark: str, source: DeviceAddress = DEFAULT_SOURCE
) -> Packet:
    """0xD052 ``[channel, remark20]`` (21 bytes) -> 0xD053 (TfrmMain.ModifyTimerChannelRemark)."""
    return _packet(
        target, OP_WRITE_CHANNEL_REMARK, bytes([_u8(channel, "channel")]) + encode_name(remark), source
    )


def build_read_channel_run_status(
    target: DeviceAddress, channel: int, source: DeviceAddress = DEFAULT_SOURCE
) -> Packet:
    """0xD064 ``[channel]`` -> 0xD065 (TfrmMain.ReadTimerCurChannelRunStatus)."""
    return _packet(target, OP_READ_CHANNEL_RUN_STATUS, bytes([_u8(channel, "channel")]), source)


@dataclass
class ChannelRunStatus:
    status: int          # payload[0]; TfrmMain.ShowCurChannelRunningStatus column 2
    mode: int            # payload[1]; also cached in a global the tool re-reads
    raw: bytes = b""     # UNVERIFIED — remaining bytes (season/day-type/mode indexes)


def parse_channel_run_status(payload: bytes) -> ChannelRunStatus:
    """0xD065 -> :class:`ChannelRunStatus` (layout LOW confidence)."""
    if len(payload) < 2:
        raise ValueError("channel run status reply too short")
    return ChannelRunStatus(status=payload[0], mode=payload[1], raw=bytes(payload[2:]))


async def read_channel_enable(
    bus: SmartG4Bus, target: DeviceAddress, channel: int, **kw: Any
) -> bool | None:
    try:
        reply = await request(
            bus, target, OP_READ_CHANNEL_ENABLE, bytes([channel]), OP_READ_CHANNEL_ENABLE_RESP,
            match=lambda p: p.payload[:1] == bytes([channel]), **kw,
        )
    except (TimeoutError, asyncio.TimeoutError):
        return None
    return parse_channel_enable(reply.payload)[1]


async def write_channel_enable(
    bus: SmartG4Bus, target: DeviceAddress, channel: int, enabled: bool, **kw: Any
) -> bool:
    return await _write(
        bus, target, build_write_channel_enable(target, channel, enabled), OP_WRITE_CHANNEL_ENABLE_RESP, **kw
    )


async def read_channel_remark(
    bus: SmartG4Bus, target: DeviceAddress, channel: int, **kw: Any
) -> str | None:
    try:
        reply = await request(
            bus, target, OP_READ_CHANNEL_REMARK, bytes([channel]), OP_READ_CHANNEL_REMARK_RESP, **kw
        )
    except (TimeoutError, asyncio.TimeoutError):
        return None
    return parse_channel_remark(reply.payload)[1]


async def write_channel_remark(
    bus: SmartG4Bus, target: DeviceAddress, channel: int, remark: str, **kw: Any
) -> bool:
    return await _write(
        bus, target, build_write_channel_remark(target, channel, remark), OP_WRITE_CHANNEL_REMARK_RESP, **kw
    )


async def read_channel_run_status(
    bus: SmartG4Bus, target: DeviceAddress, channel: int, **kw: Any
) -> ChannelRunStatus | None:
    try:
        reply = await request(
            bus, target, OP_READ_CHANNEL_RUN_STATUS, bytes([channel]), OP_READ_CHANNEL_RUN_STATUS_RESP, **kw
        )
    except (TimeoutError, asyncio.TimeoutError):
        return None
    return parse_channel_run_status(reply.payload)


# ---------------------------------------------------------------------------
# Day modes  — LOW
#
# TfrmMain.ReadTimerAllModeEnable: 0xD06C, 4 bytes ``[p8, p3, p7, p6]`` ->
# 0xD06D. The caller (TfrmTimer.ShowChannelInfoForMonitor) passes the
# channel in the register slot and pushes 1 / 0xEB / two channel-table
# values; FUN_00f97118 then reads payload[0], payload[1] and a bit array
# starting at payload[2] (bits >>1 .. >>4 per byte = per-mode enables).
#
# TfrmMain.ReadDayModeContent: 0xD044, 6 bytes ``[p3, p9, p8, p7, p6, p5]``
# -> 0xD045, shown by TfrmMain.ShowDayModeContent, which inserts into
# tmpDayMode / tmpSensorGroup with the SQL columns ChannelIndex, SeasonIndex,
# DayType, DayDtl, Mode, GroupIndex/SensorGroupIndex, ConditionIndex,
# IsEnable, LowLimit/HighLimit, QtyCount, SubNetID1..5, DeviceID1..5,
# Relation. The byte-level mapping depends on the device type (0xE4 / 0xE6 /
# 0xEA branches) and is NOT recovered; only the raw payload is exposed.
#
# TfrmMain.ModifyTimerDayModeContent: 0xD046 -> 0xD047, header
# ``[p11, p10, p9|p8, p8|0, p7, p6]`` followed by an open array of command
# bytes (the caller copies a grid of Kind/Subnet/Device/Para1/Para2/Para3
# records — the LogicCommands shape).
# ---------------------------------------------------------------------------


def build_read_all_mode_enable(
    target: DeviceAddress, channel: int, a: int = 1, b: int = 0xEB, c: int = 0,
    source: DeviceAddress = DEFAULT_SOURCE,
) -> Packet:
    """0xD06C ``[a, channel, b, c]`` -> 0xD06D (TfrmMain.ReadTimerAllModeEnable).  # UNVERIFIED"""
    return _packet(
        target, OP_READ_ALL_MODE_ENABLE,
        bytes([_u8(a, "a"), _u8(channel, "channel"), _u8(b, "b"), _u8(c, "c")]), source,
    )


def parse_all_mode_enable(payload: bytes) -> dict[str, Any]:
    """0xD06D -> ``{"head": (b0, b1), "bits": [...]}`` (FUN_00f97118).  # UNVERIFIED"""
    bits: list[bool] = []
    for byte in payload[2:]:
        bits.extend(bool((byte >> shift) & 1) for shift in range(8))
    return {"head": (payload[0] if payload else 0, payload[1] if len(payload) > 1 else 0), "bits": bits}


def build_read_day_mode(
    target: DeviceAddress, channel: int, season: int, day_type: int, day_detail: int,
    mode: int, extra: int = 0, source: DeviceAddress = DEFAULT_SOURCE,
) -> Packet:
    """0xD044 6 bytes -> 0xD045 (TfrmMain.ReadDayModeContent).

    Byte order follows the decompile ``[p3, p9, p8, p7, p6, p5]`` with the
    Delphi declaration order guessed from the tmpDayMode key columns
    (ChannelIndex, SeasonIndex, DayType, DayDtl, Mode).  # UNVERIFIED
    """
    payload = bytes(
        [
            _u8(channel, "channel"), _u8(season, "season"), _u8(day_type, "day_type"),
            _u8(day_detail, "day_detail"), _u8(mode, "mode"), _u8(extra, "extra"),
        ]
    )
    return _packet(target, OP_READ_DAY_MODE, payload, source)


def parse_day_mode(payload: bytes) -> dict[str, Any]:
    """0xD045 -> ``{"channel", "season", "raw"}`` (TfrmMain.ShowDayModeContent).  # UNVERIFIED"""
    return {
        "channel": payload[0] if payload else None,
        "season": payload[1] if len(payload) > 1 else None,
        "raw": bytes(payload),
    }


def build_write_day_mode(
    target: DeviceAddress, header: Sequence[int], commands: bytes = b"",
    source: DeviceAddress = DEFAULT_SOURCE,
) -> Packet:
    """0xD046 ``header(6) + commands`` -> 0xD047 (TfrmMain.ModifyTimerDayModeContent).  # UNVERIFIED"""
    if len(header) != 6:
        raise ValueError("day mode header must be 6 bytes")
    return _packet(target, OP_WRITE_DAY_MODE, bytes(_u8(b, "header") for b in header) + bytes(commands), source)


# ---------------------------------------------------------------------------
# Remarks for day modes / working days / rest days / holidays  — MED
#
# TfrmMain.ReadDayModeRemark: 0xD040 ``[p3, p8, p7, p6, p5]`` -> 0xD041 (the
# reply is rendered by TfrmMain.ShowSeasonInfo which extracts a 20-byte
# remark). TfrmMain.ModifyDayModeRemark: 0xD042 ``[p8, p3, p7, p6, p5,
# remark20]`` (25 bytes) -> 0xD043.
#
# TfrmMain.ModifyTimerDayRemark has three branches selected by ``kind``:
#   kind 0 -> 0xD032 ``[index, channel, remark20]``           (working day)
#   kind 1 -> 0xD036 ``[index, channel, sub, remark20]``      (rest day)
#   kind 2 -> 0xD03C ``[sub, channel, remark20]``             (holiday)
# and the matching reads are 0xD030 ``[channel, index]``, 0xD034 ``[sub,
# channel, index]`` and 0xD03A ``[channel, index]`` (TfrmMain.
# ReadWorkingDayRemark / ReadRestDayRemark / ReadFeastRemark).
# ---------------------------------------------------------------------------


def build_read_day_mode_remark(
    target: DeviceAddress, channel: int, a: int, b: int, c: int, d: int,
    source: DeviceAddress = DEFAULT_SOURCE,
) -> Packet:
    """0xD040 ``[channel, a, b, c, d]`` -> 0xD041 (TfrmMain.ReadDayModeRemark).  # UNVERIFIED order"""
    return _packet(
        target, OP_READ_DAY_MODE_REMARK,
        bytes([_u8(channel, "channel"), _u8(a, "a"), _u8(b, "b"), _u8(c, "c"), _u8(d, "d")]), source,
    )


def build_write_day_mode_remark(
    target: DeviceAddress, channel: int, a: int, b: int, c: int, d: int, remark: str,
    source: DeviceAddress = DEFAULT_SOURCE,
) -> Packet:
    """0xD042 ``[a, channel, b, c, d, remark20]`` -> 0xD043 (TfrmMain.ModifyDayModeRemark).  # UNVERIFIED order"""
    payload = bytes([_u8(a, "a"), _u8(channel, "channel"), _u8(b, "b"), _u8(c, "c"), _u8(d, "d")])
    return _packet(target, OP_WRITE_DAY_MODE_REMARK, payload + encode_name(remark), source)


def build_read_workday_remark(
    target: DeviceAddress, channel: int, index: int, source: DeviceAddress = DEFAULT_SOURCE
) -> Packet:
    """0xD030 ``[channel, index]`` -> 0xD031 (TfrmMain.ReadWorkingDayRemark)."""
    return _packet(target, OP_READ_WORKDAY_REMARK, bytes([_u8(channel, "channel"), _u8(index, "index")]), source)


def build_write_workday_remark(
    target: DeviceAddress, channel: int, index: int, remark: str, source: DeviceAddress = DEFAULT_SOURCE
) -> Packet:
    """0xD032 ``[index, channel, remark20]`` -> 0xD033 (TfrmMain.ModifyTimerDayRemark kind 0)."""
    return _packet(
        target, OP_WRITE_WORKDAY_REMARK,
        bytes([_u8(index, "index"), _u8(channel, "channel")]) + encode_name(remark), source,
    )


def build_read_restday_remark(
    target: DeviceAddress, channel: int, index: int, sub: int, source: DeviceAddress = DEFAULT_SOURCE
) -> Packet:
    """0xD034 ``[sub, channel, index]`` -> 0xD035 (TfrmMain.ReadRestDayRemark)."""
    return _packet(
        target, OP_READ_RESTDAY_REMARK,
        bytes([_u8(sub, "sub"), _u8(channel, "channel"), _u8(index, "index")]), source,
    )


def build_write_restday_remark(
    target: DeviceAddress, channel: int, index: int, sub: int, remark: str,
    source: DeviceAddress = DEFAULT_SOURCE,
) -> Packet:
    """0xD036 ``[index, channel, sub, remark20]`` -> 0xD037 (TfrmMain.ModifyTimerDayRemark kind 1)."""
    return _packet(
        target, OP_WRITE_RESTDAY_REMARK,
        bytes([_u8(index, "index"), _u8(channel, "channel"), _u8(sub, "sub")]) + encode_name(remark), source,
    )


def build_read_holiday_remark(
    target: DeviceAddress, channel: int, index: int, source: DeviceAddress = DEFAULT_SOURCE
) -> Packet:
    """0xD03A ``[channel, index]`` -> 0xD03B (TfrmMain.ReadFeastRemark)."""
    return _packet(target, OP_READ_HOLIDAY_REMARK, bytes([_u8(channel, "channel"), _u8(index, "index")]), source)


def build_write_holiday_remark(
    target: DeviceAddress, channel: int, index: int, remark: str, source: DeviceAddress = DEFAULT_SOURCE
) -> Packet:
    """0xD03C ``[index, channel, remark20]`` -> 0xD03D (TfrmMain.ModifyTimerDayRemark kind 2)."""
    return _packet(
        target, OP_WRITE_HOLIDAY_REMARK,
        bytes([_u8(index, "index"), _u8(channel, "channel")]) + encode_name(remark), source,
    )


def parse_remark_reply(payload: bytes) -> str:
    """Remark replies (0xD031/0xD035/0xD03B/0xD041/0xD055/0xD083).

    The handlers call ``FUN_01277b14(buf, len, offset, out, 20)``; the
    offset is 2 for group remarks (after the 16-bit group id) and the
    handlers for the day-type remarks pass 0. Because the module may echo
    the request bytes first, the first printable 20-byte window is used.
    """
    for offset in range(0, max(1, len(payload) - REMARK_LEN + 1)):
        text = decode_name(payload[offset : offset + REMARK_LEN])
        if text:
            return text
    return ""


# ---------------------------------------------------------------------------
# Calendar: holidays ("feast"), rest days, span days, seasons  — MED/LOW
# ---------------------------------------------------------------------------


@dataclass
class Holiday:
    channel: int
    index: int
    month: int
    day: int
    flag: int = 1        # UNVERIFIED: enable / "span day" flag
    raw: bytes = b""


def build_read_holiday(
    target: DeviceAddress, channel: int, index: int, source: DeviceAddress = DEFAULT_SOURCE
) -> Packet:
    """0xD028 ``[index, channel]`` -> 0xD029 (TfrmMain.ReadFeastTable).

    The routine waits until the reply echoes ``payload[?] == index`` and
    ``== channel`` (globals 0x0131f0c4 / 0x0131efac) instead of polling the
    opcode.
    """
    return _packet(target, OP_READ_HOLIDAY, bytes([_u8(index, "index"), _u8(channel, "channel")]), source)


def parse_holiday(payload: bytes) -> Holiday:
    """0xD029 -> :class:`Holiday`.

    TfrmMain.ShowFeastTable reads payload[0], payload[1], payload[2] (clamped
    to 23 -> an hour), payload[3] (stored as "day no." echo) and payload[4]
    (stored as "channel" echo) before inserting into tmpFeastTable; the
    month/day assignment below is the most plausible reading.  # UNVERIFIED
    """
    if len(payload) < 5:
        raise ValueError("holiday reply too short")
    return Holiday(
        channel=payload[4], index=payload[3], month=payload[0], day=payload[1], flag=payload[2],
        raw=bytes(payload),
    )


def build_write_holiday(
    target: DeviceAddress, holiday: Holiday, source: DeviceAddress = DEFAULT_SOURCE
) -> Packet:
    """0xD02A ``[channel, index, month, day, flag]`` -> 0xD02B (TfrmMain.ModifyTimerFeast).

    The decompile writes ``[p3, p7, p6, p5, p4]``; the ack is matched on
    ``payload[0] == channel`` and ``payload[1] == index``.  # UNVERIFIED field order after index
    """
    payload = bytes(
        [
            _u8(holiday.channel, "channel"), _u8(holiday.index, "index"),
            _u8(holiday.month, "month", 12), _u8(holiday.day, "day", 31), _u8(holiday.flag, "flag"),
        ]
    )
    return _packet(target, OP_WRITE_HOLIDAY, payload, source)


@dataclass
class RestDay:
    channel: int
    season: int
    weekday: int
    mode: int = 0        # UNVERIFIED: "rest day 1/2/3" selector
    raw: bytes = b""


def build_read_rest_day(
    target: DeviceAddress, channel: int, season: int, weekday: int, source: DeviceAddress = DEFAULT_SOURCE
) -> Packet:
    """0xD024 ``[channel, season, weekday]`` -> 0xD025 (TfrmMain.ReadRestDaySetup).  # UNVERIFIED order"""
    return _packet(
        target, OP_READ_RESTDAY,
        bytes([_u8(channel, "channel"), _u8(season, "season"), _u8(weekday, "weekday")]), source,
    )


def parse_rest_day(payload: bytes) -> RestDay:
    """0xD025 ``[channel, season, weekday, mode]`` (TfrmMain.ShowRestDaySetupInfo).  # UNVERIFIED"""
    if len(payload) < 3:
        raise ValueError("rest day reply too short")
    return RestDay(
        channel=payload[0], season=payload[1], weekday=payload[2],
        mode=payload[3] if len(payload) > 3 else 0, raw=bytes(payload),
    )


def build_write_rest_day(
    target: DeviceAddress, rest_day: RestDay, source: DeviceAddress = DEFAULT_SOURCE
) -> Packet:
    """0xD026 ``[channel, season, weekday, mode]`` -> 0xD027 (TfrmMain.ModifyTimerRestDay).  # UNVERIFIED order"""
    payload = bytes(
        [
            _u8(rest_day.channel, "channel"), _u8(rest_day.season, "season"),
            _u8(rest_day.weekday, "weekday"), _u8(rest_day.mode, "mode"),
        ]
    )
    return _packet(target, OP_WRITE_RESTDAY, payload, source)


@dataclass
class SpanDay:
    channel: int
    index: int
    month: int
    day: int
    end_hour: int
    end_minute: int


def build_read_span_day(
    target: DeviceAddress, channel: int, index: int, source: DeviceAddress = DEFAULT_SOURCE
) -> Packet:
    """0xD068 ``[channel, index]`` -> 0xD069 (TfrmMain.ReadOverDayTable)."""
    return _packet(target, OP_READ_SPAN_DAY, bytes([_u8(channel, "channel"), _u8(index, "index")]), source)


def parse_span_day(payload: bytes) -> SpanDay:
    """0xD069 ``[channel, index, month, day, end_hh, end_mm]`` (TfrmMain.ShowOverDayTable).

    The handler clamps payload[2] to 12, payload[3] to 31, payload[4] to 23
    and payload[5] to 60 and echoes payload[0]/payload[1] back into the
    globals ReadOverDayTable waits on (channel / index). MED confidence.
    """
    if len(payload) < 6:
        raise ValueError("span day reply too short")
    return SpanDay(payload[0], payload[1], payload[2], payload[3], payload[4], payload[5])


def build_write_span_day(
    target: DeviceAddress, span: SpanDay, source: DeviceAddress = DEFAULT_SOURCE
) -> Packet:
    """0xD06A ``[channel, index, month, day, end_hh, end_mm]`` -> 0xD06B (TfrmMain.ModifyTimerOverDay)."""
    payload = bytes(
        [
            _u8(span.channel, "channel"), _u8(span.index, "index"), _u8(span.month, "month", 12),
            _u8(span.day, "day", 31), _u8(span.end_hour, "end_hour", 23), _u8(span.end_minute, "end_minute", 59),
        ]
    )
    return _packet(target, OP_WRITE_SPAN_DAY, payload, source)


@dataclass
class Season:
    channel: int
    index: int
    start_month: int
    start_day: int
    end_month: int
    end_day: int


def build_read_season(
    target: DeviceAddress, channel: int, index: int, source: DeviceAddress = DEFAULT_SOURCE
) -> Packet:
    """0xD03E ``[channel, index]`` -> 0xD03F (TfrmMain.ReadSeasonInfo)."""
    return _packet(target, OP_READ_SEASON, bytes([_u8(channel, "channel"), _u8(index, "index")]), source)


def parse_season(payload: bytes) -> Season:
    """0xD03F -> :class:`Season`.

    FUN_00f9ea38 (0xD03F case) clamps payload[0] and payload[2] to 12 and
    payload[1] to 31 before inserting a season row, so the reply carries
    ``[start_month, start_day, end_month, end_day, ...]`` after an
    UNVERIFIED channel/index prefix. Both shapes are accepted.
    """
    if len(payload) >= 6:
        return Season(payload[0], payload[1], payload[2], payload[3], payload[4], payload[5])
    if len(payload) >= 4:
        return Season(0, 0, payload[0], payload[1], payload[2], payload[3])
    raise ValueError("season reply too short")


def build_write_season(
    target: DeviceAddress, season: Season, source: DeviceAddress = DEFAULT_SOURCE
) -> Packet:
    """0xD022 ``[channel, index, start_mm, start_dd, end_mm, end_dd]`` -> 0xD023 (TfrmMain.ModifySeason).  # UNVERIFIED order"""
    payload = bytes(
        [
            _u8(season.channel, "channel"), _u8(season.index, "index"),
            _u8(season.start_month, "start_month", 12), _u8(season.start_day, "start_day", 31),
            _u8(season.end_month, "end_month", 12), _u8(season.end_day, "end_day", 31),
        ]
    )
    return _packet(target, OP_WRITE_SEASON, payload, source)


# ---------------------------------------------------------------------------
# Groups  — MED (counts / remarks / names) , LOW (member records)
#
# TfrmMain.ReadCountGroup: 0xD060, empty -> 0xD061 ``[count16]`` (the caller
# FUN_00ee236c then pages through ReadManyGroup with ceil(count/30) pages).
# TfrmMain.ReadManyGroup: 0xD062 ``[page]`` -> 0xD063, rendered by
# TfrmMain.ShowAllGroupInfo as ``[count, id16, id16, ...]``.
# TfrmMain.ReadCountGroupMember: 0xD012 ``[group16]`` -> 0xD013 (ack only).
# TfrmMain.ReadGroupMember: 0xD00A ``[group16, a, b]`` -> 0xD00B, rendered by
# TfrmMain.ShowGroupMember (4-byte or 7-byte member records depending on the
# device type). TfrmMain.ReadGroupMemberNew: 0xD086 ``[group16, index]`` ->
# 0xD087 (FUN_00f9aa30 inserts SubNetID, DeviceID, ObjType, FirstParameter,
# SecondParameter, RunTimeMinute, RunTimeSecond into tmpGroupMember).
# ---------------------------------------------------------------------------


def build_read_group_count(target: DeviceAddress, source: DeviceAddress = DEFAULT_SOURCE) -> Packet:
    """0xD060, empty payload -> 0xD061 ``[count16]`` (TfrmMain.ReadCountGroup)."""
    return _packet(target, OP_READ_GROUP_COUNT, b"", source)


def parse_group_count(payload: bytes) -> int:
    """0xD061: big-endian 16-bit group count (FUN_00f9f1a8, case 0xD061)."""
    if len(payload) < 2:
        raise ValueError("group count reply too short")
    return int.from_bytes(payload[:2], "big")


def build_read_group_page(
    target: DeviceAddress, page: int, source: DeviceAddress = DEFAULT_SOURCE
) -> Packet:
    """0xD062 ``[page]`` -> 0xD063 (TfrmMain.ReadManyGroup; 30 groups per page)."""
    return _packet(target, OP_READ_GROUP_PAGE, bytes([_u8(page, "page")]), source)


def parse_group_page(payload: bytes) -> list[int]:
    """0xD063 ``[count, id16 * count]`` -> group ids (TfrmMain.ShowAllGroupInfo)."""
    if not payload:
        return []
    count = payload[0]
    ids = []
    for i in range(count):
        chunk = payload[1 + 2 * i : 3 + 2 * i]
        if len(chunk) < 2:
            break
        ids.append(int.from_bytes(chunk, "big"))
    return ids


def build_read_group_member_count(
    target: DeviceAddress, group: int, source: DeviceAddress = DEFAULT_SOURCE
) -> Packet:
    """0xD012 ``[group16]`` -> 0xD013 (TfrmMain.ReadCountGroupMember)."""
    return _packet(target, OP_READ_GROUP_MEMBER_COUNT, _u16(group, "group"), source)


def build_read_group_member(
    target: DeviceAddress, group: int, a: int, b: int, source: DeviceAddress = DEFAULT_SOURCE
) -> Packet:
    """0xD00A ``[group16, a, b]`` -> 0xD00B (TfrmMain.ReadGroupMember, old style).  # UNVERIFIED a/b"""
    return _packet(target, OP_READ_GROUP_MEMBER, _u16(group, "group") + bytes([_u8(a, "a"), _u8(b, "b")]), source)


def build_read_group_member_new(
    target: DeviceAddress, group: int, index: int, source: DeviceAddress = DEFAULT_SOURCE
) -> Packet:
    """0xD086 ``[group16, index]`` -> 0xD087 (TfrmMain.ReadGroupMemberNew)."""
    return _packet(target, OP_READ_GROUP_MEMBER_NEW, _u16(group, "group") + bytes([_u8(index, "index")]), source)


@dataclass
class GroupMember:
    group: int
    index: int
    subnet: int
    device: int
    obj_type: int
    param1: int
    param2: int
    run_minutes: int = 0
    run_seconds: int = 0
    raw: bytes = b""


def parse_group_member_new(payload: bytes) -> GroupMember:
    """0xD087 ``[group16, index, subnet, device, obj_type, p1, p2, min, sec]``.  # UNVERIFIED order after index"""
    if len(payload) < 8:
        raise ValueError("group member reply too short")
    return GroupMember(
        group=int.from_bytes(payload[:2], "big"), index=payload[2], subnet=payload[3], device=payload[4],
        obj_type=payload[5], param1=payload[6], param2=payload[7],
        run_minutes=payload[8] if len(payload) > 8 else 0,
        run_seconds=payload[9] if len(payload) > 9 else 0, raw=bytes(payload),
    )


def build_write_group_member(
    target: DeviceAddress, member: GroupMember, source: DeviceAddress = DEFAULT_SOURCE
) -> Packet:
    """0xD01E 17 bytes -> 0xD01F (TfrmMain.ModifyTimerGroupMemberNewVersion).

    Decompile: ``[group16, p18, p17, p16, p14, p13, x16, p15, p10, p9, p7,
    p6, y16, p8]`` — a group id followed by the member record and two
    16-bit fields. Mapped as ``[group16, index, subnet, device, obj_type,
    p1, run16, p2, ...zeros]``.  # UNVERIFIED
    """
    payload = (
        _u16(member.group, "group")
        + bytes([_u8(member.index, "index"), _u8(member.subnet, "subnet"), _u8(member.device, "device"),
                 _u8(member.obj_type, "obj_type"), _u8(member.param1, "param1")])
        + _u16(member.run_minutes * 60 + member.run_seconds, "run_time")
        + bytes([_u8(member.param2, "param2")])
        + bytes(7)
    )
    return _packet(target, OP_WRITE_GROUP_MEMBER, payload, source)


def build_add_group_member(
    target: DeviceAddress, group: int, source: DeviceAddress = DEFAULT_SOURCE
) -> Packet:
    """0xD008 ``[group16, 0, 0, 1, 0]`` -> 0xD009 (TfrmMain.AddNewGroupMember, constant tail)."""
    return _packet(target, OP_ADD_GROUP_MEMBER, _u16(group, "group") + bytes([0, 0, 1, 0]), source)


def build_delete_group_member(
    target: DeviceAddress, group: int, member: Sequence[int], source: DeviceAddress = DEFAULT_SOURCE
) -> Packet:
    """0xD01C ``[group16, member...]`` (7 or 10 bytes) -> 0xD01D (TfrmMain.DeleteGroupMember).  # UNVERIFIED"""
    return _packet(target, OP_DELETE_GROUP_MEMBER, _u16(group, "group") + bytes(_u8(b, "member") for b in member), source)


def build_read_group_remark(
    target: DeviceAddress, group: int, source: DeviceAddress = DEFAULT_SOURCE
) -> Packet:
    """0xD082 ``[group16]`` -> 0xD083 ``[group16, remark20]`` (TfrmMain.ReadGroupRemark / FUN_00f9a730)."""
    return _packet(target, OP_READ_GROUP_REMARK, _u16(group, "group"), source)


def parse_group_remark(payload: bytes) -> tuple[int, str]:
    """0xD083 ``[group16, remark20]`` (FUN_00f9a730 extracts the remark at offset 2)."""
    if len(payload) < 2:
        raise ValueError("group remark reply too short")
    return int.from_bytes(payload[:2], "big"), _remark(payload, 2)


def build_write_group_remark(
    target: DeviceAddress, group: int, remark: str, source: DeviceAddress = DEFAULT_SOURCE
) -> Packet:
    """0xD080 ``[group16, remark20]`` (22 bytes) -> 0xD081 (TfrmMain.ModifyTimerGroupRemark)."""
    return _packet(target, OP_WRITE_GROUP_REMARK, _u16(group, "group") + encode_name(remark), source)


def build_write_group_name(
    target: DeviceAddress, group: int, name_id: int, source: DeviceAddress = DEFAULT_SOURCE
) -> Packet:
    """0xD018 ``[group16, name16]`` -> 0xD019 (TfrmMain.ModifyTimerGroupName)."""
    return _packet(target, OP_WRITE_GROUP_NAME, _u16(group, "group") + _u16(name_id, "name_id"), source)


def build_delete_group_name(
    target: DeviceAddress, group: int, source: DeviceAddress = DEFAULT_SOURCE
) -> Packet:
    """0xF71E ``[group16]`` -> 0xF71F (TfrmMain.DeleteTimerGroupName)."""
    return _packet(target, OP_DELETE_GROUP_NAME, _u16(group, "group"), source)


async def read_group_count(bus: SmartG4Bus, target: DeviceAddress, **kw: Any) -> int | None:
    try:
        reply = await request(bus, target, OP_READ_GROUP_COUNT, b"", OP_READ_GROUP_COUNT_RESP, **kw)
    except (TimeoutError, asyncio.TimeoutError):
        return None
    return parse_group_count(reply.payload)


async def read_group_ids(bus: SmartG4Bus, target: DeviceAddress, **kw: Any) -> list[int]:
    """Enumerate all group ids (count, then 30-per-page reads)."""
    count = await read_group_count(bus, target, **kw)
    if not count:
        return []
    ids: list[int] = []
    for page in range((count + 29) // 30):
        try:
            reply = await request(bus, target, OP_READ_GROUP_PAGE, bytes([page]), OP_READ_GROUP_PAGE_RESP, **kw)
        except (TimeoutError, asyncio.TimeoutError):
            break
        ids.extend(parse_group_page(reply.payload))
        await asyncio.sleep(0.05)
    return ids


async def read_group_remark(bus: SmartG4Bus, target: DeviceAddress, group: int, **kw: Any) -> str | None:
    try:
        reply = await request(
            bus, target, OP_READ_GROUP_REMARK, _u16(group, "group"), OP_READ_GROUP_REMARK_RESP,
            match=lambda p: p.payload[:2] == _u16(group, "group"), **kw,
        )
    except (TimeoutError, asyncio.TimeoutError):
        return None
    return parse_group_remark(reply.payload)[1]


async def write_group_remark(
    bus: SmartG4Bus, target: DeviceAddress, group: int, remark: str, **kw: Any
) -> bool:
    return await _write(bus, target, build_write_group_remark(target, group, remark), OP_WRITE_GROUP_REMARK_RESP, **kw)


# ---------------------------------------------------------------------------
# Logic tables  — LOW
#
# TfrmMain.hdlReadLogicTimer: 0xDA00, empty -> 0xDA01. The caller
# (0x00fdc271) copies the reply into a global buffer and shows byte 10 as a
# checkbox (``== 0xF8``) plus four text fields; the DDP-9-in-1 handler
# (FUN_01205ba4) only uses one byte as a checkbox. Layout not recovered.
# TfrmMain.hdlModifyLogicTimer: 0xD998 ``[a, b]`` -> 0xD999 (two edits of
# the logic-timer dialog, 0x65c and 0x664).
# TfrmMain.hdlReadLogicTableRemark: 0xDA38 ``[table16, index]`` -> 0xDA39.
# TfrmMain.LogicReadObjRemark: 0xDA34 ``[object16, index]`` -> 0xDA35.
# TfrmMain.ReadDeviceLogicBlockRemark: 0xD992, empty -> 0xD993 whose first
# two bytes are shown as a big-endian number (FUN_0109da78, case 0xD993).
# TfrmMain.ReadTimerModeLogicOfMonitor: 0xD06E ``[a]`` -> 0xD06F and
# TfrmMain.ReadTimerSensorLogicOfMonitor: 0xD070 ``[a, b, c]`` -> 0xD071
# (the send opcode is not a literal in either body; it is derived from the
# polled reply opcode - 1).  # UNVERIFIED request opcodes
# ---------------------------------------------------------------------------


def build_read_logic_timer(target: DeviceAddress, source: DeviceAddress = DEFAULT_SOURCE) -> Packet:
    """0xDA00, empty payload -> 0xDA01 (TfrmMain.hdlReadLogicTimer)."""
    return _packet(target, OP_READ_LOGIC_TIMER, b"", source)


def parse_logic_timer(payload: bytes) -> dict[str, Any]:
    """0xDA01 -> ``{"enabled": payload[10] == 0xF8, "raw": ...}``.  # UNVERIFIED"""
    return {"enabled": len(payload) > 10 and payload[10] == ACK_OK, "raw": bytes(payload)}


def build_write_logic_timer(
    target: DeviceAddress, a: int, b: int, source: DeviceAddress = DEFAULT_SOURCE
) -> Packet:
    """0xD998 ``[a, b]`` -> 0xD999 (TfrmMain.hdlModifyLogicTimer).  # UNVERIFIED meaning of a/b"""
    return _packet(target, OP_WRITE_LOGIC_TIMER, bytes([_u8(a, "a"), _u8(b, "b")]), source)


def build_read_logic_table_remark(
    target: DeviceAddress, table: int, index: int, source: DeviceAddress = DEFAULT_SOURCE
) -> Packet:
    """0xDA38 ``[table16, index]`` -> 0xDA39 (TfrmMain.hdlReadLogicTableRemark)."""
    return _packet(target, OP_READ_LOGIC_TABLE_REMARK, _u16(table, "table") + bytes([_u8(index, "index")]), source)


def build_read_logic_object_remark(
    target: DeviceAddress, obj: int, index: int, source: DeviceAddress = DEFAULT_SOURCE
) -> Packet:
    """0xDA34 ``[object16, index]`` -> 0xDA35 (TfrmMain.LogicReadObjRemark)."""
    return _packet(target, OP_READ_LOGIC_OBJECT_REMARK, _u16(obj, "object") + bytes([_u8(index, "index")]), source)


def build_read_logic_block_remark(target: DeviceAddress, source: DeviceAddress = DEFAULT_SOURCE) -> Packet:
    """0xD992, empty payload -> 0xD993 ``[value16, ...]`` (TfrmMain.ReadDeviceLogicBlockRemark)."""
    return _packet(target, OP_READ_LOGIC_BLOCK_REMARK, b"", source)


def parse_logic_block_remark(payload: bytes) -> int:
    """0xD993: the tool displays ``payload[0] << 8 | payload[1]``."""
    if len(payload) < 2:
        raise ValueError("logic block reply too short")
    return int.from_bytes(payload[:2], "big")


def build_read_mode_logic_monitor(
    target: DeviceAddress, a: int, source: DeviceAddress = DEFAULT_SOURCE
) -> Packet:
    """0xD06E ``[a]`` -> 0xD06F (TfrmMain.ReadTimerModeLogicOfMonitor).  # UNVERIFIED request opcode"""
    return _packet(target, OP_READ_MODE_LOGIC_MONITOR, bytes([_u8(a, "a")]), source)


def build_read_sensor_logic_monitor(
    target: DeviceAddress, a: int, b: int, c: int, source: DeviceAddress = DEFAULT_SOURCE
) -> Packet:
    """0xD070 ``[a, b, c]`` -> 0xD071 (TfrmMain.ReadTimerSensorLogicOfMonitor).  # UNVERIFIED request opcode"""
    return _packet(target, OP_READ_SENSOR_LOGIC_MONITOR, bytes([_u8(a, "a"), _u8(b, "b"), _u8(c, "c")]), source)


def parse_sensor_logic_monitor(payload: bytes) -> list[dict[str, int]]:
    """0xD071 -> 4-byte records ``[a, b, value16]`` after a 3-byte echo (FUN_00f96560).  # UNVERIFIED"""
    records = []
    for offset in range(3, len(payload) - 3, 4):
        records.append(
            {"a": payload[offset], "b": payload[offset + 1],
             "value": int.from_bytes(payload[offset + 2 : offset + 4], "big")}
        )
    return records


def build_read_vacation(
    target: DeviceAddress, a: int, b: int, c: int, d: int, source: DeviceAddress = DEFAULT_SOURCE
) -> Packet:
    """0x0116 ``[a, b, c, d]`` -> 0x0117 (TfrmMain.ReadVacationSetting).

    The routine keeps polling until three globals equal a/b/c, i.e. the
    reply echoes the request prefix; nothing else about the layout is
    known.  # UNVERIFIED
    """
    return _packet(target, OP_READ_VACATION, bytes([_u8(a, "a"), _u8(b, "b"), _u8(c, "c"), _u8(d, "d")]), source)


def build_read_time_usable(target: DeviceAddress, source: DeviceAddress = DEFAULT_SOURCE) -> Packet:
    """0xD946, empty payload -> 0xD947 ``[flag]`` (TfrmMain.ReadTimeForCanUseOrNo)."""
    return _packet(target, OP_READ_TIME_USABLE, b"", source)


def parse_time_usable(payload: bytes) -> bool:
    """0xD947: payload[0] is stored as the "time can be used" flag (FUN_00f8ed58)."""
    return bool(payload) and payload[0] != 0


__all__ = [name for name in dir() if name.startswith(("OP_", "build_", "parse_", "read_", "write_"))] + [
    "ACK_OK", "ACK_FAIL", "DEFAULT_SOURCE", "REMARK_LEN", "WEEKDAY_NAMES",
    "TimerDateTime", "TimerLocation", "SunTimes", "ChannelRunStatus", "Holiday", "RestDay",
    "SpanDay", "Season", "GroupMember", "is_ack", "request",
]
