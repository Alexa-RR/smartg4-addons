"""Payload parsers/encoders for S-BUS operation codes.

Ported from caligo-mentis/smart-bus (lib/commands.js), which follows
"Operation Code of HDL Buspro v1.111" and was validated against real
hardware. Smart-G4 shares these opcodes; only the UDP signature differs.

Each entry maps an opcode to optional `parse(payload) -> dict`,
`encode(data) -> bytes`, and the opcode of its expected `response`.
Unknown opcodes simply pass raw payload through.
"""

from __future__ import annotations

from typing import Any, Callable

OpParser = Callable[[bytes], dict[str, Any]]
OpEncoder = Callable[[dict[str, Any]], bytes]


def _status_byte(value: int) -> bool | None:
    return {0xF8: True, 0xF5: False}.get(value)


def _channel_bitmask(data: bytes, count: int) -> list[dict[str, Any]]:
    channels: list[dict[str, Any]] = []
    for i, byte in enumerate(data):
        for bit in range(8):
            if len(channels) >= count:
                return channels
            channels.append(
                {"number": i * 8 + bit + 1, "status": bool(byte & (1 << bit))}
            )
    return channels


def _encode_bitmask(channels: list[dict[str, Any]]) -> bytes:
    out = bytearray((len(channels) + 7) // 8)
    for i, channel in enumerate(channels):
        if channel["status"]:
            out[i // 8] |= 1 << (i % 8)
    return bytes(out)


def _levels_list(payload: bytes) -> dict[str, Any]:
    count = payload[0]
    return {
        "channels": [
            {"number": i + 1, "level": payload[i + 1]} for i in range(count)
        ]
    }


def _encode_levels_list(data: dict[str, Any]) -> bytes:
    channels = data.get("channels", [])
    return bytes([len(channels)] + [c["level"] for c in channels])


COMMANDS: dict[int, dict[str, Any]] = {
    # --- Scenes -----------------------------------------------------------
    # 4.1.1 Scene Control
    0x0002: {
        "name": "SceneControl",
        "parse": lambda p: {"area": p[0], "scene": p[1]},
        "encode": lambda d: bytes([d["area"], d["scene"]]),
        "response": 0x0003,
    },
    # 4.1.2 Scene Control Response
    0x0003: {
        "name": "SceneControlResponse",
        "parse": lambda p: {
            "area": p[0],
            "scene": p[1],
            "channels": _channel_bitmask(p[3:], p[2]),
        },
        "encode": lambda d: bytes([d["area"], d["scene"], len(d["channels"])])
        + _encode_bitmask(d["channels"]),
    },
    # 4.1.3 / 4.1.4 Read Status of Scene
    0x000C: {
        "name": "ReadSceneStatus",
        "parse": lambda p: {"area": p[0]},
        "encode": lambda d: bytes([d["area"]]),
        "response": 0x000D,
    },
    0x000D: {
        "name": "ReadSceneStatusResponse",
        "parse": lambda p: {"area": p[0], "scene": p[1]},
        "encode": lambda d: bytes([d["area"], d["scene"]]),
    },
    # 4.1.5 Broadcast Status of Scene
    0xEFFF: {
        "name": "SceneStatusBroadcast",
        "parse": lambda p: {
            "areas": [
                {"number": i + 1, "scene": p[i + 1]} for i in range(p[0])
            ],
            "channels": _channel_bitmask(p[p[0] + 2 :], p[p[0] + 1]),
        },
    },
    # --- Single channel (dimmers / relays) --------------------------------
    # 4.3.1 Single Channel Control: level 0-100 (%), time in seconds
    0x0031: {
        "name": "SingleChannelControl",
        "parse": lambda p: {
            "channel": p[0],
            "level": p[1],
            "time": int.from_bytes(p[2:4], "big"),
        },
        "encode": lambda d: bytes([d["channel"], d["level"]])
        + int(d.get("time", 0)).to_bytes(2, "big"),
        "response": 0x0032,
    },
    # 4.3.2 Response Single Channel Control
    0x0032: {
        "name": "SingleChannelControlResponse",
        "parse": lambda p: {
            "channel": p[0],
            "success": _status_byte(p[1]),
            "level": p[2],
        },
        "encode": lambda d: bytes(
            [d["channel"], 0xF8 if d["success"] else 0xF5, d["level"]]
        ),
    },
    # 4.3.3 / 4.3.4 Read Status of Channels
    0x0033: {"name": "ReadChannelStatus", "response": 0x0034},
    0x0034: {
        "name": "ReadChannelStatusResponse",
        "parse": _levels_list,
        "encode": _encode_levels_list,
    },
    # 4.3.5 / 4.3.6 Read Current Level of Channels
    0x0038: {"name": "ReadChannelLevel", "response": 0x0039},
    0x0039: {
        "name": "ReadChannelLevelResponse",
        "parse": _levels_list,
        "encode": _encode_levels_list,
    },
    # --- Universal (virtual) switches -------------------------------------
    # 6.1.1 UV Switch Control
    0xE01C: {
        "name": "UniversalSwitchControl",
        "parse": lambda p: {"switch": p[0], "status": bool(p[1])},
        "encode": lambda d: bytes([d["switch"], 255 if d["status"] else 0]),
        "response": 0xE01D,
    },
    # 6.1.2 Response UV Switch Control
    0xE01D: {
        "name": "UniversalSwitchControlResponse",
        "parse": lambda p: {"switch": p[0], "status": bool(p[1])},
        "encode": lambda d: bytes([d["switch"], 1 if d["status"] else 0]),
    },
    # 6.1.3 / 6.1.4 Read Status of UV Switch
    0xE018: {
        "name": "ReadUniversalSwitch",
        "parse": lambda p: {"switch": p[0]},
        "encode": lambda d: bytes([d["switch"]]),
        "response": 0xE019,
    },
    0xE019: {
        "name": "ReadUniversalSwitchResponse",
        "parse": lambda p: {"switch": p[0], "status": bool(p[1])},
        "encode": lambda d: bytes([d["switch"], 1 if d["status"] else 0]),
    },
    # 6.1.5 Broadcast Status of UV Switches
    0xE017: {
        "name": "UniversalSwitchBroadcast",
        "parse": lambda p: {
            "switches": [
                {"number": i + 1, "status": bool(p[i + 1])} for i in range(p[0])
            ]
        },
    },
    # --- Curtains ----------------------------------------------------------
    # 7.1.1 Curtain Switch Control (status: 0=stop, 1=open, 2=close)
    0xE3E0: {
        "name": "CurtainControl",
        "parse": lambda p: {"curtain": p[0], "status": p[1]},
        "encode": lambda d: bytes([d["curtain"], d["status"]]),
        "response": 0xE3E1,
    },
    0xE3E1: {
        "name": "CurtainControlResponse",
        "parse": lambda p: {"curtain": p[0], "status": p[1]},
        "encode": lambda d: bytes([d["curtain"], d["status"]]),
    },
    # 7.1.3 / 7.1.4 Read Status of Curtain Switch
    0xE3E2: {
        "name": "ReadCurtainStatus",
        "parse": lambda p: {"curtain": p[0]},
        "encode": lambda d: bytes([d["curtain"]]),
        "response": 0xE3E3,
    },
    0xE3E3: {
        "name": "ReadCurtainStatusResponse",
        "parse": lambda p: {
            "curtain": p[0],
            "status": p[1],
            **(
                {"duration": int.from_bytes(p[2:4], "big") / 10}
                if len(p) >= 4
                else {}
            ),
        },
    },
    # --- HVAC --------------------------------------------------------------
    # 0x193A HVAC_Automatic_Control. Payload (13 bytes), from the vendor SDK:
    #   ACNo, Temperature, 0xFF, Cool, Heat, Auto, 0xFF, ModeSpeed, Power,
    #   0xFF, 0xFF, 0xFF, 0xFF
    # ModeSpeed packs mode (high nibble) and fan speed (low nibble).
    0x193A: {
        "name": "HVACControl",
        "encode": lambda d: bytes(
            [
                d.get("ac", 1),
                d.get("temperature", 0),
                0xFF,
                d.get("cool", 0),
                d.get("heat", 0),
                d.get("auto", 0),
                0xFF,
                d.get("mode_speed", 0),
                1 if d.get("power") else 0,
                0xFF,
                0xFF,
                0xFF,
                0xFF,
            ]
        ),
        "response": 0x193B,
    },
    # 0xE0EC Read AC current status
    0xE0EC: {"name": "ReadACStatus", "response": 0xE0ED},
    # --- Panel control (universal DDP command channel) ---------------------
    # 0xE3D8 Panel_Control(Type, Value). Type selects the sub-function:
    #   1=IR receiver on/off, 2=button lock, 3=AC power, 4=cool setpoint,
    #   5=fan speed, 6=AC mode, 7=heat setpoint, 8=auto setpoint, etc.
    # Also the natural channel for emulating DDP button presses from HA.
    0xE3D8: {
        "name": "PanelControl",
        "parse": lambda p: {"type": p[0], "value": p[1]},
        "encode": lambda d: bytes([d["type"], d["value"]]),
        "response": 0xE3D9,
    },
    # --- Music / Z-Audio ---------------------------------------------------
    # 0x0218 Audio_Play_Control — payload is a short byte sequence, e.g.
    #   [4,1]=source, [3,2]=next folder, [1,x]=play control.
    0x0218: {
        "name": "AudioPlayControl",
        "encode": lambda d: bytes(d["bytes"]),
        "response": 0x0219,
    },
    # --- Discovery ----------------------------------------------------------
    # 0x000E LAN_Scan_Device_Online — the vendor tool's primary discovery
    # probe; broadcast to 255.255, every device answers 0x000F.
    0x000E: {"name": "ScanDeviceOnline", "response": 0x000F},
    # Observed live: the response payload is the device's remark (name),
    # space-padded ASCII (20 bytes on this bus). The real device type is
    # in the frame header.
    0x000F: {
        "name": "ScanDeviceOnlineResponse",
        "parse": lambda p: {
            "remark": p.decode("ascii", "replace").rstrip("\x00 ")
        },
    },
    # 0x0010 Write device remark (name): 20 bytes, space-padded ASCII.
    0x0010: {
        "name": "WriteDeviceRemark",
        "encode": lambda d: d["remark"].encode("ascii")[:20].ljust(20, b" "),
        "response": 0x0011,
    },
    0x0011: {"name": "WriteDeviceRemarkResponse"},
    # 0xDC1x device flash backup family (see backup.py; confirmed live).
    0xDC10: {"name": "ReadBackupInfo", "response": 0xDC11},
    0xDC11: {
        "name": "ReadBackupInfoResponse",
        "parse": lambda p: {
            "success": p[0] == 0xF8,
            "total_pages": int.from_bytes(p[1:3], "big"),
        },
    },
    0xDC14: {
        "name": "ReadFlashPage",
        "encode": lambda d: int(d["package"]).to_bytes(2, "big"),
        "response": 0xDC15,
    },
    0xDC15: {
        "name": "ReadFlashPageResponse",
        "parse": lambda p: {
            "package": int.from_bytes(p[0:2], "big"),
            "flag": p[2],
            "address": int.from_bytes(p[3:6], "big"),
            "data": p[6:].hex(),
        },
    },
    # Restore: announce/commit with a page count; ack 0xDC17. Page data is
    # staged by sending 0xDC15-format frames to the device (see backup.py).
    0xDC16: {
        "name": "DeviceRestore",
        "encode": lambda d: int(d["packages"]).to_bytes(2, "big"),
        "response": 0xDC17,
    },
    0xDC17: {
        "name": "DeviceRestoreResponse",
        "parse": lambda p: {"raw": p.hex()},
    },
    # 0xF003 Read MAC address — answers 0xF004 with MAC + remark (name).
    0xF003: {"name": "ReadMACAddress", "response": 0xF004},
    0xF004: {
        "name": "ReadMACAddressResponse",
        "parse": lambda p: {
            "mac": ":".join(f"{b:02x}" for b in p[0:8]),
            "remark": p[8:].split(b"\x00")[0].decode("ascii", "replace"),
        },
    },
}

# Full opcode dictionary recovered from the official SBUS.dll SDK
# (docs/opcodes.json). Names for opcodes we do not yet parse/encode, so
# the monitor and discovery can still label every telegram it sees.
SDK_OPCODE_NAMES: dict[int, str] = {
    0x0000: "Read_Scene_Model", 0x0002: "Scene_Control",
    0x0004: "Read_Setting_Zones", 0x0006: "Make_Zones_Dimmer",
    0x0008: "Modify_Scene_Model", 0x000E: "LAN_Scan_Device_Online",
    0x000F: "Scan_Device_Online_Response", 0x0012: "Read_Sequence_Running",
    0x0014: "Read_Sequence_Detail", 0x0016: "Modify_Sequence_Detail",
    0x001A: "Sequence_Control", 0x0031: "Single_Light_Control",
    0x0033: "Read_Status_Channels", 0x018C: "Read_HVAC_Temperatures_Sensor",
    0x018E: "Modify_HVAC_Temperatures_Sensor", 0x0218: "Audio_Play_Control",
    0x0222: "Read_Music_Page", 0x0224: "Write_Music_Page",
    0x022A: "Read_Z_Audio_Type", 0x022C: "Write_Z_Audio_Type",
    0x02E0: "Read_QTY_Of_Playlist", 0x02E2: "Read_Playlist_Name",
    0x02E4: "Read_QTY_Of_Songs", 0x02E6: "Read_Songs_Name",
    0x1900: "Read_Temperature_Range", 0x1902: "Modify_Temperature_Range",
    0x192E: "Get_Music_Device_Status", 0x193A: "HVAC_Automatic_Control",
    0xD910: "PC_SendIR_Stop", 0xD912: "PC_SendIR_Data",
    0xDC1C: "Reversing_Control", 0xDC23: "Read_Curtain_Control_Enabled",
    0xDC25: "Write_Curtain_Control_Enabled", 0xDC38: "Enable_Disable_IR_Service",
    0xE0EC: "Read_Ac_Current_Status", 0xE120: "Read_Celsius_Fahrenheit_Flag",
    0xE122: "Modify_Celsius_Fahrenheit_Flag", 0xE124: "Read_Fan_Speed_And_Mode",
    0xE140: "Read_Radio_Channel_Info", 0xE142: "Write_Radio_Channel_Info",
    0xE3D8: "Panel_Control", 0xE3E7: "Read_Temperature_Value",
    0xE3F4: "Read_Compressor_And_Fan", 0xE3F6: "Modify_Compressor_And_Fan",
    0xE3F8: "Read_VAV_Settings", 0xE3FA: "Modify_VAV_Settings",
    0xF00A: "Read_Remark_One_Zone", 0xF00C: "Write_Remark_One_Zone",
    0xF00E: "Read_Channel_Remark", 0xF010: "Write_Channel_Remark",
    0xF012: "Read_Channel_Type", 0xF014: "Modify_Channel_Type",
    0xF016: "Read_Channel_Limit", 0xF018: "Write_Channel_Limit",
    0xF024: "Read_Remark_Zone_Scene", 0xF026: "Write_Remark_Zone_Scene",
    0xF03F: "Read_Safeguard_Time_Of_Channel",
    0xF041: "Modify_Safeguard_Time_Of_Channel",
    0xF04D: "Read_Delay_Of_Turn_On_Channel",
    0xF04F: "Modify_Delay_Of_Turn_On_Channel", 0xF051: "Read_Power_On",
    0xF053: "Write_Power_On", 0xF078: "Read_Scene_All_Zones_Running",
    # response codes worth labelling
    0x0003: "Scene_Control_Response", 0x0032: "Single_Light_Response",
    0x0034: "Read_Channel_Status_Response", 0x193B: "HVAC_Control_Response",
    0xE3D9: "Panel_Control_Response", 0xEFFF: "Scene_Status_Broadcast",
}


def parse_payload(opcode: int, payload: bytes) -> dict[str, Any] | None:
    """Parse payload for a known opcode; None if unknown/unparseable."""
    command = COMMANDS.get(opcode)
    if not command or "parse" not in command:
        return None
    try:
        return command["parse"](payload)
    except (IndexError, ValueError):
        return None


def encode_payload(opcode: int, data: dict[str, Any]) -> bytes:
    command = COMMANDS.get(opcode)
    if not command or "encode" not in command:
        raise ValueError(f"no encoder for opcode {opcode:#06x}")
    return command["encode"](data)


def response_opcode(opcode: int) -> int | None:
    command = COMMANDS.get(opcode)
    return command.get("response") if command else None


def opcode_name(opcode: int) -> str:
    command = COMMANDS.get(opcode)
    if command:
        return command["name"]
    if opcode in SDK_OPCODE_NAMES:
        return SDK_OPCODE_NAMES[opcode]
    return f"Unknown({opcode:#06x})"
