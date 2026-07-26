"""pysmartg4 — async Python library for the Smart-G4 (S-BUS) protocol."""

from .bus import SmartG4Bus
from .commands import COMMANDS, opcode_name, parse_payload, encode_payload
from .discovery import DiscoveredDevice, discover
from .packet import (
    BROADCAST,
    SIGNATURE_HDLMIRACLE,
    SIGNATURE_SMARTCLOUD,
    DeviceAddress,
    Packet,
)

__version__ = "0.1.0"

__all__ = [
    "BROADCAST",
    "COMMANDS",
    "DeviceAddress",
    "DiscoveredDevice",
    "Packet",
    "SIGNATURE_HDLMIRACLE",
    "SIGNATURE_SMARTCLOUD",
    "SmartG4Bus",
    "discover",
    "encode_payload",
    "opcode_name",
    "parse_payload",
]
