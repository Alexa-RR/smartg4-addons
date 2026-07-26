"""S-BUS UDP frame encoding/decoding.

Wire format of one UDP datagram (typically broadcast, port 6000):

    offset  size  field
    0       4     source IPv4 address of the sender (informational)
    4       10    ASCII signature: b"SMARTCLOUD" (Smart-G4) or b"HDLMIRACLE" (HDL)
    14      2     0xAA 0xAA sync bytes
    16      1     length N = 9 (header) + len(payload) + 2 (CRC)
    17      1     source subnet ID
    18      1     source device ID
    19      2     source device type (big-endian)
    21      2     operation code (big-endian)
    23      1     target subnet ID (0xFF = broadcast)
    24      1     target device ID (0xFF = broadcast)
    25      ...   payload
    -2      2     CRC-16/XMODEM over bytes [16 : -2] (big-endian)
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .crc import crc16_xmodem

SIGNATURE_SMARTCLOUD = b"SMARTCLOUD"
SIGNATURE_HDLMIRACLE = b"HDLMIRACLE"
_VALID_SIGNATURES = (SIGNATURE_SMARTCLOUD, SIGNATURE_HDLMIRACLE)
_SYNC = b"\xaa\xaa"

BROADCAST_SUBNET = 0xFF
BROADCAST_DEVICE = 0xFF

# Device type reported for "virtual" senders (PCs, integrations).
VIRTUAL_DEVICE_TYPE = 0xFFFE


@dataclass(frozen=True)
class DeviceAddress:
    subnet: int
    device: int

    def __str__(self) -> str:
        return f"{self.subnet}.{self.device}"

    @classmethod
    def parse(cls, address: str) -> "DeviceAddress":
        subnet, device = address.split(".")
        return cls(int(subnet), int(device))

    @property
    def is_broadcast(self) -> bool:
        return self.subnet == BROADCAST_SUBNET and self.device == BROADCAST_DEVICE


BROADCAST = DeviceAddress(BROADCAST_SUBNET, BROADCAST_DEVICE)


@dataclass
class Packet:
    opcode: int
    source: DeviceAddress
    target: DeviceAddress
    source_type: int = VIRTUAL_DEVICE_TYPE
    payload: bytes = b""
    signature: bytes = SIGNATURE_SMARTCLOUD
    source_ip: bytes = field(default=b"\x00\x00\x00\x00", repr=False)

    def encode(self) -> bytes:
        content = bytes(
            [
                11 + len(self.payload),
                self.source.subnet,
                self.source.device,
                (self.source_type >> 8) & 0xFF,
                self.source_type & 0xFF,
                (self.opcode >> 8) & 0xFF,
                self.opcode & 0xFF,
                self.target.subnet,
                self.target.device,
            ]
        ) + self.payload
        crc = crc16_xmodem(content)
        return (
            self.source_ip
            + self.signature
            + _SYNC
            + content
            + bytes([(crc >> 8) & 0xFF, crc & 0xFF])
        )

    @classmethod
    def decode(cls, datagram: bytes) -> "Packet":
        """Decode a raw UDP datagram. Raises ValueError on malformed frames."""
        if len(datagram) < 27:
            raise ValueError(f"frame too short: {len(datagram)} bytes")

        signature = datagram[4:14]
        if signature not in _VALID_SIGNATURES:
            raise ValueError(f"unknown signature: {signature!r}")
        if datagram[14:16] != _SYNC:
            raise ValueError("missing 0xAAAA sync bytes")

        length = datagram[16]
        if len(datagram) < 16 + length:
            raise ValueError(f"truncated frame: length byte says {length}, "
                             f"got {len(datagram) - 16} content bytes")

        content = datagram[16 : 16 + length - 2]
        crc_expected = int.from_bytes(datagram[14 + length : 16 + length], "big")
        crc_actual = crc16_xmodem(content)
        if crc_actual != crc_expected:
            raise ValueError(f"CRC mismatch: expected {crc_expected:#06x}, "
                             f"computed {crc_actual:#06x}")

        return cls(
            opcode=int.from_bytes(content[5:7], "big"),
            source=DeviceAddress(content[1], content[2]),
            target=DeviceAddress(content[7], content[8]),
            source_type=int.from_bytes(content[3:5], "big"),
            payload=bytes(content[9:]),
            signature=bytes(signature),
            source_ip=bytes(datagram[0:4]),
        )
