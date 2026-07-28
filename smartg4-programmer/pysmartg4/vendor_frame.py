"""Vendor button-programming frames (undocumented protocol variant).

The vendor's Smart Cloud programs panel buttons with frames that are NOT
the documented S-BUS format: after the `SMARTCLOUD` signature they carry
the marker `0x4563` instead of `0xAAAA`, and their 8 header bytes
(addresses, type, opcode) are obfuscated — no standard CRC validates the
frame as observed on the wire.

The payload, however, is plaintext, and the trailing checksum is a
**linear** CRC-16/CCITT (poly 0x1021) computed over the *plaintext*
frame. Linearity is what makes this usable without breaking the header
obfuscation: for two frames that share a header and length,

    crc(A) XOR crc(B) == crc16_xmodem(A XOR B)

so a captured frame can be re-payloaded and its checksum corrected,
with the unknown header contribution cancelling out. Verified against
24/24 same-header pairs from a live programming session.

Consequence and limitation: a template can only address the device it
was captured against, because the destination lives inside the
obfuscated header. Capturing one exchange per panel model/address is
enough to program that panel.

Observed operations (payloads, plaintext):

    read button      -> [button, page]
    read response    <- [button, page, function, subnet, device, p1, p2, p3hi, p3lo]
    read label       -> [button]
    label response   <- [button, 20-byte name]
    WRITE button     -> [button, page, function, subnet, device, p1, p2, p3hi, p3lo, 0xFF]
    write ack        <- [button, page]
"""

from __future__ import annotations

from dataclasses import dataclass

from .crc import crc16_xmodem

MARKER = b"\x45\x63"
SIGNATURE = b"SMARTCLOUD"

# Payload offsets within the datagram
LEN_OFFSET = 16
HEADER_OFFSET = 17
PAYLOAD_OFFSET = 25


@dataclass
class VendorTemplate:
    """A captured frame used as a template for the same operation."""

    raw: bytes

    @property
    def header(self) -> bytes:
        return self.raw[HEADER_OFFSET:PAYLOAD_OFFSET]

    @property
    def payload(self) -> bytes:
        return self.raw[PAYLOAD_OFFSET:-2]

    @property
    def source_ip(self) -> bytes:
        return self.raw[0:4]

    def is_valid(self) -> bool:
        return (
            len(self.raw) > PAYLOAD_OFFSET + 2
            and self.raw[4:14] == SIGNATURE
            and self.raw[14:16] == MARKER
            and self.raw[LEN_OFFSET] == len(self.raw) - LEN_OFFSET
        )

    def with_payload(self, payload: bytes, source_ip: bytes | None = None) -> bytes:
        """Rebuild this frame with a new payload of the SAME length.

        The checksum is corrected using CRC linearity, so the obfuscated
        header carries over untouched and keeps addressing the same device.
        """
        if len(payload) != len(self.payload):
            raise ValueError(
                f"payload must stay {len(self.payload)} bytes "
                f"(got {len(payload)}) — the header encodes the length"
            )
        body_old = self.raw[LEN_OFFSET:-2]
        new = bytearray(self.raw)
        new[PAYLOAD_OFFSET:-2] = payload
        if source_ip is not None:
            new[0:4] = source_ip
        body_new = bytes(new[LEN_OFFSET:-2])
        diff = bytes(a ^ b for a, b in zip(body_old, body_new))
        trailer = int.from_bytes(self.raw[-2:], "big") ^ crc16_xmodem(diff)
        new[-2:] = trailer.to_bytes(2, "big")
        return bytes(new)


READ_OP = "b442"
READ_RESP = "b462"
WRITE_OP = "b402"
WRITE_RESP = "b422"


class TemplateStore:
    """Vendor frames learned by watching the bus, keyed by operation.

    A template addresses whichever panel it was captured against, so
    callers MUST confirm the target matches before writing (see
    `verify_addresses`).
    """

    def __init__(self) -> None:
        self.templates: dict[str, VendorTemplate] = {}

    def learn(self, data: bytes) -> str | None:
        """Record a vendor frame; returns the operation if it was new."""
        if len(data) < PAYLOAD_OFFSET + 2 or data[14:16] != MARKER:
            return None
        if data[4:14] != SIGNATURE:
            return None
        op = data[21:23].hex()
        if op not in (READ_OP, WRITE_OP) or op in self.templates:
            return None
        template = VendorTemplate(data)
        if not template.is_valid():
            return None
        self.templates[op] = template
        return op

    @property
    def can_read(self) -> bool:
        return READ_OP in self.templates

    @property
    def can_write(self) -> bool:
        return WRITE_OP in self.templates and READ_OP in self.templates

    def read_frame(self, button: int, page: int, source_ip: bytes) -> bytes:
        return self.templates[READ_OP].with_payload(
            bytes([button, page]), source_ip=source_ip
        )

    def write_frame(
        self, button: int, page: int, record: bytes, source_ip: bytes
    ) -> bytes:
        return self.templates[WRITE_OP].with_payload(
            bytes([button, page]) + record + b"\xff", source_ip=source_ip
        )

    def as_dict(self) -> dict[str, str]:
        return {op: t.raw.hex() for op, t in self.templates.items()}

    def load(self, data: dict[str, str]) -> None:
        for op, hexdata in data.items():
            try:
                template = VendorTemplate(bytes.fromhex(hexdata))
            except ValueError:
                continue
            if template.is_valid():
                self.templates[op] = template


def button_record(
    function: int, subnet: int, device: int, p1: int, p2: int, p3: int = 0
) -> bytes:
    """The Magic Line body shared by read responses and write requests."""
    return bytes([function, subnet, device, p1, p2]) + p3.to_bytes(2, "big")


def parse_button_payload(payload: bytes) -> dict | None:
    """Decode a read-response / write-request payload."""
    if len(payload) < 9:
        return None
    return {
        "button": payload[0],
        "page": payload[1],
        "function": payload[2],
        "target": f"{payload[3]}.{payload[4]}",
        "p1": payload[5],
        "p2": payload[6],
        "p3": int.from_bytes(payload[7:9], "big"),
    }
