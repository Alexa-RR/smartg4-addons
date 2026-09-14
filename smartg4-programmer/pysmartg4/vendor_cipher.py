"""The Smart Cloud "vendor" frame cipher — cracked from the app, no capture.

Smart Cloud programs panel buttons (read/write a key's function config) with
frames that look non-standard on the wire: after the ``SMARTCLOUD`` signature
they carry the marker ``0x45 0x63`` instead of the usual ``0xAA 0xAA`` sync,
and their 8 header bytes (source subnet/device, source type, opcode, target
subnet/device) are scrambled, so no CRC appears to validate the frame.

It is not encryption in any real sense. Reversed from ``FUN_01271388`` in
``Smart Cloud Configuration V16.38`` (the routine ``TfrmMain.SendAddBuf`` calls
right before sending a ``0x45 0x63`` frame), the transform is, per header byte
``i`` (0..7)::

    k   = key[i]                       # key defaults to b"SMARTBUS"
    b   = ror8(b, k % 7)               # rotate right (k mod 7) bits
    b   = b ^ k                        # xor with the key byte

The key is the panel's programming password as a string; an unset password
falls back to ``"SMARTBUS"`` (the app substitutes ``"SMARTBUS"`` when the
password field is empty). Only the 8 header bytes are transformed; the length
byte, the payload and the CRC are plaintext, and the CRC is the ordinary
CRC-16/XMODEM over the *plaintext* telegram (computed before the header is
scrambled).

Consequences, versus the old capture-and-replay approach in
``vendor_frame.py``:

* frames can be built from scratch for *any* panel and any target — nothing
  needs to be captured first, and the destination is no longer trapped inside
  an opaque header;
* incoming ``0x45 0x63`` frames decode to a normal :class:`~pysmartg4.packet.Packet`.

Verified: the app's captured opcode field ``0xB4 0x42`` decrypts to ``0xE000``
(``ReadPanelKeyFunConfig``), matching the opcode found independently in the
disassembly; round-trips on random input; see ``tests/test_vendor_cipher.py``.
"""

from __future__ import annotations

from .crc import crc16_xmodem

DEFAULT_KEY = b"SMARTBUS"

SIGNATURE = b"SMARTCLOUD"
VENDOR_MARKER = b"\x45\x63"
STANDARD_SYNC = b"\xaa\xaa"

# Datagram layout (both variants): [0:4] source IP, [4:14] signature,
# [14:16] marker/sync, [16] length, [17:25] the 8 header bytes, then payload,
# then 2 CRC bytes.
MARKER_OFFSET = 14
LENGTH_OFFSET = 16
HEADER_OFFSET = 17
HEADER_LEN = 8


def _ror8(value: int, count: int) -> int:
    count &= 7
    return ((value >> count) | (value << (8 - count))) & 0xFF


def _rol8(value: int, count: int) -> int:
    count &= 7
    return ((value << count) | (value >> (8 - count))) & 0xFF


def _key_bytes(key: bytes | str | None) -> bytes:
    if key is None or key == b"" or key == "":
        return DEFAULT_KEY
    if isinstance(key, str):
        key = key.encode("latin1")
    if len(key) < HEADER_LEN:
        raise ValueError(f"vendor key must be >= {HEADER_LEN} bytes, got {len(key)}")
    return key


def encrypt_header(header: bytes, key: bytes | str | None = None) -> bytes:
    """Scramble the 8 plaintext header bytes for a ``0x45 0x63`` frame."""
    if len(header) != HEADER_LEN:
        raise ValueError(f"header must be {HEADER_LEN} bytes, got {len(header)}")
    k = _key_bytes(key)
    out = bytearray(HEADER_LEN)
    for i in range(HEADER_LEN):
        out[i] = _ror8(header[i], k[i] % 7) ^ k[i]
    return bytes(out)


def decrypt_header(header: bytes, key: bytes | str | None = None) -> bytes:
    """Recover the 8 plaintext header bytes from a ``0x45 0x63`` frame."""
    if len(header) != HEADER_LEN:
        raise ValueError(f"header must be {HEADER_LEN} bytes, got {len(header)}")
    k = _key_bytes(key)
    out = bytearray(HEADER_LEN)
    for i in range(HEADER_LEN):
        out[i] = _rol8(header[i] ^ k[i], k[i] % 7)
    return bytes(out)


def to_vendor_frame(datagram: bytes, key: bytes | str | None = None) -> bytes:
    """Turn a standard ``0xAAAA`` datagram into its ``0x45 0x63`` vendor form.

    The input is what :meth:`pysmartg4.packet.Packet.encode` produces. The CRC
    is left untouched because it is computed over the plaintext telegram; only
    the marker and the 8 header bytes change.
    """
    if len(datagram) < HEADER_OFFSET + HEADER_LEN + 2:
        raise ValueError("datagram too short to be a vendor frame")
    out = bytearray(datagram)
    out[MARKER_OFFSET : MARKER_OFFSET + 2] = VENDOR_MARKER
    out[HEADER_OFFSET : HEADER_OFFSET + HEADER_LEN] = encrypt_header(
        bytes(datagram[HEADER_OFFSET : HEADER_OFFSET + HEADER_LEN]), key
    )
    return bytes(out)


def from_vendor_frame(datagram: bytes, key: bytes | str | None = None) -> bytes:
    """Turn a ``0x45 0x63`` vendor frame back into a standard ``0xAAAA`` datagram.

    The result decodes with :meth:`pysmartg4.packet.Packet.decode`.
    """
    if len(datagram) < HEADER_OFFSET + HEADER_LEN + 2:
        raise ValueError("datagram too short to be a vendor frame")
    out = bytearray(datagram)
    out[MARKER_OFFSET : MARKER_OFFSET + 2] = STANDARD_SYNC
    out[HEADER_OFFSET : HEADER_OFFSET + HEADER_LEN] = decrypt_header(
        bytes(datagram[HEADER_OFFSET : HEADER_OFFSET + HEADER_LEN]), key
    )
    return bytes(out)


def is_vendor_frame(datagram: bytes) -> bool:
    """True if this datagram is a Smart Cloud ``0x45 0x63`` vendor frame."""
    return (
        len(datagram) >= HEADER_OFFSET + HEADER_LEN + 2
        and datagram[4:14] == SIGNATURE
        and datagram[MARKER_OFFSET : MARKER_OFFSET + 2] == VENDOR_MARKER
    )


def verify_plaintext_crc(datagram: bytes, key: bytes | str | None = None) -> bool:
    """Check that a vendor frame's trailing CRC matches its plaintext telegram."""
    plain = from_vendor_frame(datagram, key)
    length = plain[LENGTH_OFFSET]
    content = plain[LENGTH_OFFSET : LENGTH_OFFSET + length - 2]
    crc_expected = int.from_bytes(plain[LENGTH_OFFSET + length - 2 : LENGTH_OFFSET + length], "big")
    return crc16_xmodem(content) == crc_expected
