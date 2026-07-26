"""CRC-16/XMODEM as used by the S-BUS / HDL Buspro wire protocol.

Polynomial 0x1021, initial value 0x0000, no reflection, no final XOR.
The checksum covers the frame content from the length byte through the
last payload byte (i.e. everything after the 16-byte UDP preamble and
before the 2-byte CRC itself).
"""

_TABLE: list[int] = []


def _build_table() -> None:
    for byte in range(256):
        crc = byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) if crc & 0x8000 else (crc << 1)
        _TABLE.append(crc & 0xFFFF)


_build_table()


def crc16_xmodem(data: bytes) -> int:
    crc = 0
    for byte in data:
        crc = ((crc << 8) & 0xFFFF) ^ _TABLE[((crc >> 8) ^ byte) & 0xFF]
    return crc
