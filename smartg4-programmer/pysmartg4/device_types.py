"""Known S-BUS device type codes.

The device type is reported in every frame header. This table is
deliberately small and grows as we identify modules on the user's bus —
unknown types are displayed as hex and remain fully usable.

Sources: wb-mqtt-smartbus, community protocol documentation.
"""

DEVICE_TYPES: dict[int, str] = {
    0x0095: "DDP panel (dynamic display panel)",
    # Observed live on this bus (1.55/1.108/1.109): answers 0x000E scan,
    # broadcasts 3-channel 0xEFFF scene status, ignores 0x0033 and 0xF003.
    0x07D3: "3-channel relay/dimmer module",
    # Observed live: answers 0x0033 with 12 channel levels; names like
    # "F1 O/F2" (on/off).
    0x01B8: "12-channel relay module",
    # Observed live: one per room ("F1 Bathroom", "B Movie Room", ...);
    # answers 0x000E but no channel/temperature reads. Model unconfirmed.
    0x0119: "Room module (unidentified, likely wall panel)",
    # Confirmed by the owner: the installation's central controller.
    0x0456: "Central controller",
    0x139C: "Zone Beast (relay/dimmer/HVAC combo)",
    0xFFFE: "Virtual device (PC / integration)",
}


def device_type_name(device_type: int) -> str:
    return DEVICE_TYPES.get(device_type, f"Unknown (0x{device_type:04X})")
