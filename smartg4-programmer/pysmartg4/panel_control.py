"""Live panel control: LED / LCD backlight intensity, locks, page jumps.

Two ways exist to change a wall panel's LED brightness:

* **Live** — ``0xE3D8`` ``Panel_Control(type, value)`` from the official SDK
  (``OCR_PANEL_CONTROL``), acked by ``0xE3D9``. The ``type`` byte selects the
  sub-function; the list below is the vendor app's own
  ``[AirControlTypeForPanelControl]`` table, which is what a panel key
  programmed as "Panel control" (KeyFunType 0x5F) sends. Type 14 is the LED
  backlight level, 13 the LCD backlight level, both 0..100. This is the path
  to use from Home Assistant: instant, plain-frame, documented.

* **Stored setting** — ``0xE010``/``0xE012`` (:mod:`pysmartg4.panel_config`),
  the record behind the vendor app's "Dimming and LED" page. Reading it gives
  the current configured levels; writing persists them across power cycles.
  :func:`persist_led_levels` reads, patches the two level bytes and writes
  the record back so the rest of it is left untouched.
"""

from __future__ import annotations

from enum import IntEnum

from .packet import DeviceAddress
from . import panel_config as _pc

PANEL_CONTROL = 0xE3D8
PANEL_CONTROL_RESPONSE = 0xE3D9


class PanelControlType(IntEnum):
    """``Panel_Control`` sub-functions (vendor table, 1:1 with the SDK)."""

    IR_RECEIVER = 1
    LOCK_KEY = 2
    AC_POWER = 3
    AC_COOL_SETPOINT = 4
    AC_FAN_SPEED = 5
    AC_MODE = 6
    AC_HEAT_SETPOINT = 7
    AC_AUTO_SETPOINT = 8
    RAISE_TEMPERATURE = 9
    LOWER_TEMPERATURE = 10
    LCD_BACKLIGHT_SWITCH = 11
    LOCK_AC_PAGE = 12
    LCD_BACKLIGHT_LEVEL = 13
    LED_LEVEL = 14
    LOCK_BUTTON = 15
    LOCK_PAGE = 16
    BUTTON_STATUS = 17
    BUTTON = 18
    DRY_TEMPERATURE = 19
    FLOOR_HEATING_POWER = 20
    FLOOR_HEATING_MODE = 21
    GOTO_PAGE = 22
    FLOOR_HEATING_SETPOINT = 23
    DIMMING_ADJUST = 24
    AC_FAN_SPEED_ADJUST = 25
    AC_TEMPERATURE_ADJUST = 26


def _check_percent(value: int, name: str) -> int:
    value = int(value)
    if not 0 <= value <= 100:
        raise ValueError(f"{name} must be 0..100, got {value}")
    return value


async def panel_control(
    bus, target: DeviceAddress, control_type: int, value: int, *, wait_ack: bool = True
) -> bool:
    """Send one ``Panel_Control`` command. Returns True if the panel acked.

    With ``wait_ack=False`` the frame is fired without waiting (some panels
    act on the command but never answer ``0xE3D9``).
    """
    data = {"type": int(control_type), "value": int(value) & 0xFF}
    if not wait_ack:
        bus.send(target, PANEL_CONTROL, data)
        return False
    try:
        await bus.request(target, PANEL_CONTROL, data)
        return True
    except (TimeoutError, OSError):
        return False


async def set_led_level(bus, target: DeviceAddress, level: int, **kw) -> bool:
    """Set the key LED brightness (0..100 %) live."""
    return await panel_control(
        bus, target, PanelControlType.LED_LEVEL, _check_percent(level, "level"), **kw
    )


async def set_backlight_level(bus, target: DeviceAddress, level: int, **kw) -> bool:
    """Set the LCD backlight brightness (0..100 %) live."""
    return await panel_control(
        bus, target, PanelControlType.LCD_BACKLIGHT_LEVEL,
        _check_percent(level, "level"), **kw,
    )


async def set_backlight_on(bus, target: DeviceAddress, on: bool, **kw) -> bool:
    """Switch the LCD backlight on/off live."""
    return await panel_control(
        bus, target, PanelControlType.LCD_BACKLIGHT_SWITCH, 1 if on else 0, **kw
    )


async def lock_buttons(bus, target: DeviceAddress, locked: bool, **kw) -> bool:
    return await panel_control(
        bus, target, PanelControlType.LOCK_BUTTON, 1 if locked else 0, **kw
    )


async def goto_page(bus, target: DeviceAddress, page: int, **kw) -> bool:
    return await panel_control(bus, target, PanelControlType.GOTO_PAGE, int(page), **kw)


async def read_led_levels(bus, target: DeviceAddress, **kw) -> dict | None:
    """The panel's stored LED / backlight levels (``0xE010``), or None."""
    rec = await _pc.read_led_level(bus, target, **kw)
    if rec is None:
        return None
    return {"backlight": rec.backlight, "led": rec.led, "enabled": rec.enabled,
            "record": rec}


async def persist_led_levels(
    bus,
    target: DeviceAddress,
    *,
    led: int | None = None,
    backlight: int | None = None,
    **kw,
) -> bool:
    """Store new LED and/or backlight levels in the panel's settings.

    Reads the current ``0xE010`` record so every other byte of it is written
    back unchanged, then sends ``0xE012``. Returns True on the panel's ack;
    False if the record could not be read or the write went unanswered.
    """
    rec = await _pc.read_led_level(bus, target, **kw)
    if rec is None:
        return False
    new = _pc.LedLevel(
        backlight=_check_percent(backlight, "backlight") if backlight is not None else rec.backlight,
        led=_check_percent(led, "led") if led is not None else rec.led,
        enabled=rec.enabled,
        params=rec.params,
        wide=rec.wide,
    )
    return await _pc.write_led_level(bus, target, new, **kw)


__all__ = [
    "PANEL_CONTROL",
    "PANEL_CONTROL_RESPONSE",
    "PanelControlType",
    "panel_control",
    "set_led_level",
    "set_backlight_level",
    "set_backlight_on",
    "lock_buttons",
    "goto_page",
    "read_led_levels",
    "persist_led_levels",
]
