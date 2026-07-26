"""Async UDP transport for the S-BUS / Smart-G4 protocol.

The RSIP / Z-Audio gateway relays every bus telegram to the LAN as a UDP
broadcast on port 6000 and forwards LAN datagrams onto the bus, so a
single socket bound to that port sees all bus traffic and can inject
commands.
"""

from __future__ import annotations

import asyncio
import logging
import socket
from typing import Any, Callable

from . import commands
from .packet import (
    BROADCAST,
    SIGNATURE_SMARTCLOUD,
    VIRTUAL_DEVICE_TYPE,
    DeviceAddress,
    Packet,
)

_LOGGER = logging.getLogger(__name__)

PacketCallback = Callable[[Packet, "dict[str, Any] | None"], None]


class SmartG4Bus(asyncio.DatagramProtocol):
    """Listens on UDP port 6000 and sends S-BUS commands.

    gateway: IP of the RSIP/Z-Audio module, or a broadcast address such as
    "192.168.10.255" (recommended — the gateway hears broadcasts and so do
    we, which also enables passive monitoring on multi-gateway setups).
    """

    def __init__(
        self,
        gateway: str = "255.255.255.255",
        port: int = 6000,
        sender: DeviceAddress = DeviceAddress(0xEE, 0xEE),
        sender_type: int | None = None,
        signature: bytes = SIGNATURE_SMARTCLOUD,
    ) -> None:
        self.gateway = gateway
        self.port = port
        self.sender = sender
        # The official SDK mirrors its own subnet/device into the 2-byte
        # device-type field, and Smart-G4 modules were observed to IGNORE
        # probes carrying the community 0xFFFE "virtual PC" type — so
        # mirror by default, exactly like the SDK (whose default self
        # address is 238.238).
        self.sender_type = (
            sender_type
            if sender_type is not None
            else (sender.subnet << 8) | sender.device
        )
        self.signature = signature

        self._transport: asyncio.DatagramTransport | None = None
        self._callbacks: list[PacketCallback] = []
        self._waiters: list[
            tuple[Callable[[Packet], bool], asyncio.Future[Packet]]
        ] = []
        self._local_ip = b"\x00\x00\x00\x00"

    # -- lifecycle ----------------------------------------------------------

    async def connect(self) -> None:
        loop = asyncio.get_running_loop()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if hasattr(socket, "SO_REUSEPORT"):
            # Lets several S-BUS tools (add-on, HA integration, CLI tools)
            # share port 6000 on one host; broadcasts reach all of them.
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.bind(("", self.port))
        await loop.create_datagram_endpoint(lambda: self, sock=sock)
        self._detect_local_ip()

    def close(self) -> None:
        if self._transport:
            self._transport.close()
            self._transport = None

    def _detect_local_ip(self) -> None:
        """Best-effort detection of our LAN IP for the frame preamble."""
        try:
            probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            probe.connect((self.gateway.replace("255", "1", 1), 6000))
            self._local_ip = socket.inet_aton(probe.getsockname()[0])
            probe.close()
        except OSError:
            _LOGGER.debug("could not detect local IP; using 0.0.0.0")

    # -- receiving ----------------------------------------------------------

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self._transport = transport  # type: ignore[assignment]

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        try:
            packet = Packet.decode(data)
        except ValueError as err:
            _LOGGER.debug("ignoring invalid datagram from %s: %s", addr, err)
            return

        parsed = commands.parse_payload(packet.opcode, packet.payload)

        for matcher, future in list(self._waiters):
            if not future.done() and matcher(packet):
                future.set_result(packet)

        for callback in self._callbacks:
            try:
                callback(packet, parsed)
            except Exception:  # noqa: BLE001 - user callback must not kill the loop
                _LOGGER.exception("error in packet callback")

    def on_packet(self, callback: PacketCallback) -> Callable[[], None]:
        """Subscribe to all decoded packets. Returns an unsubscribe function."""
        self._callbacks.append(callback)
        return lambda: self._callbacks.remove(callback)

    # -- sending ------------------------------------------------------------

    def send(
        self,
        target: DeviceAddress,
        opcode: int,
        data: dict[str, Any] | None = None,
        payload: bytes = b"",
    ) -> None:
        if data is not None:
            payload = commands.encode_payload(opcode, data)
        packet = Packet(
            opcode=opcode,
            source=self.sender,
            target=target,
            source_type=self.sender_type,
            payload=payload,
            signature=self.signature,
            source_ip=self._local_ip,
        )
        if not self._transport:
            raise RuntimeError("bus is not connected; call connect() first")
        self._transport.sendto(packet.encode(), (self.gateway, self.port))

    async def request(
        self,
        target: DeviceAddress,
        opcode: int,
        data: dict[str, Any] | None = None,
        payload: bytes = b"",
        timeout: float = 2.0,
        retries: int = 2,
        match: Callable[[Packet], bool] | None = None,
    ) -> Packet:
        """Send a command and await the matching response from the target.

        `match` optionally filters response payloads — needed when devices
        emit duplicate responses (observed live) and replies must be paired
        with a specific request, e.g. a flash page number.
        """
        response = commands.response_opcode(opcode)
        if response is None:
            raise ValueError(f"opcode {opcode:#06x} has no known response code")

        def matches(packet: Packet) -> bool:
            return (
                packet.opcode == response
                and (target.is_broadcast or packet.source == target)
                and (match is None or match(packet))
            )

        last_error: Exception | None = None
        for _ in range(retries + 1):
            future: asyncio.Future[Packet] = (
                asyncio.get_running_loop().create_future()
            )
            entry = (matches, future)
            self._waiters.append(entry)
            try:
                self.send(target, opcode, data, payload)
                return await asyncio.wait_for(future, timeout)
            except asyncio.TimeoutError as err:
                last_error = err
            finally:
                self._waiters.remove(entry)
        raise TimeoutError(
            f"no response {response:#06x} from {target} "
            f"after {retries + 1} attempts"
        ) from last_error

    # -- convenience wrappers ------------------------------------------------

    async def set_channel(
        self,
        target: DeviceAddress,
        channel: int,
        level: int,
        transition: int = 0,
    ) -> Packet:
        """Set dimmer/relay channel level (0-100) with optional ramp seconds."""
        return await self.request(
            target,
            0x0031,
            {"channel": channel, "level": level, "time": transition},
        )

    async def read_channels(self, target: DeviceAddress) -> Packet:
        return await self.request(target, 0x0033)

    def activate_scene(self, target: DeviceAddress, area: int, scene: int) -> None:
        self.send(target, 0x0002, {"area": area, "scene": scene})

    def set_universal_switch(
        self, target: DeviceAddress, switch: int, status: bool
    ) -> None:
        self.send(target, 0xE01C, {"switch": switch, "status": status})

    def panel_control(
        self, target: DeviceAddress, control_type: int, value: int
    ) -> None:
        """Universal DDP panel command (opcode 0xE3D8).

        control_type per the vendor SDK: 3=AC power, 4=cool setpoint,
        5=fan speed, 6=AC mode, 7=heat setpoint, 8=auto setpoint,
        1=IR receiver, 2=button lock. Also used to emulate panel button
        presses so button logic can live in Home Assistant.
        """
        self.send(target, 0xE3D8, {"type": control_type, "value": value})

    def hvac_control(
        self,
        target: DeviceAddress,
        *,
        ac: int = 1,
        power: bool = True,
        mode_speed: int = 0,
        temperature: int = 0,
        cool: int = 0,
        heat: int = 0,
        auto: int = 0,
    ) -> None:
        """HVAC automatic control (opcode 0x193A)."""
        self.send(
            target,
            0x193A,
            {
                "ac": ac,
                "power": power,
                "mode_speed": mode_speed,
                "temperature": temperature,
                "cool": cool,
                "heat": heat,
                "auto": auto,
            },
        )
