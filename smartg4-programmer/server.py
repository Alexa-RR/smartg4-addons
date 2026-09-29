"""Smart-G4 Builder — Home Assistant ingress add-on backend.

Serves the single-page UI (www/app.html, wrapped in an HTML skeleton) and a
small JSON + WebSocket API backed by pysmartg4. Runs behind HA ingress, so the
frontend uses only relative URLs and inherits the ingress base path.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from pathlib import Path

from aiohttp import WSMsgType, web

from pysmartg4 import SmartG4Bus, opcode_name
from pysmartg4.backup import (
    DeviceBackup,
    backup_device,
    commit_restore,
    read_backup_info,
    read_page,
    stage_page,
)
from pysmartg4.ddp import (
    LAYOUTS,
    ButtonCommand,
    apply_button,
    decode_panel,
    find_channel_names,
)
from pysmartg4.device_types import device_type_name
from pysmartg4.discovery import discover, merge_device_lists
from pysmartg4.naming import (
    clean as clean_name,
    read_channel_names,
    write_channel_name,
    write_device_name,
)
from pysmartg4.packet import BROADCAST, DeviceAddress, Packet
from pysmartg4.vendor_frame import (
    READ_RESP,
    WRITE_RESP,
    TemplateStore,
    button_record,
    parse_button_payload,
)
from pysmartg4.vendor_program import (
    FIRST_PAGE,
    KEYMODE_READ_RESPONSE,
    KEYMODE_WRITE_RESPONSE,
    LABEL_READ_RESPONSE,
    READ_RESPONSE,
    WRITE_RESPONSE,
    ButtonFunction,
    build_keymode_read_frame,
    build_keymode_write_frame,
    build_label_read_frame,
    build_read_frame,
    build_write_frame,
    parse_response,
)

APP_DIR = Path(__file__).parent
GATEWAY = os.environ.get("SMARTG4_GATEWAY", "255.255.255.255")
SUBNET = int(os.environ.get("SMARTG4_SUBNET", "238"))
DEVICE = int(os.environ.get("SMARTG4_DEVICE", "238"))
BACKUP_DIR = Path(os.environ.get("SMARTG4_BACKUP_DIR", "backups"))
# The flash-restore commit (0xDC16) is inferred from the SDK but not yet
# verified on real hardware — writing is opt-in via add-on configuration.
FLASH_WRITE_ENABLED = os.environ.get(
    "SMARTG4_ENABLE_FLASH_WRITE", "false"
).lower() in ("1", "true", "yes")
PORT = 8099

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
_LOGGER = logging.getLogger("smartg4")

SKELETON = """<!doctype html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Smart-G4 Builder</title></head><body>{body}</body></html>"""


async def index(_request: web.Request) -> web.Response:
    body = (APP_DIR / "www" / "app.html").read_text(encoding="utf-8")
    return web.Response(text=SKELETON.format(body=body), content_type="text/html")


async def api_config(_request: web.Request) -> web.Response:
    return web.json_response(
        {"gateway": GATEWAY, "subnet": SUBNET, "device": DEVICE}
    )


def _inventory_path() -> Path:
    return BACKUP_DIR / "devices.json"


def _channel_names_path() -> Path:
    return BACKUP_DIR / "channel_names.json"


def _sane_name(name: object) -> bool:
    """Reject anything that isn't a real name — including mojibake cached
    by older versions that decoded raw flash as ASCII."""
    return (
        isinstance(name, str)
        and bool(name.strip())
        and "�" not in name
        and all(c.isprintable() for c in name)
    )


def _sanitize_channel_cache(cache: dict) -> dict:
    clean: dict[str, list] = {}
    for address, names in cache.items():
        if not isinstance(names, list):
            continue
        scrubbed = [n if _sane_name(n) else None for n in names]
        if any(scrubbed):  # all-empty: drop so it gets re-read
            clean[address] = scrubbed
    return clean


def _save_channel_names(app: web.Application) -> None:
    try:
        BACKUP_DIR.mkdir(parents=True, exist_ok=True)
        _channel_names_path().write_text(
            json.dumps(app["channel_names"], indent=2), encoding="utf-8"
        )
    except OSError:
        pass


def _save_inventory(app: web.Application) -> None:
    try:
        BACKUP_DIR.mkdir(parents=True, exist_ok=True)
        _inventory_path().write_text(
            json.dumps(app["devices"], indent=2), encoding="utf-8"
        )
    except OSError:
        pass  # persistence is best-effort


def _update_inventory(app: web.Application, found: list[dict]) -> int:
    """Merge into the inventory IN PLACE (the app mapping is frozen after
    startup) and persist. Returns the number of new devices."""
    merged, new = merge_device_lists(app["devices"], found)
    app["devices"][:] = merged
    _save_inventory(app)
    return new


async def api_inventory(request: web.Request) -> web.Response:
    """The accumulated inventory, instantly — no scan."""
    return web.json_response(request.app["devices"])


async def api_devices(request: web.Request) -> web.Response:
    """Scan and return the ACCUMULATED inventory, not just this scan.

    Broadcast scan replies are lossy (RS-485 collisions), so any single
    scan misses modules; the inventory merges every scan and all passive
    traffic, and persists across restarts.
    """
    app = request.app
    bus: SmartG4Bus = app["bus"]
    duration = float(request.query.get("duration", 30.0))
    _LOGGER.info("scan: starting (%.0fs)", duration)
    found = await discover(bus, duration=min(duration, 120.0))
    new = _update_inventory(app, [d.as_dict() for d in found])
    _LOGGER.info(
        "scan: %d answered, %d new, inventory now %d",
        len(found), new, len(app["devices"]),
    )
    return web.json_response(app["devices"])


async def api_send(request: web.Request) -> web.Response:
    """Generic command passthrough: {target, opcode, data|payload, confirm}.

    With confirm=true and a known response opcode, waits for the module's
    acknowledgement and reports it.
    """
    bus: SmartG4Bus = request.app["bus"]
    body = await request.json()
    target = DeviceAddress.parse(body["target"])
    opcode = int(body["opcode"])
    data = body.get("data")
    payload = bytes(body.get("payload", []))
    try:
        if body.get("confirm"):
            try:
                packet = await bus.request(
                    target, opcode, data, payload, timeout=1.0, retries=2
                )
                return web.json_response(
                    {"ok": True, "confirmed": True,
                     "ack": f"0x{packet.opcode:04X}"}
                )
            except (TimeoutError, asyncio.TimeoutError):
                return web.json_response({"ok": True, "confirmed": False})
        bus.send(target, opcode, data, payload=payload)
        return web.json_response({"ok": True})
    except Exception as err:  # noqa: BLE001 - report to UI
        return web.json_response({"ok": False, "error": str(err)}, status=400)


# Output-module channel counts by device type (live-confirmed).
OUTPUT_CHANNELS = {0x01B8: 12, 0x07D3: 3}


async def api_channels(request: web.Request) -> web.Response:
    """Output modules + channel names — feeds the editor's dropdowns.

    Names come from the modules themselves (0xF00E), cached in
    /share/smartg4; `?refresh=1` re-reads them from the bus, and a saved
    .sbd backup is used as a fallback for anything that stays silent.
    """
    app = request.app
    bus: SmartG4Bus = app["bus"]
    refresh = request.query.get("refresh") in ("1", "true", "yes")
    cache = app["channel_names"]
    result = []
    for device in app["devices"]:
        count = OUTPUT_CHANNELS.get(int(device["device_type"], 16))
        if not count:
            continue
        address = device["address"]
        names = cache.get(address)
        if names is None or refresh:
            live = await read_channel_names(
                bus, DeviceAddress.parse(address), count
            )
            fallback: list[str] | None = None
            if any(n is None for n in live):
                path = BACKUP_DIR / f"{address}.sbd"
                if path.is_file():
                    try:
                        fallback = find_channel_names(
                            DeviceBackup.from_sbd(
                                path.read_text(encoding="utf-8")
                            ),
                            count,
                        )
                    except (OSError, ValueError):
                        fallback = None
            names = [
                live[i]
                if live[i] is not None
                else (fallback[i] if fallback else None)
                for i in range(count)
            ]
            names = [n if _sane_name(n) else None for n in names]
            # Always replace the cached entry — a module that answers with
            # nothing must clear stale values, not keep serving them.
            if any(names):
                cache[address] = names
            else:
                cache.pop(address, None)
            _save_channel_names(app)
        result.append(
            {
                "address": address,
                "name": device.get("remark") or f"Module {address}",
                "channels": count,
                "channel_names": names,
            }
        )
    return web.json_response(result)


async def api_rename(request: web.Request) -> web.Response:
    """Rename a device (0x0010) or one of its channels (0xF010).

    Body: {target, remark} for a device, or {target, channel, remark}
    for a channel. Channel renames are verified by reading the name back.
    """
    app = request.app
    bus: SmartG4Bus = app["bus"]
    body = await request.json()
    target = DeviceAddress.parse(body["target"])
    remark = clean_name(str(body["remark"]))

    if body.get("channel"):
        channel = int(body["channel"])
        ok = await write_channel_name(bus, target, channel, remark)
        _LOGGER.info(
            "rename: %s ch%d -> %r %s",
            target, channel, remark, "OK" if ok else "FAILED",
        )
        if not ok:
            return web.json_response(
                {"ok": False, "error": "channel name did not stick"},
                status=504,
            )
        return web.json_response({"ok": True, "remark": remark})

    if not await write_device_name(bus, target, remark):
        _LOGGER.warning("rename: %s -> %r no ack", target, remark)
        return web.json_response(
            {"ok": False, "error": "no acknowledgement from device"}, status=504
        )
    for device in app["devices"]:
        if device["address"] == str(target):
            device["remark"] = remark
    _save_inventory(app)
    _LOGGER.info("rename: %s -> %r OK", target, remark)
    return web.json_response({"ok": True, "remark": remark})


async def api_backup_start(request: web.Request) -> web.Response:
    """Start a flash backup of one device; progress via /api/backup/status."""
    app = request.app
    job = app["backup_job"]
    if job["task"] is not None and not job["task"].done():
        return web.json_response(
            {"ok": False, "error": f"backup of {job['target']} still running"},
            status=409,
        )
    body = await request.json()
    target = DeviceAddress.parse(body["target"])
    bus: SmartG4Bus = app["bus"]
    try:
        total = await read_backup_info(bus, target)
    except (TimeoutError, asyncio.TimeoutError):
        return web.json_response(
            {"ok": False, "error": "device does not answer backup reads"},
            status=504,
        )
    job.update(target=str(target), done=0, total=total, error=None, file=None)
    _LOGGER.info("backup: %s starting (%d pages)", target, total)

    async def run() -> None:
        def progress(done: int, _total: int) -> None:
            job["done"] = done

        try:
            backup = await backup_device(bus, target, progress=progress)
            BACKUP_DIR.mkdir(parents=True, exist_ok=True)
            path = BACKUP_DIR / f"{target}.sbd"
            path.write_text(backup.to_sbd(), encoding="utf-8")
            job["file"] = path.name
            _LOGGER.info("backup: %s written to %s", target, path)
        except Exception as err:  # noqa: BLE001 - reported via status endpoint
            job["error"] = str(err)
            _LOGGER.exception("backup: %s failed", target)

    job["task"] = asyncio.create_task(run())
    return web.json_response({"ok": True, "total": total})


async def api_backup_status(request: web.Request) -> web.Response:
    job = request.app["backup_job"]
    return web.json_response(
        {
            "running": job["task"] is not None and not job["task"].done(),
            "target": job["target"],
            "done": job["done"],
            "total": job["total"],
            "file": job["file"],
            "error": job["error"],
        }
    )


async def api_backups(request: web.Request) -> web.Response:
    if not BACKUP_DIR.is_dir():
        return web.json_response([])
    return web.json_response(
        sorted(p.name for p in BACKUP_DIR.glob("*.sbd"))
    )


def _known_device_type(app: web.Application, address: str) -> int | None:
    for device in app["devices"]:
        if device["address"] == address:
            return int(device["device_type"], 16)
    return None


def _templates_path() -> Path:
    return BACKUP_DIR / "vendor_templates.json"


async def _vendor_exchange(
    app: web.Application, frame: bytes, response_op: str, button: int,
    timeout: float = 2.0,
) -> dict | None:
    """Send a forged vendor frame and wait for its reply."""
    loop = asyncio.get_running_loop()
    future: asyncio.Future = loop.create_future()

    def on_raw(data: bytes, _addr) -> None:
        if future.done() or len(data) < 27 or data[14:16] != b"\x45\x63":
            return
        if data[21:23].hex() != response_op:
            return
        payload = data[25:-2]
        if payload and payload[0] == button:
            future.set_result(parse_button_payload(payload))

    unsubscribe = app["bus"].on_raw(on_raw)
    try:
        app["bus"].send_raw(frame)
        return await asyncio.wait_for(future, timeout)
    except (TimeoutError, asyncio.TimeoutError):
        return None
    finally:
        unsubscribe()


async def _program_exchange(
    app: web.Application,
    frame: bytes,
    want_opcode: int,
    button: int | None = None,
    timeout: float = 2.0,
    retries: int = 3,
    panel: DeviceAddress | None = None,
) -> dict | None:
    """Send a capture-free vendor programming frame and await its reply.

    Mirrors Smart Cloud: up to `retries` attempts with a short timeout, since
    these frames collide with the panel's periodic broadcasts. `button`
    narrows the match to replies about that key; `panel` to replies from
    that panel (several panels answer the same opcodes).
    """
    bus: SmartG4Bus = app["bus"]
    for _ in range(retries):
        loop = asyncio.get_running_loop()
        future: asyncio.Future = loop.create_future()

        def on_raw(data: bytes, _addr) -> None:
            if future.done():
                return
            parsed = parse_response(data)
            if (
                parsed
                and parsed.get("opcode") == want_opcode
                and (button is None or parsed.get("button") == button)
                and (panel is None or parsed.get("source") == str(panel))
            ):
                future.set_result(parsed)

        unsubscribe = bus.on_raw(on_raw)
        try:
            bus.send_raw(frame)
            return await asyncio.wait_for(future, timeout)
        except (TimeoutError, asyncio.TimeoutError):
            continue
        finally:
            unsubscribe()
    return None


def _program_source(app: web.Application) -> dict:
    """Source identity for capture-free frames, taken from the live bus."""
    bus: SmartG4Bus = app["bus"]
    return {
        "source": bus.sender,
        "source_type": bus.sender_type,
        "source_ip": app["local_ip"],
    }


async def _program_read(
    app: web.Application,
    panel: DeviceAddress,
    button: int,
    page: int = FIRST_PAGE,
    **kwargs,
) -> dict | None:
    frame = build_read_frame(button, page, panel, **_program_source(app))
    return await _program_exchange(
        app, frame, READ_RESPONSE, button, panel=panel, **kwargs
    )


async def _program_read_label(
    app: web.Application, panel: DeviceAddress, button: int, **kwargs
) -> str | None:
    frame = build_label_read_frame(button, panel, **_program_source(app))
    reply = await _program_exchange(
        app, frame, LABEL_READ_RESPONSE, button, panel=panel, **kwargs
    )
    return None if reply is None else reply.get("label", "")


async def _program_prepare_write(
    app: web.Application, panel: DeviceAddress
) -> bool:
    """Replay Smart Cloud's pre-write handshake: read key modes, write them back.

    The app sends 0xE00A (echoing 0xE009) before every 0xE002 and the panel
    acks with 0xE00B. Whether the write needs it is unknown; the verified
    writes all had it, so mirror the sequence. Returns True if the panel
    acked, False if any step went unanswered (the write is still attempted).
    """
    src = _program_source(app)
    modes = await _program_exchange(
        app, build_keymode_read_frame(panel, **src), KEYMODE_READ_RESPONSE,
        panel=panel,
    )
    if modes is None:
        _LOGGER.info("write: %s did not answer 0xE008 key-mode read", panel)
        return False
    ack = await _program_exchange(
        app,
        build_keymode_write_frame(bytes(modes["modes"]), panel, **src),
        KEYMODE_WRITE_RESPONSE,
        panel=panel,
    )
    if ack is None:
        _LOGGER.info("write: %s did not ack 0xE00A key-mode write", panel)
    return ack is not None


async def _program_snapshot(
    app: web.Application, panel: DeviceAddress, buttons: int
) -> dict[int, dict] | None:
    """Read every key's label and first function entry straight from the panel.

    Returns {index: {"label": str | None, "commands": [...]}} or None when
    the panel doesn't speak the programming protocol (no answer at all for
    the first keys) — the flash backup is the only source then.
    """
    snapshot: dict[int, dict] = {}
    silent = 0
    for index in range(1, buttons + 1):
        entry = await _program_read(app, panel, index, timeout=1.0, retries=2)
        label = await _program_read_label(
            app, panel, index, timeout=1.0, retries=1
        )
        if entry is None and label is None:
            silent += 1
            if index <= 2 and silent == index:
                # Two keys with nothing back: not a supported panel / offline.
                return None
            continue
        commands = []
        if entry and entry.get("function", 0) not in (0x00, 0xFF):
            sub, dev = (int(x) for x in entry["target"].split("."))
            commands.append(
                ButtonCommand(
                    function=entry["function"], subnet=sub, device=dev,
                    p1=entry["p1"], p2=entry["p2"], p3=entry["p3"],
                ).as_dict()
            )
        snapshot[index] = {"label": label, "commands": commands}
    return snapshot


async def _program_write_button(
    app: web.Application,
    panel: DeviceAddress,
    button: int,
    commands: list["ButtonCommand"],
) -> dict:
    """Write every function entry of one key, capture-free, verifying each.

    Each command becomes one (button, page) entry via opcode 0xE002; the entry
    is read back (0xE000/0xE001) and compared. Returns a per-page report.
    """
    src = _program_source(app)
    handshake = await _program_prepare_write(app, panel)
    pages = []
    # Pages are 1-based on the wire (every Smart Cloud frame says so); page 1
    # is the only entry ever verified live, so anything beyond it is a
    # best-effort extension that the read-back will either confirm or not.
    for page, cmd in enumerate(commands, start=FIRST_PAGE):
        fn = ButtonFunction(
            button=button,
            page=page,
            function=cmd.function,
            target=DeviceAddress(cmd.subnet, cmd.device),
            p1=cmd.p1,
            p2=cmd.p2,
            p3=cmd.p3,
        )
        ack = await _program_exchange(
            app, build_write_frame(fn, panel, **src), WRITE_RESPONSE, button,
            panel=panel,
        )
        await asyncio.sleep(0.4)
        back = await _program_read(app, panel, button, page)
        verified = bool(
            back
            and back.get("target") == f"{cmd.subnet}.{cmd.device}"
            and back.get("p1") == cmd.p1
            and back.get("p2") == cmd.p2
        )
        pages.append(
            {"page": page, "acked": bool(ack), "verified": verified}
        )
        _LOGGER.info(
            "write: %s button %d page %d via capture-free protocol — "
            "ack=%s verified=%s",
            panel, button, page, bool(ack), verified,
        )
    return {
        "written": bool(pages),
        "verified": all(p["verified"] for p in pages) and bool(pages),
        "handshake": handshake,
        "pages": pages,
    }


async def _vendor_addresses_panel(
    app: web.Application, address: str, decoded: dict
) -> tuple[bool, str]:
    """Confirm the learned template talks to THIS panel.

    A template carries its target inside the obfuscated header, so the
    only safe check is empirical: read buttons back and compare them with
    the panel's own decoded configuration. Refusing on a mismatch is what
    stops a write landing on the wrong panel.
    """
    store: TemplateStore = app["vendor"]
    if not store.can_read:
        return False, "no vendor read template learned yet"
    matched = compared = 0
    for button in decoded["buttons"]:
        if not button["commands"]:
            continue
        live = await _vendor_exchange(
            app,
            store.read_frame(button["index"], 1, app["local_ip"]),
            READ_RESP,
            button["index"],
        )
        if live is None:
            continue
        compared += 1
        first = button["commands"][0]
        if (
            live.get("target") == first["target"]
            and live.get("p1") == first["p1"]
        ):
            matched += 1
        if compared >= 4:
            break
    if compared == 0:
        return False, "the panel did not answer vendor-protocol reads"
    if matched < compared:
        return False, (
            f"the learned template addresses a different panel "
            f"({matched}/{compared} buttons matched {address})"
        )
    return True, f"verified against {matched} button(s)"


async def api_vendor_status(request: web.Request) -> web.Response:
    store: TemplateStore = request.app["vendor"]
    return web.json_response(
        {
            # Programming no longer needs a captured template: the header
            # cipher is known, so frames are built from scratch for any panel.
            "capture_free": True,
            "can_read": True,
            "can_write": True,
            "template_can_read": store.can_read,
            "template_can_write": store.can_write,
            "operations": sorted(store.templates),
        }
    )


async def api_program_read(request: web.Request) -> web.Response:
    """Read one key's current function config straight from the panel.

    Query: target=<subnet.device>, button=<n>, page=<n, default 1>.
    Capture-free — no backup or template required.
    """
    app = request.app
    panel = DeviceAddress.parse(request.query["target"])
    button = int(request.query["button"])
    page = int(request.query.get("page", str(FIRST_PAGE)))
    result = await _program_read(app, panel, button, page)
    if result is None:
        return web.json_response(
            {"ok": False, "error": "the panel did not answer (offline, "
             "password-protected, or unsupported firmware)"},
            status=504,
        )
    return web.json_response({"ok": True, **result})


async def api_panel_buttons(request: web.Request) -> web.Response:
    """A panel's buttons: read live from the panel, backup as fill-in.

    Live (0xE000/0xE004 per key) is the truth — it is what the panel will
    do when pressed. The flash backup, if any, supplies buttons the panel
    didn't answer and the 2nd+ commands of multi-command buttons (live
    reads cover the first function entry only).
    """
    app = request.app
    target = request.query["target"]
    panel = DeviceAddress.parse(target)
    dtype = _known_device_type(app, target)
    path = BACKUP_DIR / f"{target}.sbd"

    decoded: dict | None = None
    if path.is_file():
        backup = DeviceBackup.from_sbd(path.read_text(encoding="utf-8"))
        try:
            decoded = decode_panel(backup, dtype)
        except ValueError as err:
            _LOGGER.warning("%s: backup does not decode — %s", target, err)

    layout = LAYOUTS.get(dtype) if dtype is not None else None
    buttons = layout.buttons if layout else (
        len(decoded["buttons"]) if decoded else 0
    )
    if not buttons:
        return web.json_response(
            {"ok": False, "error": "no backup and no known button layout for "
             "this panel type — run a flash backup first"},
            status=404,
        )

    live = await _program_snapshot(app, panel, buttons)
    if live is None and decoded is None:
        return web.json_response(
            {"ok": False, "error": "the panel did not answer live reads and "
             "there is no backup to fall back on"},
            status=504,
        )

    by_index = {b["index"]: b for b in (decoded or {}).get("buttons", [])}
    merged = []
    for index in range(1, buttons + 1):
        stored = by_index.get(index, {"index": index, "label": "", "commands": []})
        entry = (live or {}).get(index)
        if entry is None:
            merged.append({**stored, "live": False})
            continue
        commands = entry["commands"]
        # Keep a backup's extra commands only when the live first entry
        # agrees with the backup's first record — otherwise the backup is stale.
        stored_cmds = stored.get("commands", [])
        if commands and stored_cmds and commands[0] == stored_cmds[0]:
            commands = commands + stored_cmds[1:]
        label = entry["label"] if entry["label"] is not None else stored.get("label", "")
        merged.append({"index": index, "label": label, "commands": commands, "live": True})

    return web.json_response(
        {
            "ok": True,
            "name": (decoded or {}).get("name", ""),
            "device_type": f"0x{dtype:04X}" if dtype is not None else (decoded or {}).get("device_type"),
            "buttons": merged,
            "source": "live+backup" if (live and decoded) else "live" if live else "backup",
            "backup_file": path.name if decoded else None,
        }
    )


async def api_panel_write(request: web.Request) -> web.Response:
    """Write one button's config back to a DDP panel.

    Body: {target, index, label, commands:[{target, p1, p2, p3}], confirm}.
    Without `confirm` this is a dry run returning the pages that would
    change. A real write additionally requires the `enable_flash_write`
    add-on option, stages the changed pages (0xDC15), commits (0xDC16),
    then re-reads every written page to verify.
    """
    app = request.app
    bus: SmartG4Bus = app["bus"]
    body = await request.json()
    target = DeviceAddress.parse(body["target"])
    path = BACKUP_DIR / f"{target}.sbd"
    # The capture-free path needs no backup; the flash fallback does.
    backup = (
        DeviceBackup.from_sbd(path.read_text(encoding="utf-8"))
        if path.is_file()
        else None
    )
    commands = [
        ButtonCommand(
            function=int(str(c.get("function", "0x59")), 0),
            subnet=DeviceAddress.parse(c["target"]).subnet,
            device=DeviceAddress.parse(c["target"]).device,
            p1=int(c["p1"]),
            p2=int(c["p2"]),
            p3=int(c.get("p3", 0)),
        )
        for c in body["commands"]
    ]
    dtype = _known_device_type(request.app, str(target))
    changed = []
    if backup is not None:
        try:
            changed = apply_button(
                backup, int(body["index"]), body.get("label"), commands, dtype
            )
        except ValueError as err:
            return web.json_response({"ok": False, "error": str(err)}, status=422)
    else:
        layout = LAYOUTS.get(dtype) if dtype is not None else None
        limit = layout.buttons if layout else 16
        if not 1 <= int(body["index"]) <= limit:
            return web.json_response(
                {"ok": False, "error": f"button index out of range (1-{limit})"},
                status=422,
            )

    _LOGGER.info(
        "write: %s button %s -> %d command(s), %d page(s) change%s",
        target, body["index"], len(commands), len(changed),
        "" if body.get("confirm") else " (dry run)",
    )
    result = {
        "ok": True,
        "changed_pages": [p.number for p in changed],
        "written": False,
        "verified": False,
    }

    # Preferred path: the vendor's own button-write operation, built from
    # scratch (no capture needed) now that the header cipher is known
    # (pysmartg4.vendor_program). Verifies by reading each entry back.
    if commands:
        if not body.get("confirm"):
            result["method"] = "capture-free"
            result["vendor"] = {"available": True, "capture_free": True}
            return web.json_response(result)
        report = await _program_write_button(
            app, target, int(body["index"]), commands
        )
        result.update(
            method="capture-free",
            written=report["written"],
            verified=report["verified"],
            pages=report["pages"],
        )
        if not report["verified"]:
            result["error"] = (
                "The panel did not confirm the change — it may be offline, "
                "protected by a programming password, or on a firmware whose "
                "button opcode differs. Re-read the panel and try again."
            )
        return web.json_response(result)

    # Fallback: a captured vendor template, if one was learned by watching
    # Smart Cloud. Only used once proven to address THIS panel.
    store: TemplateStore = app["vendor"]
    if store.can_write and backup is not None:
        decoded = decode_panel(backup, dtype)
        addressed, why = await _vendor_addresses_panel(app, str(target), decoded)
        result["vendor"] = {"available": True, "addresses_panel": addressed,
                            "detail": why}
        if not body.get("confirm"):
            return web.json_response(result)
        if not addressed:
            _LOGGER.warning("write: %s vendor template rejected — %s", target, why)
            return web.json_response(
                {"ok": False, "error": f"Refusing to write: {why}."}, status=409
            )
        index = int(body["index"])
        first = commands[0] if commands else None
        record = button_record(
            first.function if first else 0,
            first.subnet if first else 0,
            first.device if first else 0,
            first.p1 if first else 0,
            first.p2 if first else 0,
            first.p3 if first else 0,
        )
        ack = await _vendor_exchange(
            app,
            store.write_frame(index, 1, record, app["local_ip"]),
            WRITE_RESP,
            index,
        )
        await asyncio.sleep(0.4)
        after = await _vendor_exchange(
            app, store.read_frame(index, 1, app["local_ip"]), READ_RESP, index
        )
        ok = bool(
            after
            and first
            and after.get("target") == f"{first.subnet}.{first.device}"
            and after.get("p1") == first.p1
            and after.get("p2") == first.p2
        )
        _LOGGER.info(
            "write: %s button %d via vendor protocol — ack=%s verified=%s",
            target, index, bool(ack), ok,
        )
        result.update(written=True, verified=ok, method="vendor")
        if not ok:
            result["error"] = (
                "The panel acknowledged but the button did not change — "
                "re-read the panel and try again."
            )
        if len(commands) > 1:
            result["note"] = (
                f"only the first of {len(commands)} commands was written — "
                "multi-command buttons are not supported over this path yet"
            )
        return web.json_response(result)

    if not changed or not body.get("confirm"):
        return web.json_response(result)
    if not FLASH_WRITE_ENABLED:
        return web.json_response(
            {
                "ok": False,
                "error": "flash writing is disabled — set the "
                "enable_flash_write add-on option to allow it "
                "(the restore commit is still experimental)",
            },
            status=403,
        )
    for page in changed:
        _LOGGER.info("write: staging page %d (0xDC15)", page.number)
        stage_page(bus, target, page)
        await asyncio.sleep(0.1)
    try:
        await commit_restore(bus, target, len(changed))
    except (TimeoutError, asyncio.TimeoutError):
        _LOGGER.warning("write: %s no 0xDC17 restore ack", target)
        return web.json_response(
            {"ok": False, "error": "no 0xDC17 restore acknowledgement"},
            status=504,
        )
    result["written"] = True
    verified = True
    unchanged = 0
    for page in changed:
        try:
            reread = await read_page(bus, target, page.number)
            if reread.data != page.data:
                verified = False
                original = next(
                    (p for p in backup.pages if p.number == page.number), None
                )
                if original is not None and reread.data == original.data:
                    unchanged += 1
        except (TimeoutError, asyncio.TimeoutError):
            verified = False
    result["verified"] = verified
    if not verified:
        # Known state of play: the device acks the 0xDC16 restore but the
        # page never lands, so flash is left exactly as it was.
        result["unchanged_pages"] = unchanged
        _LOGGER.warning(
            "write: %s NOT applied — %d/%d pages unchanged after commit",
            target, unchanged, len(changed),
        )
        result["error"] = (
            "Flash writing is not supported yet: the panel acknowledged the "
            "restore but the page did not change"
            + (" — the panel is untouched." if unchanged == len(changed)
               else ". Verify the panel against its backup.")
        )
    if verified:
        # Keep the on-disk backup in sync with what the panel now holds.
        by_number = {p.number: p for p in changed}
        backup.pages = [by_number.get(p.number, p) for p in backup.pages]
        path.write_text(backup.to_sbd(), encoding="utf-8")
        _LOGGER.info("write: %s verified and backup updated", target)
    return web.json_response(result)


async def ws_monitor(request: web.Request) -> web.WebSocketResponse:
    """Stream every decoded bus telegram to the live console."""
    ws = web.WebSocketResponse()
    await ws.prepare(request)
    bus: SmartG4Bus = request.app["bus"]
    loop = asyncio.get_running_loop()

    def on_packet(packet: Packet, parsed: dict | None) -> None:
        payload = {
            "src": str(packet.source),
            "dst": str(packet.target),
            "op": opcode_name(packet.opcode),
            "opcode": f"0x{packet.opcode:04X}",
            "data": parsed if parsed is not None else packet.payload.hex(" "),
        }
        loop.call_soon_threadsafe(
            lambda: asyncio.ensure_future(ws.send_json(payload))
        )

    unsubscribe = bus.on_packet(on_packet)
    try:
        async for msg in ws:
            if msg.type in (WSMsgType.CLOSE, WSMsgType.ERROR):
                break
    finally:
        unsubscribe()
    return ws


async def on_startup(app: web.Application) -> None:
    bus = SmartG4Bus(
        gateway=GATEWAY, sender=DeviceAddress(SUBNET, DEVICE)
    )
    await bus.connect()
    app["bus"] = bus

    if _inventory_path().is_file():
        try:
            app["devices"][:] = json.loads(
                _inventory_path().read_text(encoding="utf-8")
            )
        except (OSError, ValueError):
            pass
    if _channel_names_path().is_file():
        try:
            raw = json.loads(_channel_names_path().read_text(encoding="utf-8"))
            cleaned = _sanitize_channel_cache(raw)
            app["channel_names"].update(cleaned)
            dropped = sum(
                1
                for a, names in raw.items()
                for i, n in enumerate(names if isinstance(names, list) else [])
                if n and not _sane_name(n)
            )
            if dropped:
                _LOGGER.info(
                    "channel names: dropped %d unreadable cached name(s)",
                    dropped,
                )
                _save_channel_names(app)
        except (OSError, ValueError):
            pass

    def register_passive(packet: Packet, _parsed: dict | None) -> None:
        """Any module heard on the bus joins the inventory."""
        if packet.source_type == 0xFFFE or packet.source == bus.sender:
            return
        entry = {
            "address": str(packet.source),
            "subnet": packet.source.subnet,
            "device": packet.source.device,
            "device_type": f"0x{packet.source_type:04X}",
            "type_name": device_type_name(packet.source_type),
            "mac": None,
            "remark": None,
            "opcodes_seen": [f"0x{packet.opcode:04X}"],
        }
        merged, new = merge_device_lists(app["devices"], [entry])
        app["devices"][:] = merged
        if new:
            _save_inventory(app)

    bus.on_packet(register_passive)

    app["local_ip"] = bus._local_ip  # noqa: SLF001 - needed for forged frames
    store: TemplateStore = app["vendor"]
    if _templates_path().is_file():
        try:
            store.load(json.loads(_templates_path().read_text(encoding="utf-8")))
            _LOGGER.info(
                "vendor templates loaded: %s", sorted(store.templates) or "none"
            )
        except (OSError, ValueError):
            pass

    def learn_vendor(data: bytes, _addr) -> None:
        """Learn the vendor's button-programming frames off the wire."""
        op = store.learn(data)
        if op:
            _LOGGER.info("vendor template learned: opcode %s", op)
            try:
                BACKUP_DIR.mkdir(parents=True, exist_ok=True)
                _templates_path().write_text(
                    json.dumps(store.as_dict(), indent=2), encoding="utf-8"
                )
            except OSError:
                pass

    bus.on_raw(learn_vendor)


async def on_cleanup(app: web.Application) -> None:
    app["bus"].close()


def build_app() -> web.Application:
    app = web.Application()
    app.router.add_get("/", index)
    app.router.add_get("/api/config", api_config)
    app.router.add_get("/api/inventory", api_inventory)
    app.router.add_get("/api/devices", api_devices)
    app.router.add_post("/api/send", api_send)
    app.router.add_get("/api/channels", api_channels)
    app.router.add_post("/api/rename", api_rename)
    app.router.add_post("/api/backup", api_backup_start)
    app.router.add_get("/api/backup/status", api_backup_status)
    app.router.add_get("/api/backups", api_backups)
    app.router.add_get("/api/panel/buttons", api_panel_buttons)
    app.router.add_post("/api/panel/write", api_panel_write)
    app.router.add_get("/api/vendor/status", api_vendor_status)
    app.router.add_get("/api/panel/read", api_program_read)
    app.router.add_get("/api/monitor", ws_monitor)
    app["devices"] = []
    app["channel_names"] = {}
    app["vendor"] = TemplateStore()
    app["local_ip"] = b"\x00\x00\x00\x00"
    app["backup_job"] = {
        "task": None, "target": None, "done": 0, "total": 0,
        "file": None, "error": None,
    }
    app.router.add_static("/www/", APP_DIR / "www")
    app.on_startup.append(on_startup)
    app.on_cleanup.append(on_cleanup)
    return app


if __name__ == "__main__":
    web.run_app(build_app(), host="0.0.0.0", port=PORT)
