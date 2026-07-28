"""Smart-G4 Builder — Home Assistant ingress add-on backend.

Serves the single-page UI (www/app.html, wrapped in an HTML skeleton) and a
small JSON + WebSocket API backed by pysmartg4. Runs behind HA ingress, so the
frontend uses only relative URLs and inherits the ingress base path.
"""

from __future__ import annotations

import asyncio
import json
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
from pysmartg4.ddp import ButtonCommand, apply_button, decode_panel
from pysmartg4.device_types import device_type_name
from pysmartg4.discovery import discover, merge_device_lists
from pysmartg4.packet import BROADCAST, DeviceAddress, Packet

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


def _save_inventory(app: web.Application) -> None:
    try:
        BACKUP_DIR.mkdir(parents=True, exist_ok=True)
        _inventory_path().write_text(
            json.dumps(app["devices"], indent=2), encoding="utf-8"
        )
    except OSError:
        pass  # persistence is best-effort


async def api_devices(request: web.Request) -> web.Response:
    """Scan and return the ACCUMULATED inventory, not just this scan.

    Broadcast scan replies are lossy (RS-485 collisions), so any single
    scan misses modules; the inventory merges every scan and all passive
    traffic, and persists across restarts.
    """
    app = request.app
    bus: SmartG4Bus = app["bus"]
    duration = float(request.query.get("duration", 45.0))
    found = await discover(bus, duration=min(duration, 120.0))
    merged, _new = merge_device_lists(
        app["devices"], [d.as_dict() for d in found]
    )
    app["devices"] = merged
    _save_inventory(app)
    return web.json_response(merged)


async def api_send(request: web.Request) -> web.Response:
    """Generic command passthrough: {target, opcode, data|payload}."""
    bus: SmartG4Bus = request.app["bus"]
    body = await request.json()
    target = DeviceAddress.parse(body["target"])
    opcode = int(body["opcode"])
    try:
        if "data" in body:
            bus.send(target, opcode, body["data"])
        else:
            bus.send(target, opcode, payload=bytes(body.get("payload", [])))
        return web.json_response({"ok": True})
    except Exception as err:  # noqa: BLE001 - report to UI
        return web.json_response({"ok": False, "error": str(err)}, status=400)


async def api_rename(request: web.Request) -> web.Response:
    """Write a device's remark (0x0010) and confirm via its 0x0011 ack."""
    bus: SmartG4Bus = request.app["bus"]
    body = await request.json()
    target = DeviceAddress.parse(body["target"])
    remark = str(body["remark"])[:20]
    try:
        await bus.request(target, 0x0010, {"remark": remark})
        return web.json_response({"ok": True})
    except (TimeoutError, asyncio.TimeoutError):
        return web.json_response(
            {"ok": False, "error": "no acknowledgement from device"}, status=504
        )


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

    async def run() -> None:
        def progress(done: int, _total: int) -> None:
            job["done"] = done

        try:
            backup = await backup_device(bus, target, progress=progress)
            BACKUP_DIR.mkdir(parents=True, exist_ok=True)
            path = BACKUP_DIR / f"{target}.sbd"
            path.write_text(backup.to_sbd(), encoding="utf-8")
            job["file"] = path.name
        except Exception as err:  # noqa: BLE001 - reported via status endpoint
            job["error"] = str(err)

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


async def api_panel_buttons(request: web.Request) -> web.Response:
    """Decode a DDP panel's buttons from its saved .sbd backup."""
    target = request.query["target"]
    path = BACKUP_DIR / f"{target}.sbd"
    if not path.is_file():
        return web.json_response(
            {"ok": False, "error": "no backup yet — run a flash backup first"},
            status=404,
        )
    try:
        backup = DeviceBackup.from_sbd(path.read_text(encoding="utf-8"))
        panel = decode_panel(backup)
    except ValueError as err:
        return web.json_response({"ok": False, "error": str(err)}, status=422)
    panel["ok"] = True
    panel["backup_file"] = path.name
    return web.json_response(panel)


async def api_panel_write(request: web.Request) -> web.Response:
    """Write one button's config back to a DDP panel.

    Body: {target, index, label, commands:[{target, p1, p2, p3}], confirm}.
    Without `confirm` this is a dry run returning the pages that would
    change. A real write additionally requires the `enable_flash_write`
    add-on option, stages the changed pages (0xDC15), commits (0xDC16),
    then re-reads every written page to verify.
    """
    bus: SmartG4Bus = request.app["bus"]
    body = await request.json()
    target = DeviceAddress.parse(body["target"])
    path = BACKUP_DIR / f"{target}.sbd"
    if not path.is_file():
        return web.json_response(
            {"ok": False, "error": "no backup — run a flash backup first"},
            status=404,
        )
    backup = DeviceBackup.from_sbd(path.read_text(encoding="utf-8"))
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
    try:
        changed = apply_button(
            backup, int(body["index"]), body.get("label"), commands
        )
    except ValueError as err:
        return web.json_response({"ok": False, "error": str(err)}, status=422)

    result = {
        "ok": True,
        "changed_pages": [p.number for p in changed],
        "written": False,
        "verified": False,
    }
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
        stage_page(bus, target, page)
        await asyncio.sleep(0.1)
    try:
        await commit_restore(bus, target, len(changed))
    except (TimeoutError, asyncio.TimeoutError):
        return web.json_response(
            {"ok": False, "error": "no 0xDC17 restore acknowledgement"},
            status=504,
        )
    result["written"] = True
    verified = True
    for page in changed:
        try:
            reread = await read_page(bus, target, page.number)
            if reread.data != page.data:
                verified = False
        except (TimeoutError, asyncio.TimeoutError):
            verified = False
    result["verified"] = verified
    if verified:
        # Keep the on-disk backup in sync with what the panel now holds.
        by_number = {p.number: p for p in changed}
        backup.pages = [by_number.get(p.number, p) for p in backup.pages]
        path.write_text(backup.to_sbd(), encoding="utf-8")
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

    app["devices"] = []
    if _inventory_path().is_file():
        try:
            app["devices"] = json.loads(
                _inventory_path().read_text(encoding="utf-8")
            )
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
        app["devices"] = merged
        if new:
            _save_inventory(app)

    bus.on_packet(register_passive)


async def on_cleanup(app: web.Application) -> None:
    app["bus"].close()


def build_app() -> web.Application:
    app = web.Application()
    app.router.add_get("/", index)
    app.router.add_get("/api/config", api_config)
    app.router.add_get("/api/devices", api_devices)
    app.router.add_post("/api/send", api_send)
    app.router.add_post("/api/rename", api_rename)
    app.router.add_post("/api/backup", api_backup_start)
    app.router.add_get("/api/backup/status", api_backup_status)
    app.router.add_get("/api/backups", api_backups)
    app.router.add_get("/api/panel/buttons", api_panel_buttons)
    app.router.add_post("/api/panel/write", api_panel_write)
    app.router.add_get("/api/monitor", ws_monitor)
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
