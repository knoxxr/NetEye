from __future__ import annotations

import asyncio
import json
import os
import tempfile
import threading
from urllib.parse import unquote
from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncIterator

from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from backend.capture import import_pcap, start_capture
from backend.engine import Engine
from backend.storage import Store
from backend.vulns import VulnDB

ROOT = Path(__file__).resolve().parents[1]
FRONTEND = ROOT / "frontend"
DB_PATH = os.getenv("NETEYE_DB", str(ROOT / "data" / "neteye.db"))
MAX_PCAP_BYTES = int(os.getenv("NETEYE_MAX_PCAP_MB", "512")) * 1024 * 1024
VULNDB_PATH = Path(os.getenv("NETEYE_VULNDB", str(ROOT / "data" / "vulndb.json")))
MAX_VULNDB_BYTES = 128 * 1024 * 1024
FLUSH_INTERVAL_S = 5

store = Store(DB_PATH)
engine = Engine(store)
# Fresh database: optionally bound the initial learning window (0 = switch to detection manually).
LEARNING_HOURS = float(os.getenv("NETEYE_LEARNING_HOURS", "0"))
if LEARNING_HOURS > 0 and engine.baseline.meta_dirty:
    engine.set_mode("learning", LEARNING_HOURS)
sensor_state: dict = {"enabled": False, "interface": None, "error": None}
vulndb_state: dict = {"path": str(VULNDB_PATH), "error": None}
if VULNDB_PATH.exists():
    try:
        engine.set_vulndb(VulnDB.load(VULNDB_PATH))
    except (OSError, ValueError, KeyError) as error:
        vulndb_state["error"] = f"{VULNDB_PATH.name}: {error}"
import_state: dict = {"running": False, "file": None, "frames": 0, "error": None, "last_result": None}
_import_lock = threading.Lock()


async def _flush_loop() -> None:
    while True:
        await asyncio.sleep(FLUSH_INTERVAL_S)
        await asyncio.to_thread(engine.flush)


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    interface = os.getenv("NETEYE_INTERFACE", "").strip()
    sensor_state["interface"] = interface or None
    sniffer = None
    if interface:
        try:
            sniffer = start_capture(interface, engine)
            sensor_state["enabled"] = True
        except Exception as error:  # scapy raises many types for missing interfaces / privileges
            sensor_state["error"] = str(error)
    flusher = asyncio.create_task(_flush_loop())
    yield
    flusher.cancel()
    if sniffer is not None:
        sniffer.stop()
    engine.flush()
    store.close()


app = FastAPI(title="NetEye OT Security Monitor", lifespan=lifespan)
app.mount("/assets", StaticFiles(directory=FRONTEND), name="assets")


def _payload() -> dict:
    return {**engine.snapshot(), "sensor": dict(sensor_state), "import": dict(import_state),
            "vulndb_state": dict(vulndb_state)}


@app.get("/")
async def index() -> FileResponse:
    return FileResponse(FRONTEND / "index.html")


@app.get("/api/snapshot")
async def get_snapshot() -> dict:
    return _payload()


@app.get("/api/alerts")
async def get_alerts(status: str | None = None) -> list[dict]:
    alerts = engine.snapshot()["alerts"]
    return [a for a in alerts if status is None or a["status"] == status]


@app.post("/api/alerts/{alert_id}/ack")
async def acknowledge(alert_id: int) -> dict:
    if not engine.acknowledge(alert_id):
        raise HTTPException(404, "alert not found")
    return {"ok": True}


@app.post("/api/alerts/{alert_id}/learn")
async def learn(alert_id: int) -> dict:
    """Accept the behaviour behind a baseline alert as normal (adds it to the baseline)."""
    if not engine.learn_alert(alert_id):
        raise HTTPException(404, "alert not found")
    return {"ok": True}


class ModeRequest(BaseModel):
    mode: str = Field(pattern="^(learning|detecting)$")
    hours: float | None = Field(default=None, gt=0, le=24 * 90)
    reset: bool = False


@app.get("/api/baseline")
async def get_baseline() -> dict:
    return engine.snapshot()["baseline"]


@app.post("/api/baseline/mode")
async def set_mode(request: ModeRequest) -> dict:
    status = engine.set_mode(request.mode, request.hours, request.reset)
    await asyncio.to_thread(engine.flush)
    return status


@app.get("/api/vulns")
async def list_vulns() -> list[dict]:
    """Flattened asset x advisory list, highest risk first."""
    rows = []
    for asset in engine.snapshot()["assets"]:
        for vuln in asset["vulns"]:
            rows.append({"asset": asset["id"], "label": asset["label"], "vendor": asset["vendor"],
                         "model": asset["model"], "firmware": asset["firmware"], **vuln})
    return sorted(rows, key=lambda r: (-r["score"], r["label"]))


@app.get("/api/vulndb")
async def vulndb_info() -> dict:
    return {"loaded": engine.vulndb is not None, **(engine.vulndb.info() if engine.vulndb else {}),
            **vulndb_state}


@app.post("/api/vulndb")
async def upload_vulndb(request: Request) -> dict:
    """Replace the vulnerability database (body: vulndb.json built by backend.vulndb_build)."""
    body = bytearray()
    async for chunk in request.stream():
        body += chunk
        if len(body) > MAX_VULNDB_BYTES:
            raise HTTPException(413, "vulnerability database too large")
    try:
        db = await asyncio.to_thread(lambda: VulnDB(json.loads(bytes(body))))
    except (ValueError, KeyError, TypeError) as error:
        raise HTTPException(400, f"invalid vulnerability database: {error}") from error
    VULNDB_PATH.parent.mkdir(parents=True, exist_ok=True)
    temp = VULNDB_PATH.with_suffix(".tmp")
    temp.write_bytes(bytes(body))
    temp.replace(VULNDB_PATH)
    await asyncio.to_thread(engine.set_vulndb, db)
    vulndb_state["error"] = None
    return {"ok": True, **db.info()}


def _run_import(path: Path, name: str) -> None:
    try:
        result = import_pcap(path, engine, lambda n: import_state.update(frames=n))
        import_state.update(last_result={"file": name, **result})
    except Exception as error:  # report malformed captures to the UI instead of crashing
        import_state["error"] = f"{name}: {error}"
    finally:
        import_state.update(running=False, file=None)
        path.unlink(missing_ok=True)
        _import_lock.release()


@app.post("/api/pcap")
async def upload_pcap(request: Request) -> dict:
    """Upload a pcap/pcapng as the raw request body (Content-Type: application/octet-stream)."""
    if not _import_lock.acquire(blocking=False):
        raise HTTPException(409, "another import is running")
    name = Path(unquote(request.headers.get("x-filename", "upload.pcap"))).name
    try:
        handle = tempfile.NamedTemporaryFile(prefix="neteye-", suffix=".pcap", delete=False)
    except OSError:
        _import_lock.release()
        raise
    try:
        size = 0
        with handle:
            async for chunk in request.stream():
                size += len(chunk)
                if size > MAX_PCAP_BYTES:
                    raise HTTPException(413, "capture file too large")
                handle.write(chunk)
    except BaseException:
        Path(handle.name).unlink(missing_ok=True)
        _import_lock.release()
        raise
    import_state.update(running=True, file=name, frames=0, error=None)
    threading.Thread(target=_run_import, args=(Path(handle.name), name), daemon=True).start()
    return {"accepted": True, "bytes": size}


@app.websocket("/ws")
async def stream_snapshot(websocket: WebSocket) -> None:
    await websocket.accept()
    try:
        while True:
            await websocket.send_json(_payload())
            await asyncio.sleep(1)
    except WebSocketDisconnect:
        return
