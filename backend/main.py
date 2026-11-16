from __future__ import annotations

import asyncio
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

ROOT = Path(__file__).resolve().parents[1]
FRONTEND = ROOT / "frontend"
DB_PATH = os.getenv("NETEYE_DB", str(ROOT / "data" / "neteye.db"))
MAX_PCAP_BYTES = int(os.getenv("NETEYE_MAX_PCAP_MB", "512")) * 1024 * 1024
FLUSH_INTERVAL_S = 5

store = Store(DB_PATH)
engine = Engine(store)
# Fresh database: optionally bound the initial learning window (0 = switch to detection manually).
LEARNING_HOURS = float(os.getenv("NETEYE_LEARNING_HOURS", "0"))
if LEARNING_HOURS > 0 and engine.baseline.meta_dirty:
    engine.set_mode("learning", LEARNING_HOURS)
sensor_state: dict = {"enabled": False, "interface": None, "error": None}
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
    return {**engine.snapshot(), "sensor": dict(sensor_state), "import": dict(import_state)}


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
