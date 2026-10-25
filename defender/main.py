import asyncio
import os
import threading
import time
from pathlib import Path

import boto3
from botocore.config import Config
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from log_tailer import start_tailer_thread
from rules import run_event_rules, run_poll_rules
from state import RequestEvent, state

# Automatically load .env if present
env_file = Path(__file__).resolve().parent.parent / ".env"
if env_file.exists():
    with open(env_file, "r") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip())

LOCALSTACK_ENDPOINT = os.environ.get("LOCALSTACK_ENDPOINT", "http://localhost:4566")
CONTAINER_NAME = os.environ.get("LOCALSTACK_CONTAINER", "localstack")
POLL_INTERVAL_SECONDS = int(os.environ.get("POLL_INTERVAL_SECONDS", "3"))

app = FastAPI()

DASHBOARD_DIR = Path(__file__).resolve().parent.parent / "dashboard"


class ConnectionManager:
    def __init__(self):
        self.active: list[WebSocket] = []
        self.lock = threading.Lock()

    async def connect(self, ws: WebSocket):
        await ws.accept()
        with self.lock:
            self.active.append(ws)

    def disconnect(self, ws: WebSocket):
        with self.lock:
            if ws in self.active:
                self.active.remove(ws)

    async def broadcast(self, message: dict):
        dead = []
        with self.lock:
            conns = list(self.active)
        for ws in conns:
            try:
                await ws.send_json(message)
            except Exception:
                dead.append(ws)
        if dead:
            with self.lock:
                for ws in dead:
                    if ws in self.active:
                        self.active.remove(ws)


manager = ConnectionManager()
main_loop: asyncio.AbstractEventLoop | None = None


def broadcast_threadsafe(message: dict):
    if main_loop is None:
        return
    asyncio.run_coroutine_threadsafe(manager.broadcast(message), main_loop)


def on_log_event(event: RequestEvent):
    window = state.add_event(event)
    broadcast_threadsafe({"kind": "event", **event.to_dict()})

    alerts = run_event_rules(event, window, state)
    for alert in alerts:
        state.add_alert(alert)
        broadcast_threadsafe(alert.to_dict())


def poll_bucket_config():
    """Periodically checks S3 bucket ACLs for public exposure."""
    s3 = boto3.client(
        "s3",
        endpoint_url=LOCALSTACK_ENDPOINT,
        aws_access_key_id="test",
        aws_secret_access_key="test",
        region_name="us-east-1",
        config=Config(retries={"max_attempts": 0}),
    )
    while True:
        try:
            public = set()
            buckets = s3.list_buckets().get("Buckets", [])
            for b in buckets:
                name = b["Name"]
                try:
                    acl = s3.get_bucket_acl(Bucket=name)
                    for grant in acl.get("Grants", []):
                        grantee = grant.get("Grantee", {})
                        uri = grantee.get("URI", "")
                        if "AllUsers" in uri:
                            public.add(name)
                except Exception:
                    pass
            state.set_public_buckets(public)
            for alert in run_poll_rules(state):
                state.add_alert(alert)
                broadcast_threadsafe(alert.to_dict())
        except Exception as e:
            print(f"[poller] error: {e}")
        time.sleep(POLL_INTERVAL_SECONDS)


@app.on_event("startup")
async def startup():
    global main_loop
    main_loop = asyncio.get_event_loop()
    start_tailer_thread(CONTAINER_NAME, on_log_event)
    threading.Thread(target=poll_bucket_config, daemon=True).start()


class CanaryRegistration(BaseModel):
    access_key_id: str


@app.post("/register-canary")
async def register_canary(payload: CanaryRegistration):
    state.register_canary(payload.access_key_id)
    return {"status": "ok", "registered": payload.access_key_id}


@app.get("/history")
async def history():
    return [a.to_dict() for a in state.get_history()]


@app.post("/reset")
async def reset():
    state.reset()
    return {"status": "reset"}


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)


app.mount("/", StaticFiles(directory=str(DASHBOARD_DIR), html=True), name="dashboard")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
