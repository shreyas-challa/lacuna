import asyncio
from pathlib import Path

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from backend.ws_manager import WSManager
from backend.agent import Agent

app = FastAPI(title="Lacuna")
manager = WSManager()

FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"


@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await manager.connect(ws)
    try:
        # Wait for the start command with target info
        data = await ws.receive_json()
        target = data.get("target", "")
        if not target:
            await ws.send_json({"type": "error", "data": {"message": "No target provided"}})
            return

        agent = Agent(target=target, manager=manager)
        await agent.run()
    except WebSocketDisconnect:
        pass
    finally:
        manager.disconnect(ws)


# Serve frontend static files
app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")


@app.get("/")
async def index():
    return FileResponse(FRONTEND_DIR / "index.html")
