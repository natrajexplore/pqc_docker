"""The Host/Origin guard: what a browser on another site can and cannot do."""
import logging

import pytest
from fastapi import FastAPI, WebSocket
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from app.middleware import GuardAndLog

app = FastAPI()
app.add_middleware(GuardAndLog, allowed_hosts={"127.0.0.1", "localhost"})


@app.post("/api/thing")
async def thing() -> dict:
    logging.getLogger("pqcw.test").info("handled")
    return {"ok": True}


@app.websocket("/ws/x")
async def ws(sock: WebSocket) -> None:
    await sock.accept()
    await sock.send_json({"hi": 1})
    await sock.close()


@pytest.fixture
def client():
    return TestClient(app, base_url="http://127.0.0.1:8080")


def test_same_origin_and_originless_requests_pass(client):
    assert client.post("/api/thing").status_code == 200
    assert client.post("/api/thing", headers={"origin": "http://127.0.0.1:8080"}).status_code == 200


def test_cross_site_post_is_rejected(client):
    r = client.post("/api/thing", headers={"origin": "https://evil.example"})
    assert r.status_code == 403
    assert client.post("/api/thing", headers={"origin": "null"}).status_code == 403
    # same host, different port is a different origin
    assert client.post("/api/thing", headers={"origin": "http://127.0.0.1:3000"}).status_code == 403


def test_dns_rebinding_host_is_rejected(client):
    r = client.post("/api/thing", headers={"host": "rebind.evil.example:8080"})
    assert r.status_code == 403


def test_cross_site_websocket_is_rejected(client):
    host = {"host": "127.0.0.1:8080"}  # TestClient sends Host: testserver for websockets
    with client.websocket_connect("/ws/x", headers=host) as s:
        assert s.receive_json() == {"hi": 1}
    with pytest.raises(WebSocketDisconnect) as exc:
        with client.websocket_connect("/ws/x", headers={**host, "origin": "https://evil.example"}) as s:
            s.receive_json()
    assert exc.value.code == 4403


def test_request_id_is_propagated_and_sanitized(client):
    r = client.post("/api/thing", headers={"x-request-id": "abc123"})
    assert r.headers["x-request-id"] == "abc123"
    r = client.post("/api/thing", headers={"x-request-id": "bad id\nforged log line"})
    assert r.headers["x-request-id"] != "bad id\nforged log line"
    assert len(r.headers["x-request-id"]) == 16
