from __future__ import annotations

import pytest
from rmap import RMAPError

from server import create_app


RMAP_ENVIRONMENT_NAMES = (
    "RMAP_SERVER_PUBLIC_KEY_PATH",
    "RMAP_SERVER_PRIVATE_KEY_PATH",
    "RMAP_PRIVATE_KEY_PASSPHRASE",
    "RMAP_IDENTITIES_DIR",
    "RMAP_DOCUMENT_ID",
    "RMAP_LINK_PREFIX",
    "RMAP_WATERMARK_METHOD",
    "RMAP_WATERMARK_POSITION",
    "WATERMARK_HMAC_KEY",
)


@pytest.fixture()
def app(monkeypatch: pytest.MonkeyPatch):
    for name in RMAP_ENVIRONMENT_NAMES:
        monkeypatch.delenv(name, raising=False)

    test_app = create_app()
    test_app.config.update(TESTING=True)
    return test_app


@pytest.fixture()
def client(app):
    return app.test_client()


def test_rmap_initiate_rejects_non_json(client):
    response = client.post(
        "/api/rmap-initiate",
        data="not-json",
        content_type="text/plain",
    )

    assert response.status_code == 400
    assert response.get_json() == {
        "error": "JSON request body required"
    }


def test_rmap_initiate_rejects_non_object_json(client):
    response = client.post(
        "/api/rmap-initiate",
        json=["not", "an", "object"],
    )

    assert response.status_code == 400
    assert response.get_json() == {
        "error": "RMAP message must be a JSON object"
    }


def test_rmap_initiate_returns_503_when_unconfigured(client):
    response = client.post(
        "/api/rmap-initiate",
        json={"payload": "encrypted-msg1"},
    )

    body = response.get_json()

    assert response.status_code == 503
    assert body == {"error": "RMAP service unavailable"}

    response_text = response.get_data(as_text=True)
    assert "RMAP_SERVER_PRIVATE_KEY_PATH" not in response_text
    assert "WATERMARK_HMAC_KEY" not in response_text


def test_rmap_initiate_returns_encrypted_response(app, client):
    class FakeRMAPServer:
        def __init__(self):
            self.received_message = None

        def receiveMsg1(self, msg1):
            self.received_message = msg1
            return "Group_01", {"payload": "encrypted-resp1"}

    fake_server = FakeRMAPServer()
    app.extensions["rmap_server"] = fake_server

    response = client.post(
        "/api/rmap-initiate",
        json={"payload": "encrypted-msg1"},
    )

    assert response.status_code == 200
    assert response.get_json() == {
        "payload": "encrypted-resp1"
    }
    assert fake_server.received_message == {
        "payload": "encrypted-msg1"
    }

    # The unencrypted identity must not be exposed by the API.
    assert "Group_01" not in response.get_data(as_text=True)


def test_rmap_initiate_hides_authentication_details(app, client):
    class RejectingRMAPServer:
        def receiveMsg1(self, msg1):
            raise RMAPError("Unknown identity: SecretGroup")

    app.extensions["rmap_server"] = RejectingRMAPServer()

    response = client.post(
        "/api/rmap-initiate",
        json={"payload": "invalid-encrypted-message"},
    )

    assert response.status_code == 400
    assert response.get_json() == {
        "error": "RMAP authentication failed"
    }
    assert "SecretGroup" not in response.get_data(as_text=True)