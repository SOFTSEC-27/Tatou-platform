import pytest
from rmap import RMAPError
from sqlalchemy import create_engine, text

import server as server_module
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
    monkeypatch.setenv(
        "SECRET_KEY",
        "tatou-rmap-test-only-secret-never-use-in-production",
    )

    for name in RMAP_ENVIRONMENT_NAMES:
        monkeypatch.delenv(name, raising=False)

    test_app = create_app()
    test_app.config.update(TESTING=True)
    return test_app


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def prepared_rmap(app, monkeypatch, tmp_path):
    source_pdf = tmp_path / "source.pdf"
    source_pdf.write_bytes(b"%PDF-test-source")

    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        future=True,
    )

    with engine.begin() as conn:
        conn.execute(
            text("""
                CREATE TABLE Documents (
                    id INTEGER PRIMARY KEY,
                    path TEXT NOT NULL
                )
            """)
        )
        conn.execute(
            text("""
                CREATE TABLE Versions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    documentid INTEGER NOT NULL,
                    link TEXT NOT NULL,
                    intended_for TEXT,
                    secret TEXT,
                    method TEXT,
                    position TEXT,
                    path TEXT NOT NULL
                )
            """)
        )
        conn.execute(
            text("""
                INSERT INTO Documents (id, path)
                VALUES (:id, :path)
            """),
            {
                "id": 1,
                "path": str(source_pdf),
            },
        )

    expected_link = "a" * 32

    class FakeRMAPServer:
        def __init__(self):
            self.received_message = None

        def receiveMsg2(self, msg2):
            self.received_message = msg2
            return (
                "Group_27",
                expected_link,
                {"payload": "encrypted-resp2"},
            )

    fake_server = FakeRMAPServer()

    app.config.update(
        {
            "_ENGINE": engine,
            "STORAGE_DIR": tmp_path,
            "RMAP_DOCUMENT_ID": "1",
            "RMAP_WATERMARK_METHOD": "layered-identity-v1",
            "RMAP_WATERMARK_POSITION": "center",
            "WATERMARK_HMAC_KEY": "test-hmac-key",
        }
    )
    app.extensions["rmap_server"] = fake_server

    monkeypatch.setattr(
        server_module.WMUtils,
        "is_watermarking_applicable",
        lambda **kwargs: True,
    )
    monkeypatch.setattr(
        server_module.WMUtils,
        "apply_watermark",
        lambda **kwargs: b"%PDF-watermarked-output",
    )

    yield {
        "engine": engine,
        "source_pdf": source_pdf,
        "expected_link": expected_link,
        "fake_server": fake_server,
    }

    engine.dispose()


def test_rmap_get_link_rejects_non_json(client):
    response = client.post(
        "/api/rmap-get-link",
        data="not-json",
        content_type="text/plain",
    )

    assert response.status_code == 400
    assert response.get_json() == {
        "error": "JSON request body required"
    }


def test_rmap_get_link_rejects_non_object_json(client):
    response = client.post(
        "/api/rmap-get-link",
        json=["not", "an", "object"],
    )

    assert response.status_code == 400
    assert response.get_json() == {
        "error": "RMAP message must be a JSON object"
    }


def test_rmap_get_link_returns_503_when_unconfigured(client):
    response = client.post(
        "/api/rmap-get-link",
        json={"payload": "encrypted-msg2"},
    )

    assert response.status_code == 503
    assert response.get_json() == {
        "error": "RMAP service unavailable"
    }


def test_rmap_get_link_hides_authentication_details(app, client):
    class RejectingRMAPServer:
        def receiveMsg2(self, msg2):
            raise RMAPError("Unknown identity: SecretGroup")

    app.extensions["rmap_server"] = RejectingRMAPServer()

    response = client.post(
        "/api/rmap-get-link",
        json={"payload": "invalid-encrypted-msg2"},
    )

    assert response.status_code == 400
    assert response.get_json() == {
        "error": "RMAP authentication failed"
    }
    assert "SecretGroup" not in response.get_data(as_text=True)


def test_rmap_get_link_creates_version(
    prepared_rmap,
    client,
):
    response = client.post(
        "/api/rmap-get-link",
        json={"payload": "encrypted-msg2"},
    )

    assert response.status_code == 200
    assert response.get_json() == {
        "payload": "encrypted-resp2"
    }

    assert prepared_rmap["fake_server"].received_message == {
        "payload": "encrypted-msg2"
    }

    destination_path = (
        prepared_rmap["source_pdf"].parent
        / "watermarks"
        / f"rmap_{prepared_rmap['expected_link']}.pdf"
    )

    assert destination_path.read_bytes() == (
        b"%PDF-watermarked-output"
    )

    with prepared_rmap["engine"].connect() as conn:
        version = conn.execute(
            text("""
                SELECT
                    documentid,
                    link,
                    intended_for,
                    secret,
                    method,
                    position,
                    path
                FROM Versions
            """)
        ).mappings().one()

    assert version["documentid"] == 1
    assert version["link"] == prepared_rmap["expected_link"]
    assert version["intended_for"] == "Group_27"
    assert version["secret"] == "Group_27"
    assert version["method"] == "layered-identity-v1"
    assert version["position"] == "center"
    assert version["path"] == str(destination_path)

    # The clear identity must not appear in the API response.
    assert "Group_27" not in response.get_data(as_text=True)


def test_rmap_get_link_removes_file_when_insert_fails(
    app,
    prepared_rmap,
    client,
):
    base_engine = prepared_rmap["engine"]

    class FailingInsertEngine:
        def connect(self):
            return base_engine.connect()

        def begin(self):
            raise RuntimeError("simulated database insert failure")

    app.config["_ENGINE"] = FailingInsertEngine()

    response = client.post(
        "/api/rmap-get-link",
        json={"payload": "encrypted-msg2"},
    )

    assert response.status_code == 503
    assert response.get_json() == {
        "error": "database error"
    }

    destination_path = (
        prepared_rmap["source_pdf"].parent
        / "watermarks"
        / f"rmap_{prepared_rmap['expected_link']}.pdf"
    )

    assert not destination_path.exists()