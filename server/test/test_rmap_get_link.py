import pytest
from rmap import RMAPError
from sqlalchemy import create_engine, text
from types import SimpleNamespace

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
            self.identities = { "Group_27": SimpleNamespace(nonceServer=123456789,),}
            self._nonce_server_index = {123456789: "Group_27",}

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

@pytest.mark.parametrize(
    "legacy_prefix",
    [None, "/api/get-version/"],
    ids=["default", "legacy-env"],
)
def test_rmap_get_link_returns_bare_nonce_pair(
    prepared_rmap,
    monkeypatch,
    tmp_path,
    legacy_prefix,
):
    from pgpy import PGPKey, PGPUID
    from pgpy.constants import (
        CompressionAlgorithm,
        HashAlgorithm,
        KeyFlags,
        PubKeyAlgorithm,
        SymmetricKeyAlgorithm,
    )
    from rmap import RMAPClient

    def make_test_key(name):
        key = PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 2048)
        key.add_uid(
            PGPUID.new(name),
            usage={
                KeyFlags.Sign,
                KeyFlags.EncryptCommunications,
                KeyFlags.EncryptStorage,
            },
            hashes=[HashAlgorithm.SHA256],
            ciphers=[SymmetricKeyAlgorithm.AES256],
            compression=[CompressionAlgorithm.ZLIB],
        )
        return key

    server_key = make_test_key("TestServer")
    client_key = make_test_key("Group_27")

    server_private = tmp_path / "server_private.asc"
    server_public = tmp_path / "server_public.asc"
    client_private = tmp_path / "client_private.asc"
    identities = tmp_path / "identities"
    identities.mkdir()

    server_private.write_text(str(server_key), encoding="utf-8")
    server_public.write_text(str(server_key.pubkey), encoding="utf-8")
    client_private.write_text(str(client_key), encoding="utf-8")
    (identities / "Group_27.asc").write_text(
        str(client_key.pubkey),
        encoding="utf-8",
    )

    if legacy_prefix is None:
        monkeypatch.delenv("RMAP_LINK_PREFIX", raising=False)
    else:
        monkeypatch.setenv("RMAP_LINK_PREFIX", legacy_prefix)

    # A fresh app uses the real RMAP server instead of FakeRMAPServer.
    real_app = create_app()
    real_app.config.update(
        TESTING=True,
        _ENGINE=prepared_rmap["engine"],
        STORAGE_DIR=tmp_path,
        RMAP_SERVER_PUBLIC_KEY_PATH=str(server_public),
        RMAP_SERVER_PRIVATE_KEY_PATH=str(server_private),
        RMAP_PRIVATE_KEY_PASSPHRASE=None,
        RMAP_IDENTITIES_DIR=str(identities),
        RMAP_DOCUMENT_ID="1",
        RMAP_WATERMARK_METHOD="layered-identity-v1",
        RMAP_WATERMARK_POSITION="center",
        WATERMARK_HMAC_KEY="test-hmac-key",
    )
    http_client = real_app.test_client()

    rmap_client = RMAPClient(
        identity="Group_27",
        client_private_key_path=str(client_private),
        server_public_key_path=str(server_public),
    )

    response1 = http_client.post(
        "/api/rmap-initiate",
        json=rmap_client.build_msg1(),
    )
    assert response1.status_code == 200, response1.get_json()

    nonce_client, nonce_server = rmap_client.process_resp1(
        response1.get_json()
    )

    response2 = http_client.post(
        "/api/rmap-get-link",
        json=rmap_client.build_msg2(),
    )
    assert response2.status_code == 200, response2.get_json()

    result = rmap_client.process_resp2(response2.get_json())
    expected = f"{nonce_client:016x}{nonce_server:016x}"

    # Check the decrypted result, not just the encrypted response wrapper.
    assert result == expected
    assert len(result) == 32

    # The stored download token must match the returned nonce pair.
    with prepared_rmap["engine"].connect() as conn:
        stored_link = conn.execute(
            text("SELECT link FROM Versions")
        ).scalar_one()

    assert stored_link == result