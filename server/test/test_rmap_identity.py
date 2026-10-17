from pathlib import Path

import fitz
import pgpy
import pytest
from pgpy.constants import (
    CompressionAlgorithm,
    HashAlgorithm,
    KeyFlags,
    PubKeyAlgorithm,
    SymmetricKeyAlgorithm,
)
from rmap import RMAPClient, RMAPServer
from rmap.crypto import decrypt_json
from sqlalchemy import create_engine, text

from server import create_app
import watermarking_utils as WMUtils


REGISTERED_IDENTITY = "FIA_UID_Test_Group"
UNREGISTERED_IDENTITY = "FIA_UID_Unregistered_Group"
TEST_HMAC_KEY = "identity-regression-only-do-not-use-in-production"


def _new_test_key(name):
    key = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 2048)
    key.add_uid(
        pgpy.PGPUID.new(name, email="identity-test@example.test"),
        usage={KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage},
        hashes=[HashAlgorithm.SHA256],
        ciphers=[SymmetricKeyAlgorithm.AES256],
        compression=[CompressionAlgorithm.ZLIB, CompressionAlgorithm.Uncompressed],
    )
    return key


@pytest.fixture(scope="module")
def identity_keys(tmp_path_factory):
    """Only the registered alias has a public key in the server registry."""
    key_dir = tmp_path_factory.mktemp("fia_uid_test_keys")
    identities_dir = key_dir / "identities"
    identities_dir.mkdir()
    server_key = _new_test_key("FIA UID test server")
    client_key = _new_test_key("FIA UID test client")

    server_public = key_dir / "server_public.asc"
    server_private = key_dir / "server_private.asc"
    client_private = key_dir / "client_private.asc"
    server_public.write_text(str(server_key.pubkey), encoding="utf-8")
    server_private.write_text(str(server_key), encoding="utf-8")
    client_private.write_text(str(client_key), encoding="utf-8")
    (identities_dir / f"{REGISTERED_IDENTITY}.asc").write_text(
        str(client_key.pubkey), encoding="utf-8"
    )
    return {
        "server_public": server_public,
        "server_private": server_private,
        "client_private": client_private,
        "identities_dir": identities_dir,
    }


@pytest.fixture()
def identity_app(identity_keys, tmp_path, monkeypatch):
    """Create fresh protocol state, database, and PDF storage for each test."""
    storage_dir = tmp_path / "storage"
    monkeypatch.setenv("STORAGE_DIR", str(storage_dir))
    monkeypatch.setenv("SECRET_KEY", "fia-uid-test-only-session-key")
    app = create_app()
    source_pdf = storage_dir / "source.pdf"
    with fitz.open() as document:
        page = document.new_page()
        page.insert_text((72, 72), "FIA_UID.2 identity regression test")
        document.save(str(source_pdf))

    engine = create_engine("sqlite+pysqlite:///:memory:", future=True)
    with engine.begin() as connection:
        connection.execute(text("""
            CREATE TABLE Documents (
                id INTEGER PRIMARY KEY,
                path TEXT NOT NULL
            )
        """))
        connection.execute(text("""
            CREATE TABLE Versions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                documentid INTEGER NOT NULL,
                link TEXT NOT NULL UNIQUE,
                intended_for TEXT,
                secret TEXT,
                method TEXT,
                position TEXT,
                path TEXT NOT NULL
            )
        """))
        connection.execute(
            text("INSERT INTO Documents (id, path) VALUES (1, :path)"),
            {"path": str(source_pdf)},
        )

    app.config.update(
        TESTING=True,
        _ENGINE=engine,
        RMAP_SERVER_PUBLIC_KEY_PATH=str(identity_keys["server_public"]),
        RMAP_SERVER_PRIVATE_KEY_PATH=str(identity_keys["server_private"]),
        RMAP_PRIVATE_KEY_PASSPHRASE=None,
        RMAP_IDENTITIES_DIR=str(identity_keys["identities_dir"]),
        RMAP_DOCUMENT_ID="1",
        RMAP_LINK_PREFIX="/api/get-version/",
        RMAP_WATERMARK_METHOD="layered-identity-v1",
        RMAP_WATERMARK_POSITION="footer",
        WATERMARK_HMAC_KEY=TEST_HMAC_KEY,
    )
    try:
        yield app
    finally:
        engine.dispose()


def _client(identity, keys):
    return RMAPClient(
        identity=identity,
        client_private_key_path=keys["client_private"],
        server_public_key_path=keys["server_public"],
    )


def _versions(app):
    with app.config["_ENGINE"].connect() as connection:
        return connection.execute(text("SELECT * FROM Versions")).mappings().all()


def test_registered_identity_completes_handshake_and_gets_own_version(
    identity_app, identity_keys
):
    """Positive control: reject-all or a broken service must fail this test."""
    http = identity_app.test_client()
    client = _client(REGISTERED_IDENTITY, identity_keys)
    response1 = http.post("/api/rmap-initiate", json=client.build_msg1())
    assert response1.status_code == 200, response1.get_json()
    client.process_resp1(response1.get_json())

    rmap_server = identity_app.extensions["rmap_server"]
    assert isinstance(rmap_server, RMAPServer)
    assert set(rmap_server.identities) == {REGISTERED_IDENTITY}
    assert rmap_server._nonce_server_index[client.nonceServer] == REGISTERED_IDENTITY
    assert _versions(identity_app) == []  # Msg1 alone must not issue a version.
    assert http.get(f"/api/get-version/{client.expected_link}").status_code == 404

    response2 = http.post("/api/rmap-get-link", json=client.build_msg2())
    assert response2.status_code == 200, response2.get_json()
    download_url = client.process_resp2(response2.get_json())
    assert download_url == f"/api/get-version/{client.expected_link}"

    versions = _versions(identity_app)
    assert len(versions) == 1
    version = versions[0]
    assert version["documentid"] == 1
    assert version["link"] == client.expected_link
    assert version["intended_for"] == REGISTERED_IDENTITY
    assert version["secret"] == REGISTERED_IDENTITY
    assert Path(version["path"]).is_file()

    download = http.get(download_url)
    assert download.status_code == 200
    assert download.mimetype == "application/pdf"
    assert download.data.startswith(b"%PDF-")
    assert WMUtils.read_watermark(
        method="layered-identity-v1", pdf=download.data, key=TEST_HMAC_KEY
    ) == REGISTERED_IDENTITY
    download.close()


def test_unregistered_identity_is_rejected_without_session_or_version(
    identity_app, identity_keys
):
    """A valid encrypted Msg1 with an unknown alias cannot obtain a link."""
    http = identity_app.test_client()
    # Reuse our test-owned key while changing only the claimed identity.
    # This isolates the identity registry check from malformed PGP input.
    client = _client(UNREGISTERED_IDENTITY, identity_keys)
    msg1 = client.build_msg1()
    files_before = set(identity_app.config["STORAGE_DIR"].rglob("*"))
    response1 = http.post("/api/rmap-initiate", json=msg1)
    assert response1.status_code == 400, response1.get_json()
    assert response1.get_json() == {"error": "RMAP authentication failed"}

    rmap_server = identity_app.extensions["rmap_server"]
    assert isinstance(rmap_server, RMAPServer)
    assert set(rmap_server.identities) == {REGISTERED_IDENTITY}
    # Confirm the rejected request really was decryptable and well formed.
    assert decrypt_json(msg1, rmap_server.serverPrivateKey) == {
        "identity": UNREGISTERED_IDENTITY,
        "nonceClient": client.nonceClient,
    }
    assert rmap_server._nonce_server_index == {}
    registered = rmap_server.identities[REGISTERED_IDENTITY]
    assert registered.nonceClient is None
    assert registered.nonceServer is None
    assert _versions(identity_app) == []

    # A subsequent validly encrypted Msg2 has no issued session to complete.
    # This single chosen nonce is a state check, not an entropy measurement.
    client.nonceServer = 1
    response2 = http.post("/api/rmap-get-link", json=client.build_msg2())
    assert response2.status_code == 400, response2.get_json()
    assert response2.get_json() == {"error": "RMAP authentication failed"}
    assert http.get(f"/api/get-version/{client.expected_link}").status_code == 404
    assert rmap_server._nonce_server_index == {}
    assert _versions(identity_app) == []
    assert set(identity_app.config["STORAGE_DIR"].rglob("*")) == files_before
