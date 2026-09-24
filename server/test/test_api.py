import hashlib
import io
import pytest
from server import app
from itsdangerous import URLSafeTimedSerializer
from sqlalchemy import create_engine, event, text
from werkzeug.security import generate_password_hash
import server as server_module
from server import app, create_app

def test_healthz_route():
    client = app.test_client()
    resp = client.get("/healthz")

    assert resp.status_code == 200
    assert resp.is_json
    
def make_token(test_app, user_id: int) -> str:
    serializer = URLSafeTimedSerializer(
        test_app.config["SECRET_KEY"],
        salt="tatou-auth",
    )

    return serializer.dumps({
        "uid": user_id,
        "login": f"user-{user_id}",
        "email": f"user-{user_id}@example.test",
    })

def authorization_header(token: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
    }

#Test create user and login API
@pytest.fixture()
def account_api_app(tmp_path):
    test_app = create_app()
    test_app.config.update(
        TESTING=True,
        STORAGE_DIR=tmp_path,
    )

    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        future=True,
    )

    with engine.begin() as conn:
        conn.execute(text("""
            CREATE TABLE Users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                hpassword TEXT NOT NULL,
                login TEXT NOT NULL UNIQUE
            )
        """))

        conn.execute(
            text("""
                INSERT INTO Users (
                    email,
                    hpassword,
                    login
                )
                VALUES (
                    :email,
                    :hpassword,
                    :login
                )
            """),
            {
                "email": "existing@example.test",
                "hpassword": generate_password_hash(
                    "CorrectPassword123!"
                ),
                "login": "existing-user",
            },
        )

    test_app.config["_ENGINE"] = engine

    yield {
        "app": test_app,
        "engine": engine,
    }

    engine.dispose()


def test_create_user_and_login_success(
    account_api_app,
):
    test_app = account_api_app["app"]
    client = test_app.test_client()

    create_response = client.post(
        "/api/create-user",
        json={
            "email": "  NewUser@Example.Test  ",
            "login": "new-user",
            "password": "StrongPassword123!",
        },
    )

    assert create_response.status_code == 201

    created = create_response.get_json()

    assert created["email"] == "newuser@example.test"
    assert created["login"] == "new-user"
    assert isinstance(created["id"], int)

    login_response = client.post(
        "/api/login",
        json={
            "email": "newuser@example.test",
            "password": "StrongPassword123!",
        },
    )

    assert login_response.status_code == 200

    login_body = login_response.get_json()

    assert login_body["token_type"] == "bearer"
    assert isinstance(login_body["token"], str)
    assert login_body["token"]
    assert login_body["expires_in"] > 0

    serializer = URLSafeTimedSerializer(
        test_app.config["SECRET_KEY"],
        salt="tatou-auth",
    )

    token_data = serializer.loads(
        login_body["token"],
        max_age=test_app.config[
            "TOKEN_TTL_SECONDS"
        ],
    )

    assert token_data["uid"] == created["id"]
    assert token_data["login"] == "new-user"
    assert (
        token_data["email"]
        == "newuser@example.test"
    )


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {
            "login": "missing-email",
            "password": "Password123!",
        },
        {
            "email": "missing-login@example.test",
            "password": "Password123!",
        },
        {
            "email": "missing-password@example.test",
            "login": "missing-password",
        },
    ],
)
def test_create_user_rejects_missing_fields(
    account_api_app,
    payload,
):
    client = account_api_app[
        "app"
    ].test_client()

    response = client.post(
        "/api/create-user",
        json=payload,
    )

    assert response.status_code == 400
    assert response.get_json() == {
        "error": (
            "email, login, and password are required"
        )
    }


@pytest.mark.parametrize(
    "payload",
    [
        {
            "email": "existing@example.test",
            "login": "different-login",
            "password": "Password123!",
        },
        {
            "email": "different@example.test",
            "login": "existing-user",
            "password": "Password123!",
        },
    ],
)
def test_create_user_rejects_duplicate_identity(
    account_api_app,
    payload,
):
    client = account_api_app[
        "app"
    ].test_client()

    response = client.post(
        "/api/create-user",
        json=payload,
    )

    assert response.status_code == 409
    assert response.get_json() == {
        "error": "email or login already exists"
    }


def test_login_rejects_wrong_password(
    account_api_app,
):
    client = account_api_app[
        "app"
    ].test_client()

    response = client.post(
        "/api/login",
        json={
            "email": "existing@example.test",
            "password": "wrong-password",
        },
    )

    assert response.status_code == 401
    assert response.get_json() == {
        "error": "invalid credentials"
    }


def test_login_does_not_reveal_unknown_email(
    account_api_app,
):
    client = account_api_app[
        "app"
    ].test_client()

    response = client.post(
        "/api/login",
        json={
            "email": "unknown@example.test",
            "password": "wrong-password",
        },
    )

    assert response.status_code == 401

    # Must be identical to the wrong-password response.
    assert response.get_json() == {
        "error": "invalid credentials"
    }


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {
            "email": "existing@example.test",
        },
        {
            "password": "Password123!",
        },
    ],
)
def test_login_rejects_missing_fields(
    account_api_app,
    payload,
):
    client = account_api_app[
        "app"
    ].test_client()

    response = client.post(
        "/api/login",
        json=payload,
    )

    assert response.status_code == 400
    assert response.get_json() == {
        "error": "email and password are required"
    }

#Test upload document
@pytest.fixture()
def upload_api_app(tmp_path):
    test_app = create_app()
    test_app.config.update(
        TESTING=True,
        STORAGE_DIR=tmp_path,
    )

    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        future=True,
    )

    @event.listens_for(engine, "connect")
    def add_mariadb_compatibility_functions(
        dbapi_connection,
        _connection_record,
    ):
        dbapi_connection.create_function(
            "UNHEX",
            1,
            lambda value: bytes.fromhex(value),
        )

        # The test database starts empty, so the first
        # uploaded document receives id 1.
        dbapi_connection.create_function(
            "LAST_INSERT_ID",
            0,
            lambda: 1,
        )

    with engine.begin() as conn:
        conn.execute(text("""
            CREATE TABLE Documents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                path TEXT NOT NULL,
                ownerid INTEGER NOT NULL,
                creation TIMESTAMP
                    DEFAULT CURRENT_TIMESTAMP,
                sha256 BLOB NOT NULL,
                size INTEGER NOT NULL
            )
        """))

    test_app.config["_ENGINE"] = engine

    yield {
        "app": test_app,
        "engine": engine,
        "storage": tmp_path,
    }

    engine.dispose()


def test_upload_document_requires_authentication(
    upload_api_app,
):
    client = upload_api_app[
        "app"
    ].test_client()

    response = client.post(
        "/api/upload-document",
        data={
            "file": (
                io.BytesIO(b"%PDF-1.4\n%%EOF"),
                "document.pdf",
                "application/pdf",
            ),
        },
        content_type="multipart/form-data",
    )

    assert response.status_code == 401


def test_upload_document_requires_file(
    upload_api_app,
):
    test_app = upload_api_app["app"]
    client = test_app.test_client()

    token = make_token(test_app, user_id=100)

    response = client.post(
        "/api/upload-document",
        data={},
        headers=authorization_header(token),
        content_type="multipart/form-data",
    )

    assert response.status_code == 400
    assert response.get_json() == {
        "error": (
            "file is required (multipart/form-data)"
        )
    }


def test_upload_document_rejects_non_pdf_extension(
    upload_api_app,
):
    test_app = upload_api_app["app"]
    client = test_app.test_client()

    token = make_token(test_app, user_id=100)

    response = client.post(
        "/api/upload-document",
        data={
            "file": (
                io.BytesIO(b"%PDF-1.4\n%%EOF"),
                "document.txt",
                "application/pdf",
            ),
        },
        headers=authorization_header(token),
        content_type="multipart/form-data",
    )

    assert response.status_code == 415
    assert response.get_json() == {
        "error": "only PDF files are allowed"
    }


def test_upload_document_rejects_wrong_mime_type(
    upload_api_app,
):
    test_app = upload_api_app["app"]
    client = test_app.test_client()

    token = make_token(test_app, user_id=100)

    response = client.post(
        "/api/upload-document",
        data={
            "file": (
                io.BytesIO(b"%PDF-1.4\n%%EOF"),
                "document.pdf",
                "text/plain",
            ),
        },
        headers=authorization_header(token),
        content_type="multipart/form-data",
    )

    assert response.status_code == 415
    assert response.get_json() == {
        "error": "invalid PDF content type"
    }


def test_upload_document_rejects_fake_pdf_header(
    upload_api_app,
):
    test_app = upload_api_app["app"]
    client = test_app.test_client()

    token = make_token(test_app, user_id=100)

    response = client.post(
        "/api/upload-document",
        data={
            "file": (
                io.BytesIO(b"this is not a PDF"),
                "document.pdf",
                "application/pdf",
            ),
        },
        headers=authorization_header(token),
        content_type="multipart/form-data",
    )

    assert response.status_code == 415
    assert response.get_json() == {
        "error": "invalid PDF file"
    }


def test_upload_document_uses_generated_safe_path(
    upload_api_app,
):
    test_app = upload_api_app["app"]
    client = test_app.test_client()

    token = make_token(test_app, user_id=100)

    pdf_bytes = b"%PDF-1.4\n%%EOF"

    response = client.post(
        "/api/upload-document",
        data={
            "file": (
                io.BytesIO(pdf_bytes),
                "../../unsafe-name.pdf",
                "application/pdf",
            ),
        },
        headers=authorization_header(token),
        content_type="multipart/form-data",
    )

    assert response.status_code == 201

    body = response.get_json()

    assert body["id"] == 1
    assert body["name"] == "unsafe-name.pdf"
    assert body["size"] == len(pdf_bytes)
    assert (
        body["sha256"].lower()
        == hashlib.sha256(pdf_bytes).hexdigest()
    )

    with upload_api_app[
        "engine"
    ].connect() as conn:
        row = conn.execute(
            text("""
                SELECT
                    name,
                    path,
                    ownerid,
                    HEX(sha256) AS sha256_hex,
                    size
                FROM Documents
                WHERE id = 1
            """)
        ).one()

    stored_path = server_module.Path(
        row.path
    ).resolve()

    expected_directory = (
        upload_api_app["storage"]
        / "files"
        / "100"
    ).resolve()

    assert stored_path.parent == expected_directory
    assert stored_path.name != "unsafe-name.pdf"
    assert stored_path.suffix == ".pdf"
    assert stored_path.read_bytes() == pdf_bytes

    assert row.name == "unsafe-name.pdf"
    assert row.ownerid == 100
    assert row.size == len(pdf_bytes)
    assert (
        row.sha256_hex.lower()
        == hashlib.sha256(pdf_bytes).hexdigest()
    )


def test_upload_document_rejects_oversized_request(
    upload_api_app,
):
    test_app = upload_api_app["app"]

    # Includes multipart overhead, so keep this deliberately small.
    test_app.config["MAX_CONTENT_LENGTH"] = 128

    client = test_app.test_client()
    token = make_token(test_app, user_id=100)

    response = client.post(
        "/api/upload-document",
        data={
            "file": (
                io.BytesIO(
                    b"%PDF-" + b"A" * 1024
                ),
                "large.pdf",
                "application/pdf",
            ),
        },
        headers=authorization_header(token),
        content_type="multipart/form-data",
    )

    assert response.status_code == 413

#Document and version API tests
@pytest.fixture()
def document_api_app(tmp_path):
    storage = tmp_path / "storage"
    storage.mkdir()

    owner_document = storage / "owner.pdf"
    other_document = storage / "other.pdf"
    owner_version = storage / "owner-version.pdf"
    other_version = storage / "other-version.pdf"

    owner_document_bytes = b"%PDF-owner-document"
    other_document_bytes = b"%PDF-other-document"
    owner_version_bytes = b"%PDF-owner-version"
    other_version_bytes = b"%PDF-other-version"

    owner_document.write_bytes(owner_document_bytes)
    other_document.write_bytes(other_document_bytes)
    owner_version.write_bytes(owner_version_bytes)
    other_version.write_bytes(other_version_bytes)

    test_app = create_app()
    test_app.config.update(
        TESTING=True,
        STORAGE_DIR=storage,
    )

    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        future=True,
    )

    with engine.begin() as conn:
        conn.execute(text("""
            CREATE TABLE Documents (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                path TEXT NOT NULL,
                ownerid INTEGER NOT NULL,
                creation TIMESTAMP
                    DEFAULT CURRENT_TIMESTAMP,
                sha256 BLOB NOT NULL,
                size INTEGER NOT NULL
            )
        """))

        conn.execute(text("""
            CREATE TABLE Versions (
                id INTEGER PRIMARY KEY,
                documentid INTEGER NOT NULL,
                link TEXT NOT NULL UNIQUE,
                intended_for TEXT NOT NULL,
                secret TEXT NOT NULL,
                method TEXT NOT NULL,
                position TEXT,
                path TEXT NOT NULL
            )
        """))

        conn.execute(
            text("""
                INSERT INTO Documents (
                    id,
                    name,
                    path,
                    ownerid,
                    sha256,
                    size
                )
                VALUES
                    (
                        1,
                        'owner.pdf',
                        :owner_path,
                        100,
                        :owner_sha256,
                        :owner_size
                    ),
                    (
                        2,
                        'other.pdf',
                        :other_path,
                        200,
                        :other_sha256,
                        :other_size
                    )
            """),
            {
                "owner_path": str(owner_document),
                "other_path": str(other_document),
                "owner_sha256": hashlib.sha256(
                    owner_document_bytes
                ).digest(),
                "other_sha256": hashlib.sha256(
                    other_document_bytes
                ).digest(),
                "owner_size": len(owner_document_bytes),
                "other_size": len(other_document_bytes),
            },
        )

        conn.execute(
            text("""
                INSERT INTO Versions (
                    id,
                    documentid,
                    link,
                    intended_for,
                    secret,
                    method,
                    position,
                    path
                )
                VALUES
                    (
                        10,
                        1,
                        'owner-capability-link',
                        'owner-recipient',
                        'owner-secret-must-not-leak',
                        'layered-identity-v1',
                        'center',
                        :owner_version
                    ),
                    (
                        20,
                        2,
                        'other-capability-link',
                        'other-recipient',
                        'other-secret-must-not-leak',
                        'visible-text-watermark',
                        'center',
                        :other_version
                    )
            """),
            {
                "owner_version": str(owner_version),
                "other_version": str(other_version),
            },
        )

    test_app.config["_ENGINE"] = engine

    yield {
        "app": test_app,
        "engine": engine,
        "storage": storage,
        "owner_document": owner_document,
        "other_document": other_document,
        "owner_version": owner_version,
        "other_version": other_version,
        "owner_document_bytes": owner_document_bytes,
        "owner_version_bytes": owner_version_bytes,
    }

    engine.dispose()


def test_list_documents_returns_only_owned_documents(
    document_api_app,
):
    test_app = document_api_app["app"]
    client = test_app.test_client()

    token = make_token(test_app, user_id=100)

    response = client.get(
        "/api/list-documents",
        headers=authorization_header(token),
    )

    assert response.status_code == 200

    documents = response.get_json()["documents"]

    assert len(documents) == 1
    assert documents[0]["id"] == 1
    assert documents[0]["name"] == "owner.pdf"
    assert documents[0]["size"] == len(
        document_api_app["owner_document_bytes"]
    )

    returned_ids = {
        document["id"]
        for document in documents
    }

    assert 2 not in returned_ids


def test_list_versions_returns_only_owned_document_versions(
    document_api_app,
):
    test_app = document_api_app["app"]
    client = test_app.test_client()

    token = make_token(test_app, user_id=100)

    response = client.get(
        "/api/list-versions/1",
        headers=authorization_header(token),
    )

    assert response.status_code == 200

    versions = response.get_json()["versions"]

    assert len(versions) == 1
    assert versions[0]["id"] == 10
    assert versions[0]["documentid"] == 1
    assert (
        versions[0]["intended_for"]
        == "owner-recipient"
    )
    assert (
        versions[0]["method"]
        == "layered-identity-v1"
    )

    # The protected watermark secret must never
    # appear in a version-list response.
    assert "secret" not in versions[0]
    assert (
        "owner-secret-must-not-leak"
        not in response.get_data(as_text=True)
    )


def test_list_versions_rejects_other_users_document(
    document_api_app,
):
    test_app = document_api_app["app"]
    client = test_app.test_client()

    token = make_token(test_app, user_id=100)

    response = client.get(
        "/api/list-versions/2",
        headers=authorization_header(token),
    )

    assert response.status_code == 200
    assert response.get_json() == {
        "versions": []
    }

    assert (
        "other-secret-must-not-leak"
        not in response.get_data(as_text=True)
    )


@pytest.mark.parametrize(
    "url",
    [
        "/api/list-versions",
        "/api/list-versions?id=not-an-integer",
        "/api/list-versions?documentid=",
    ],
)
def test_list_versions_requires_valid_document_id(
    document_api_app,
    url,
):
    test_app = document_api_app["app"]
    client = test_app.test_client()

    token = make_token(test_app, user_id=100)

    response = client.get(
        url,
        headers=authorization_header(token),
    )

    assert response.status_code == 400
    assert response.get_json() == {
        "error": "document id required"
    }


def test_list_all_versions_returns_only_owned_versions(
    document_api_app,
):
    test_app = document_api_app["app"]
    client = test_app.test_client()

    token = make_token(test_app, user_id=100)

    response = client.get(
        "/api/list-all-versions",
        headers=authorization_header(token),
    )

    assert response.status_code == 200

    versions = response.get_json()["versions"]

    assert len(versions) == 1
    assert versions[0]["id"] == 10
    assert versions[0]["documentid"] == 1

    assert all(
        "secret" not in version
        for version in versions
    )

    response_text = response.get_data(
        as_text=True
    )

    assert "owner-secret-must-not-leak" not in response_text
    assert "other-secret-must-not-leak" not in response_text


def test_get_document_returns_owned_pdf(
    document_api_app,
):
    test_app = document_api_app["app"]
    client = test_app.test_client()

    token = make_token(test_app, user_id=100)

    response = client.get(
        "/api/get-document/1",
        headers=authorization_header(token),
    )

    assert response.status_code == 200
    assert (
        response.data
        == document_api_app["owner_document_bytes"]
    )
    assert response.mimetype == "application/pdf"

    cache_control = response.headers.get(
        "Cache-Control",
        "",
    )

    assert "private" in cache_control
    assert "must-revalidate" in cache_control
    assert response.headers.get("ETag")


def test_get_document_rejects_other_user(
    document_api_app,
):
    test_app = document_api_app["app"]
    client = test_app.test_client()

    token = make_token(test_app, user_id=100)

    response = client.get(
        "/api/get-document/2",
        headers=authorization_header(token),
    )

    assert response.status_code == 404
    assert response.get_json() == {
        "error": "document not found"
    }


@pytest.mark.parametrize(
    "url",
    [
        "/api/get-document",
        "/api/get-document?id=invalid",
        "/api/get-document?documentid=",
    ],
)
def test_get_document_requires_valid_document_id(
    document_api_app,
    url,
):
    test_app = document_api_app["app"]
    client = test_app.test_client()

    token = make_token(test_app, user_id=100)

    response = client.get(
        url,
        headers=authorization_header(token),
    )

    assert response.status_code == 400
    assert response.get_json() == {
        "error": "document id required"
    }


def test_get_document_rejects_path_outside_storage(
    document_api_app,
    tmp_path,
):
    test_app = document_api_app["app"]
    client = test_app.test_client()

    outside_file = tmp_path / "outside.pdf"
    outside_file.write_bytes(
        b"%PDF-outside-storage"
    )

    with document_api_app[
        "engine"
    ].begin() as conn:
        conn.execute(
            text("""
                UPDATE Documents
                SET path = :path
                WHERE id = 1
            """),
            {
                "path": str(outside_file),
            },
        )

    token = make_token(test_app, user_id=100)

    response = client.get(
        "/api/get-document/1",
        headers=authorization_header(token),
    )

    assert response.status_code == 500
    assert response.get_json() == {
        "error": "document path invalid"
    }


def test_get_document_reports_missing_file(
    document_api_app,
):
    test_app = document_api_app["app"]
    client = test_app.test_client()

    document_api_app[
        "owner_document"
    ].unlink()

    token = make_token(test_app, user_id=100)

    response = client.get(
        "/api/get-document/1",
        headers=authorization_header(token),
    )

    assert response.status_code == 410
    assert response.get_json() == {
        "error": "file missing on disk"
    }

#Test Create Watermark API
@pytest.fixture()
def create_watermark_api_app(
    tmp_path,
    monkeypatch,
):
    storage = tmp_path / "storage"
    storage.mkdir()

    owner_pdf = storage / "owner.pdf"
    other_pdf = storage / "other.pdf"

    owner_pdf.write_bytes(
        b"%PDF-owner-document"
    )
    other_pdf.write_bytes(
        b"%PDF-other-document"
    )

    test_app = create_app()
    test_app.config.update(
        TESTING=True,
        STORAGE_DIR=storage,
    )

    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        future=True,
    )

    @event.listens_for(engine, "connect")
    def add_last_insert_id(
        dbapi_connection,
        _connection_record,
    ):
        # Each parametrized test receives a new empty
        # Versions table, so its first version id is 1.
        dbapi_connection.create_function(
            "LAST_INSERT_ID",
            0,
            lambda: 1,
        )

    with engine.begin() as conn:
        conn.execute(text("""
            CREATE TABLE Documents (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                path TEXT NOT NULL,
                ownerid INTEGER NOT NULL
            )
        """))

        conn.execute(text("""
            CREATE TABLE Versions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                documentid INTEGER NOT NULL,
                link TEXT NOT NULL UNIQUE,
                intended_for TEXT NOT NULL,
                secret TEXT NOT NULL,
                method TEXT NOT NULL,
                position TEXT,
                path TEXT NOT NULL
            )
        """))

        conn.execute(
            text("""
                INSERT INTO Documents (
                    id,
                    name,
                    path,
                    ownerid
                )
                VALUES
                    (
                        1,
                        'owner.pdf',
                        :owner_path,
                        100
                    ),
                    (
                        2,
                        'other.pdf',
                        :other_path,
                        200
                    )
            """),
            {
                "owner_path": str(owner_pdf),
                "other_path": str(other_pdf),
            },
        )

    test_app.config["_ENGINE"] = engine

    captured = {
        "applicability_calls": [],
        "watermark_calls": [],
    }

    def fake_is_applicable(
        *,
        method,
        pdf,
        position,
    ):
        captured["applicability_calls"].append({
            "method": method,
            "pdf": pdf,
            "position": position,
        })

        return True

    def fake_apply_watermark(
        *,
        pdf,
        secret,
        key,
        method,
        position,
    ):
        captured["watermark_calls"].append({
            "pdf": pdf,
            "secret": secret,
            "key": key,
            "method": method,
            "position": position,
        })

        return b"%PDF-generated-watermark"

    monkeypatch.setattr(
        server_module.WMUtils,
        "is_watermarking_applicable",
        fake_is_applicable,
    )

    monkeypatch.setattr(
        server_module.WMUtils,
        "apply_watermark",
        fake_apply_watermark,
    )

    yield {
        "app": test_app,
        "engine": engine,
        "storage": storage,
        "owner_pdf": owner_pdf,
        "other_pdf": other_pdf,
        "captured": captured,
    }

    engine.dispose()


def watermark_request_payload(
    method="layered-identity-v1",
):
    return {
        "method": method,
        "intended_for": "Test Recipient",
        "secret": "Test_Group",
        "key": "test-watermark-key",
        "position": "center",
    }


def test_create_watermark_requires_authentication(
    create_watermark_api_app,
):
    client = create_watermark_api_app[
        "app"
    ].test_client()

    response = client.post(
        "/api/create-watermark/1",
        json=watermark_request_payload(),
    )

    assert response.status_code == 401


@pytest.mark.parametrize(
    "method",
    [
        "toy-eof",
        "layered-identity-v1",
        "visible-text-watermark",
    ],
)
def test_create_watermark_success_for_registered_method(
    create_watermark_api_app,
    method,
):
    test_app = create_watermark_api_app["app"]
    client = test_app.test_client()

    token = make_token(test_app, user_id=100)

    response = client.post(
        "/api/create-watermark/1",
        json=watermark_request_payload(method),
        headers=authorization_header(token),
    )

    assert response.status_code == 201

    body = response.get_json()

    assert body["id"] == 1
    assert body["documentid"] == 1
    assert body["method"] == method
    assert body["intended_for"] == "Test Recipient"
    assert body["position"] == "center"
    assert body["size"] == len(
        b"%PDF-generated-watermark"
    )

    # token_urlsafe(32) normally produces 43 characters.
    assert isinstance(body["link"], str)
    assert len(body["link"]) >= 40
    assert "/" not in body["link"]
    assert "\\" not in body["link"]

    # User-controlled recipient text must be sanitized
    # before being placed into the physical filename.
    assert ".." not in body["filename"]
    assert "/" not in body["filename"]
    assert "\\" not in body["filename"]
    assert body["filename"].endswith(".pdf")

    with create_watermark_api_app[
        "engine"
    ].connect() as conn:
        row = conn.execute(
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
                WHERE link = :link
            """),
            {
                "link": body["link"],
            },
        ).one()

    assert row.documentid == 1
    assert row.link == body["link"]
    assert row.intended_for == "Test Recipient"
    assert row.secret == "Test_Group"
    assert row.method == method
    assert row.position == "center"

    version_path = server_module.Path(
        row.path
    ).resolve()

    storage_root = create_watermark_api_app[
        "storage"
    ].resolve()

    assert version_path.is_relative_to(
        storage_root
    )
    assert version_path.parent.name == "watermarks"
    assert version_path.name == body["filename"]
    assert version_path.exists()
    assert (
        version_path.read_bytes()
        == b"%PDF-generated-watermark"
    )

    applicability_call = (
        create_watermark_api_app[
            "captured"
        ]["applicability_calls"][0]
    )

    watermark_call = (
        create_watermark_api_app[
            "captured"
        ]["watermark_calls"][0]
    )

    expected_pdf = str(
        create_watermark_api_app[
            "owner_pdf"
        ].resolve()
    )

    assert applicability_call == {
        "method": method,
        "pdf": expected_pdf,
        "position": "center",
    }

    assert watermark_call == {
        "pdf": expected_pdf,
        "secret": "Test_Group",
        "key": "test-watermark-key",
        "method": method,
        "position": "center",
    }


def test_create_watermark_generates_unique_links(
    create_watermark_api_app,
):
    test_app = create_watermark_api_app["app"]
    client = test_app.test_client()

    token = make_token(test_app, user_id=100)

    first_response = client.post(
        "/api/create-watermark/1",
        json=watermark_request_payload(),
        headers=authorization_header(token),
    )

    second_response = client.post(
        "/api/create-watermark/1",
        json=watermark_request_payload(),
        headers=authorization_header(token),
    )

    assert first_response.status_code == 201
    assert second_response.status_code == 201

    first_body = first_response.get_json()
    second_body = second_response.get_json()

    assert first_body["link"] != second_body["link"]
    assert (
        first_body["filename"]
        != second_body["filename"]
    )

    with create_watermark_api_app[
        "engine"
    ].connect() as conn:
        links = conn.execute(
            text("""
                SELECT link
                FROM Versions
                ORDER BY id
            """)
        ).scalars().all()

    assert len(links) == 2
    assert len(set(links)) == 2


def test_create_watermark_rejects_other_users_document(
    create_watermark_api_app,
):
    test_app = create_watermark_api_app["app"]
    client = test_app.test_client()

    token = make_token(test_app, user_id=100)

    response = client.post(
        "/api/create-watermark/2",
        json=watermark_request_payload(),
        headers=authorization_header(token),
    )

    assert response.status_code == 404
    assert response.get_json() == {
        "error": "document not found"
    }

    assert (
        create_watermark_api_app[
            "captured"
        ]["applicability_calls"]
        == []
    )

    assert (
        create_watermark_api_app[
            "captured"
        ]["watermark_calls"]
        == []
    )


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {
            "intended_for": "recipient",
            "secret": "secret",
            "key": "key",
        },
        {
            "method": "layered-identity-v1",
            "secret": "secret",
            "key": "key",
        },
        {
            "method": "layered-identity-v1",
            "intended_for": "recipient",
            "key": "key",
        },
        {
            "method": "layered-identity-v1",
            "intended_for": "recipient",
            "secret": "secret",
        },
        {
            "method": "layered-identity-v1",
            "intended_for": "recipient",
            "secret": 123,
            "key": "key",
        },
        {
            "method": "layered-identity-v1",
            "intended_for": "recipient",
            "secret": "secret",
            "key": 123,
        },
    ],
)
def test_create_watermark_rejects_missing_or_invalid_fields(
    create_watermark_api_app,
    payload,
):
    test_app = create_watermark_api_app["app"]
    client = test_app.test_client()

    token = make_token(test_app, user_id=100)

    response = client.post(
        "/api/create-watermark/1",
        json=payload,
        headers=authorization_header(token),
    )

    assert response.status_code == 400
    assert response.get_json() == {
        "error": (
            "method, intended_for, secret, "
            "and key are required"
        )
    }


@pytest.mark.parametrize(
    "url",
    [
        "/api/create-watermark",
        "/api/create-watermark?id=invalid",
        "/api/create-watermark?documentid=",
    ],
)
def test_create_watermark_requires_valid_document_id(
    create_watermark_api_app,
    url,
):
    test_app = create_watermark_api_app["app"]
    client = test_app.test_client()

    token = make_token(test_app, user_id=100)

    response = client.post(
        url,
        json=watermark_request_payload(),
        headers=authorization_header(token),
    )

    assert response.status_code == 400
    assert response.get_json() == {
        "error": "document_id (int) is required"
    }


def test_create_watermark_rejects_unknown_method(
    create_watermark_api_app,
    monkeypatch,
):
    test_app = create_watermark_api_app["app"]
    client = test_app.test_client()

    def raise_unknown_method(**_kwargs):
        raise KeyError("unknown watermark method")

    monkeypatch.setattr(
        server_module.WMUtils,
        "is_watermarking_applicable",
        raise_unknown_method,
    )

    token = make_token(test_app, user_id=100)

    response = client.post(
        "/api/create-watermark/1",
        json=watermark_request_payload(
            "unknown-method"
        ),
        headers=authorization_header(token),
    )

    assert response.status_code == 400
    assert response.get_json()["error"].startswith(
        "watermark applicability check failed:"
    )


def test_create_watermark_rejects_non_applicable_method(
    create_watermark_api_app,
    monkeypatch,
):
    test_app = create_watermark_api_app["app"]
    client = test_app.test_client()

    monkeypatch.setattr(
        server_module.WMUtils,
        "is_watermarking_applicable",
        lambda **_kwargs: False,
    )

    token = make_token(test_app, user_id=100)

    response = client.post(
        "/api/create-watermark/1",
        json=watermark_request_payload(),
        headers=authorization_header(token),
    )

    assert response.status_code == 400
    assert response.get_json() == {
        "error": (
            "watermarking method not applicable"
        )
    }

    assert (
        create_watermark_api_app[
            "captured"
        ]["watermark_calls"]
        == []
    )


@pytest.mark.parametrize(
    "invalid_output",
    [
        b"",
        None,
        "not-bytes",
    ],
)
def test_create_watermark_rejects_invalid_output(
    create_watermark_api_app,
    monkeypatch,
    invalid_output,
):
    test_app = create_watermark_api_app["app"]
    client = test_app.test_client()

    monkeypatch.setattr(
        server_module.WMUtils,
        "apply_watermark",
        lambda **_kwargs: invalid_output,
    )

    token = make_token(test_app, user_id=100)

    response = client.post(
        "/api/create-watermark/1",
        json=watermark_request_payload(),
        headers=authorization_header(token),
    )

    assert response.status_code == 500
    assert response.get_json() == {
        "error": "watermarking produced no output"
    }


def test_create_watermark_rejects_source_path_outside_storage(
    create_watermark_api_app,
    tmp_path,
):
    test_app = create_watermark_api_app["app"]
    client = test_app.test_client()

    outside_pdf = tmp_path / "outside.pdf"
    outside_pdf.write_bytes(
        b"%PDF-outside-storage"
    )

    with create_watermark_api_app[
        "engine"
    ].begin() as conn:
        conn.execute(
            text("""
                UPDATE Documents
                SET path = :path
                WHERE id = 1
            """),
            {
                "path": str(outside_pdf),
            },
        )

    token = make_token(test_app, user_id=100)

    response = client.post(
        "/api/create-watermark/1",
        json=watermark_request_payload(),
        headers=authorization_header(token),
    )

    assert response.status_code == 500
    assert response.get_json() == {
        "error": "document path invalid"
    }

    assert (
        create_watermark_api_app[
            "captured"
        ]["watermark_calls"]
        == []
    )


def test_create_watermark_reports_missing_source_file(
    create_watermark_api_app,
):
    test_app = create_watermark_api_app["app"]
    client = test_app.test_client()

    create_watermark_api_app[
        "owner_pdf"
    ].unlink()

    token = make_token(test_app, user_id=100)

    response = client.post(
        "/api/create-watermark/1",
        json=watermark_request_payload(),
        headers=authorization_header(token),
    )

    assert response.status_code == 410
    assert response.get_json() == {
        "error": "file missing on disk"
    }


def test_create_watermark_removes_file_when_database_insert_fails(
    create_watermark_api_app,
):
    test_app = create_watermark_api_app["app"]
    client = test_app.test_client()

    # The source lookup still works, but version insertion
    # will fail because the destination table is removed.
    with create_watermark_api_app[
        "engine"
    ].begin() as conn:
        conn.execute(text(
            "DROP TABLE Versions"
        ))

    token = make_token(test_app, user_id=100)

    response = client.post(
        "/api/create-watermark/1",
        json=watermark_request_payload(),
        headers=authorization_header(token),
    )

    assert response.status_code == 503
    assert response.get_json()[
        "error"
    ].startswith(
        "database error during version insert:"
    )

    watermark_directory = (
        create_watermark_api_app["owner_pdf"].parent
        / "watermarks"
    )

    if watermark_directory.exists():
        assert list(
            watermark_directory.iterdir()
        ) == []

#Test Read-watermark API
@pytest.fixture()
def prepared_read_app(tmp_path, monkeypatch):
    test_app = create_app()

    test_app.config.update(TESTING=True, STORAGE_DIR=tmp_path,)

    original_path = tmp_path / "original.pdf"
    original_path.write_bytes(b"%PDF-original-document")

    version_directory = tmp_path / "watermarks"
    version_directory.mkdir()

    version_path = version_directory / "version-10.pdf"
    version_path.write_bytes(b"%PDF-watermarked-version")

    engine = create_engine(
        "sqlite+pysqlite:///:memory:", future=True,)

    with engine.begin() as conn:
        conn.execute(text("""
            CREATE TABLE Documents (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                path TEXT NOT NULL,
                ownerid INTEGER NOT NULL
            )
        """))

        conn.execute(text("""
            CREATE TABLE Versions (
                id INTEGER PRIMARY KEY,
                documentid INTEGER NOT NULL,
                path TEXT NOT NULL,
                method TEXT NOT NULL,
                position TEXT
            )
        """))

        conn.execute(
            text("""
                INSERT INTO Documents (
                    id,
                    name,
                    path,
                    ownerid
                )
                VALUES (
                    1,
                    'original.pdf',
                    :path,
                    100
                )
            """),
            {
                "path": str(original_path),
            },
        )

        conn.execute(
            text("""
                INSERT INTO Versions (
                    id,
                    documentid,
                    path,
                    method,
                    position
                )
                VALUES (
                    10,
                    1,
                    :path,
                    'layered-identity-v1',
                    'center'
                )
            """),
            {
                "path": str(version_path),
            },
        )

    test_app.config["_ENGINE"] = engine

    captured = {}

    def fake_read_watermark(*, method, pdf, key):
        captured["method"] = method
        captured["pdf"] = pdf
        captured["key"] = key

        return "Test_Group"

    monkeypatch.setattr(
        server_module.WMUtils,
        "read_watermark",
        fake_read_watermark,
    )

    yield {
        "app": test_app,
        "engine": engine,
        "original_path": original_path,
        "version_path": version_path,
        "captured": captured,
    }

    engine.dispose()


def test_read_watermark_uses_version_path(
    prepared_read_app,
):
    test_app = prepared_read_app["app"]
    client = test_app.test_client()

    token = make_token(
        test_app,
        user_id=100,
    )

    response = client.post(
        "/api/read-watermark/1",
        json={
            "version_id": 10,
            "key": "correct-key",
        },
        headers=authorization_header(token),
    )

    assert response.status_code == 200

    body = response.get_json()

    assert body["documentid"] == 1
    assert body["versionid"] == 10
    assert body["secret"] == "Test_Group"
    assert body["method"] == "layered-identity-v1"
    assert body["position"] == "center"

    # Confirm that Versions.path was used.
    assert prepared_read_app["captured"]["pdf"] == str(
        prepared_read_app["version_path"].resolve()
    )

    # Confirm that Documents.path was not used.
    assert prepared_read_app["captured"]["pdf"] != str(
        prepared_read_app["original_path"].resolve()
    )

    assert (
        prepared_read_app["captured"]["method"]
        == "layered-identity-v1"
    )

    assert (
        prepared_read_app["captured"]["key"]
        == "correct-key"
    )


def test_read_watermark_rejects_other_user(
    prepared_read_app,
):
    test_app = prepared_read_app["app"]
    client = test_app.test_client()

    other_user_token = make_token(
        test_app,
        user_id=200,
    )

    response = client.post(
        "/api/read-watermark/1",
        json={
            "version_id": 10,
            "key": "correct-key",
        },
        headers=authorization_header(
            other_user_token
        ),
    )

    assert response.status_code == 404

    assert response.get_json() == {
        "error": "watermark version not found"
    }

    # The watermark implementation must not be called
    # for another user's version.
    assert prepared_read_app["captured"] == {}

def test_read_watermark_requires_authentication(
    prepared_read_app,
):
    client = prepared_read_app[
        "app"
    ].test_client()

    response = client.post(
        "/api/read-watermark/1",
        json={
            "version_id": 10,
            "key": "correct-key",
        },
    )

    assert response.status_code == 401


def test_read_watermark_requires_json_body(
    prepared_read_app,
):
    test_app = prepared_read_app["app"]
    client = test_app.test_client()

    token = make_token(test_app, user_id=100)

    response = client.post(
        "/api/read-watermark/1",
        data="not-json",
        content_type="text/plain",
        headers=authorization_header(token),
    )

    assert response.status_code == 400
    assert response.get_json() == {
        "error": "JSON request body required"
    }


@pytest.mark.parametrize(
    ("url", "payload"),
    [
        (
            "/api/read-watermark",
            {
                "version_id": 10,
                "key": "correct-key",
            },
        ),
        (
            "/api/read-watermark/1",
            {
                "key": "correct-key",
            },
        ),
        (
            "/api/read-watermark",
            {
                "document_id": "invalid",
                "version_id": 10,
                "key": "correct-key",
            },
        ),
        (
            "/api/read-watermark",
            {
                "document_id": 1,
                "version_id": "invalid",
                "key": "correct-key",
            },
        ),
    ],
)
def test_read_watermark_requires_integer_ids(
    prepared_read_app,
    url,
    payload,
):
    test_app = prepared_read_app["app"]
    client = test_app.test_client()

    token = make_token(test_app, user_id=100)

    response = client.post(
        url,
        json=payload,
        headers=authorization_header(token),
    )

    assert response.status_code == 400
    assert response.get_json() == {
        "error": (
            "document_id and version_id "
            "must be integers"
        )
    }


@pytest.mark.parametrize(
    "payload",
    [
        {
            "document_id": 0,
            "version_id": 10,
            "key": "correct-key",
        },
        {
            "document_id": -1,
            "version_id": 10,
            "key": "correct-key",
        },
        {
            "document_id": 1,
            "version_id": 0,
            "key": "correct-key",
        },
        {
            "document_id": 1,
            "version_id": -10,
            "key": "correct-key",
        },
    ],
)
def test_read_watermark_requires_positive_ids(
    prepared_read_app,
    payload,
):
    test_app = prepared_read_app["app"]
    client = test_app.test_client()

    token = make_token(test_app, user_id=100)

    response = client.post(
        "/api/read-watermark",
        json=payload,
        headers=authorization_header(token),
    )

    assert response.status_code == 400
    assert response.get_json() == {
        "error": (
            "document_id and version_id "
            "must be positive"
        )
    }


@pytest.mark.parametrize(
    "invalid_key",
    [
        None,
        "",
        123,
    ],
)
def test_read_watermark_requires_nonempty_string_key(
    prepared_read_app,
    invalid_key,
):
    test_app = prepared_read_app["app"]
    client = test_app.test_client()

    token = make_token(test_app, user_id=100)

    response = client.post(
        "/api/read-watermark/1",
        json={
            "version_id": 10,
            "key": invalid_key,
        },
        headers=authorization_header(token),
    )

    assert response.status_code == 400
    assert response.get_json() == {
        "error": "key is required"
    }


def test_read_watermark_rejects_version_document_mismatch(
    prepared_read_app,
):
    test_app = prepared_read_app["app"]
    client = test_app.test_client()

    token = make_token(test_app, user_id=100)

    # Version 10 belongs to document 1, not document 999.
    response = client.post(
        "/api/read-watermark/999",
        json={
            "version_id": 10,
            "key": "correct-key",
        },
        headers=authorization_header(token),
    )

    assert response.status_code == 404
    assert response.get_json() == {
        "error": "watermark version not found"
    }

    assert prepared_read_app["captured"] == {}


def test_read_watermark_rejects_path_outside_storage(
    prepared_read_app,
    tmp_path,
):
    test_app = prepared_read_app["app"]
    client = test_app.test_client()

    outside_path = (
        tmp_path.parent
        / f"{tmp_path.name}-outside-watermark.pdf"
    )

    outside_path.write_bytes(
        b"%PDF-outside-storage"
    )

    try:
        with prepared_read_app[
            "engine"
        ].begin() as conn:
            conn.execute(
                text("""
                    UPDATE Versions
                    SET path = :path
                    WHERE id = 10
                """),
                {
                    "path": str(outside_path),
                },
            )

        token = make_token(test_app, user_id=100)

        response = client.post(
            "/api/read-watermark/1",
            json={
                "version_id": 10,
                "key": "correct-key",
            },
            headers=authorization_header(token),
        )

        assert response.status_code == 500
        assert response.get_json() == {
            "error": "watermark path invalid"
        }

        assert prepared_read_app["captured"] == {}

    finally:
        outside_path.unlink(missing_ok=True)


def test_read_watermark_reports_missing_version_file(
    prepared_read_app,
):
    test_app = prepared_read_app["app"]
    client = test_app.test_client()

    prepared_read_app[
        "version_path"
    ].unlink()

    token = make_token(test_app, user_id=100)

    response = client.post(
        "/api/read-watermark/1",
        json={
            "version_id": 10,
            "key": "correct-key",
        },
        headers=authorization_header(token),
    )

    assert response.status_code == 410
    assert response.get_json() == {
        "error": "watermark file missing"
    }

    assert prepared_read_app["captured"] == {}


def test_read_watermark_rejects_verification_failure(
    prepared_read_app,
    monkeypatch,
):
    test_app = prepared_read_app["app"]
    client = test_app.test_client()

    def reject_watermark(**_kwargs):
        raise ValueError(
            "wrong key or tampered watermark"
        )

    monkeypatch.setattr(
        server_module.WMUtils,
        "read_watermark",
        reject_watermark,
    )

    token = make_token(test_app, user_id=100)

    response = client.post(
        "/api/read-watermark/1",
        json={
            "version_id": 10,
            "key": "wrong-key",
        },
        headers=authorization_header(token),
    )

    assert response.status_code == 400
    assert response.get_json() == {
        "error": "watermark verification failed"
    }

    # Internal cryptographic details must not be
    # returned to the caller.
    assert (
        "wrong key"
        not in response.get_data(
            as_text=True
        ).lower()
    )


def test_read_watermark_handles_database_failure(
    prepared_read_app,
):
    test_app = prepared_read_app["app"]
    client = test_app.test_client()

    with prepared_read_app[
        "engine"
    ].begin() as conn:
        conn.execute(text(
            "DROP TABLE Versions"
        ))

    token = make_token(test_app, user_id=100)

    response = client.post(
        "/api/read-watermark/1",
        json={
            "version_id": 10,
            "key": "correct-key",
        },
        headers=authorization_header(token),
    )

    assert response.status_code == 503
    assert response.get_json() == {
        "error": "database error"
    }

#Test Delect-document API
@pytest.fixture()
def prepared_delete_app(tmp_path):
    test_app = create_app()

    test_app.config.update(
        TESTING=True,
        STORAGE_DIR=tmp_path,
    )

    original_path = tmp_path / "original.pdf"
    original_path.write_bytes(
        b"%PDF-original"
    )

    watermark_directory = (
        tmp_path / "watermarks"
    )
    watermark_directory.mkdir()

    version_one = (
        watermark_directory / "version-one.pdf"
    )
    version_two = (
        watermark_directory / "version-two.pdf"
    )

    version_one.write_bytes(
        b"%PDF-version-one"
    )
    version_two.write_bytes(
        b"%PDF-version-two"
    )

    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        future=True,
    )

    @event.listens_for(engine, "connect")
    def enable_foreign_keys(
        dbapi_connection,
        _connection_record,
    ):
        cursor = dbapi_connection.cursor()

        cursor.execute(
            "PRAGMA foreign_keys=ON"
        )

        cursor.close()

    with engine.begin() as conn:
        conn.execute(text("""
            CREATE TABLE Documents (
                id INTEGER PRIMARY KEY,
                path TEXT NOT NULL,
                ownerid INTEGER NOT NULL
            )
        """))

        conn.execute(text("""
            CREATE TABLE Versions (
                id INTEGER PRIMARY KEY,
                documentid INTEGER NOT NULL,
                path TEXT NOT NULL,

                FOREIGN KEY (documentid)
                    REFERENCES Documents(id)
                    ON DELETE CASCADE
            )
        """))

        conn.execute(
            text("""
                INSERT INTO Documents (
                    id,
                    path,
                    ownerid
                )
                VALUES (
                    1,
                    :path,
                    100
                )
            """),
            {
                "path": str(original_path),
            },
        )

        conn.execute(
            text("""
                INSERT INTO Versions (
                    id,
                    documentid,
                    path
                )
                VALUES
                    (
                        10,
                        1,
                        :version_one
                    ),
                    (
                        11,
                        1,
                        :version_two
                    )
            """),
            {
                "version_one": str(version_one),
                "version_two": str(version_two),
            },
        )

    test_app.config["_ENGINE"] = engine

    yield {
        "app": test_app,
        "engine": engine,
        "original_path": original_path,
        "version_one": version_one,
        "version_two": version_two,
    }

    engine.dispose()


def test_delete_document_removes_original_and_versions(
    prepared_delete_app,
):
    test_app = prepared_delete_app["app"]
    client = test_app.test_client()

    token = make_token(
        test_app,
        user_id=100,
    )

    response = client.delete(
        "/api/delete-document/1",
        headers=authorization_header(token),
    )

    assert response.status_code == 200

    body = response.get_json()

    assert body["deleted"] is True
    assert body["id"] == 1
    assert body["file_deleted"] == 3
    assert body["file_missing"] == 0
    assert body["cleanup_pending"] == 0

    # Original and every generated version must be removed.
    assert not prepared_delete_app[
        "original_path"
    ].exists()

    assert not prepared_delete_app[
        "version_one"
    ].exists()

    assert not prepared_delete_app[
        "version_two"
    ].exists()

    # The database document and versions must also be removed.
    with prepared_delete_app[
        "engine"
    ].connect() as conn:
        document_count = conn.execute(
            text("""
                SELECT COUNT(*)
                FROM Documents
            """)
        ).scalar_one()

        version_count = conn.execute(
            text("""
                SELECT COUNT(*)
                FROM Versions
            """)
        ).scalar_one()

    assert document_count == 0
    assert version_count == 0


def test_delete_document_rejects_other_user(
    prepared_delete_app,
    ):
    test_app = prepared_delete_app["app"]
    client = test_app.test_client()

    other_user_token = make_token(
        test_app,
        user_id=200,
    )

    response = client.delete(
        "/api/delete-document/1",
        headers=authorization_header(
            other_user_token
        ),
    )

    assert response.status_code == 404

    assert response.get_json() == {
        "error": "document not found"
    }

    # No file belonging to the real owner may be removed.
    assert prepared_delete_app[
        "original_path"
    ].exists()

    assert prepared_delete_app[
        "version_one"
    ].exists()

    assert prepared_delete_app[
        "version_two"
    ].exists()

    # Database rows must remain unchanged.
    with prepared_delete_app[
        "engine"
    ].connect() as conn:
        document_count = conn.execute(
            text("""
                SELECT COUNT(*)
                FROM Documents
            """)
        ).scalar_one()

        version_count = conn.execute(
            text("""
                SELECT COUNT(*)
                FROM Versions
            """)
        ).scalar_one()

    assert document_count == 1
    assert version_count == 2

#Test Get-Version API
def test_get_version_returns_pdf_for_valid_capability_link(
    document_api_app,
):
    client = document_api_app[
        "app"
    ].test_client()

    # This endpoint intentionally does not use a bearer token.
    response = client.get(
        "/api/get-version/owner-capability-link"
    )

    assert response.status_code == 200
    assert (
        response.data
        == document_api_app["owner_version_bytes"]
    )
    assert response.mimetype == "application/pdf"

    cache_control = response.headers.get(
        "Cache-Control",
        "",
    )

    assert "private" in cache_control
    assert "max-age=0" in cache_control


def test_get_version_rejects_unknown_capability_link(
    document_api_app,
):
    client = document_api_app[
        "app"
    ].test_client()

    response = client.get(
        "/api/get-version/unknown-link"
    )

    assert response.status_code == 404
    assert response.get_json() == {
        "error": "document not found"
    }


def test_get_version_rejects_path_outside_storage(
    document_api_app,
    tmp_path,
):
    client = document_api_app[
        "app"
    ].test_client()

    outside_file = tmp_path / "outside-version.pdf"
    outside_file.write_bytes(
        b"%PDF-outside-version"
    )

    with document_api_app[
        "engine"
    ].begin() as conn:
        conn.execute(
            text("""
                UPDATE Versions
                SET path = :path
                WHERE id = 10
            """),
            {
                "path": str(outside_file),
            },
        )

    response = client.get(
        "/api/get-version/owner-capability-link"
    )

    assert response.status_code == 500
    assert response.get_json() == {
        "error": "document path invalid"
    }


def test_get_version_reports_missing_file(
    document_api_app,
):
    client = document_api_app[
        "app"
    ].test_client()

    document_api_app[
        "owner_version"
    ].unlink()

    response = client.get(
        "/api/get-version/owner-capability-link"
    )

    assert response.status_code == 410
    assert response.get_json() == {
        "error": "file missing on disk"
    }

#Test plugin and watermark registry API
def test_load_plugin_requires_authentication(
    document_api_app,
):
    client = document_api_app[
        "app"
    ].test_client()

    response = client.post(
        "/api/load-plugin"
    )

    assert response.status_code == 401


def test_load_plugin_is_always_disabled(
    document_api_app,
):
    test_app = document_api_app["app"]
    client = test_app.test_client()

    token = make_token(test_app, user_id=100)

    response = client.post(
        "/api/load-plugin",
        json={
            "module": "unsafe_plugin",
        },
        headers=authorization_header(token),
    )

    assert response.status_code == 403
    assert response.get_json() == {
        "error": (
            "dynamic plugin loading is disabled "
            "for security reasons"
        )
    }


def test_get_watermarking_methods_returns_safe_registry(
    document_api_app,
):
    client = document_api_app[
        "app"
    ].test_client()

    response = client.get(
        "/api/get-watermarking-methods"
    )

    assert response.status_code == 200

    body = response.get_json()
    methods = {
        item["name"]
        for item in body["methods"]
    }

    assert body["count"] == len(
        body["methods"]
    )

    assert "toy-eof" in methods
    assert "layered-identity-v1" in methods
    assert "visible-text-watermark" in methods
    assert "bash-bridge-eof" not in methods


#Authenticate Test
@pytest.mark.parametrize(
    ("headers", "expected_error"),
    [
        (
            {},
            "Missing or invalid Authorization header",
        ),
        (
            {"Authorization": "Basic abc123"},
            "Missing or invalid Authorization header",
        ),
        (
            {"Authorization": "Bearer invalid-token"},
            "Invalid token",
        ),
    ],
)
def test_protected_api_rejects_invalid_authentication(
    tmp_path,
    headers,
    expected_error,
):
    test_app = create_app()
    test_app.config.update(
        TESTING=True,
        STORAGE_DIR=tmp_path,
    )

    client = test_app.test_client()

    response = client.get(
        "/api/list-documents",
        headers=headers,
    )

    assert response.status_code == 401
    assert response.get_json() == {
        "error": expected_error
    }

def test_delete_document_requires_authentication(
    prepared_delete_app,
):
    client = prepared_delete_app[
        "app"
    ].test_client()

    response = client.delete(
        "/api/delete-document/1"
    )

    assert response.status_code == 401


@pytest.mark.parametrize(
    ("payload", "expected_error"),
    [
        (
            {},
            "document id required",
        ),
        (
            {"id": "invalid"},
            "document id required",
        ),
        (
            {"id": 0},
            "document id must be positive",
        ),
        (
            {"id": -1},
            "document id must be positive",
        ),
    ],
)
def test_delete_document_validates_document_id(
    prepared_delete_app,
    payload,
    expected_error,
):
    test_app = prepared_delete_app["app"]
    client = test_app.test_client()

    token = make_token(test_app, user_id=100)

    response = client.post(
        "/api/delete-document",
        json=payload,
        headers=authorization_header(token),
    )

    assert response.status_code == 400
    assert response.get_json() == {
        "error": expected_error
    }


def test_delete_document_rejects_path_outside_storage(
    prepared_delete_app,
    tmp_path,
):
    test_app = prepared_delete_app["app"]
    client = test_app.test_client()

    outside_path = (
        tmp_path.parent
        / f"{tmp_path.name}-outside-document.pdf"
    )

    outside_path.write_bytes(
        b"%PDF-outside-storage"
    )

    try:
        with prepared_delete_app[
            "engine"
        ].begin() as conn:
            conn.execute(
                text("""
                    UPDATE Documents
                    SET path = :path
                    WHERE id = 1
                """),
                {
                    "path": str(outside_path),
                },
            )

        token = make_token(test_app, user_id=100)

        response = client.delete(
            "/api/delete-document/1",
            headers=authorization_header(token),
        )

        assert response.status_code == 500
        assert response.get_json() == {
            "error": "stored path invalid"
        }

        # No version files or database records
        # may be removed after path validation fails.
        assert prepared_delete_app[
            "version_one"
        ].exists()

        assert prepared_delete_app[
            "version_two"
        ].exists()

        with prepared_delete_app[
            "engine"
        ].connect() as conn:
            assert conn.execute(
                text("""
                    SELECT COUNT(*)
                    FROM Documents
                """)
            ).scalar_one() == 1

            assert conn.execute(
                text("""
                    SELECT COUNT(*)
                    FROM Versions
                """)
            ).scalar_one() == 2

    finally:
        outside_path.unlink(missing_ok=True)


def test_delete_document_rejects_directory_as_file(
    prepared_delete_app,
):
    test_app = prepared_delete_app["app"]
    client = test_app.test_client()

    storage_directory = (
        prepared_delete_app[
            "original_path"
        ].parent
    )

    with prepared_delete_app[
        "engine"
    ].begin() as conn:
        conn.execute(
            text("""
                UPDATE Documents
                SET path = :path
                WHERE id = 1
            """),
            {
                "path": str(storage_directory),
            },
        )

    token = make_token(test_app, user_id=100)

    response = client.delete(
        "/api/delete-document/1",
        headers=authorization_header(token),
    )

    assert response.status_code == 500
    assert response.get_json() == {
        "error": "stored path invalid"
    }

    assert prepared_delete_app[
        "version_one"
    ].exists()

    assert prepared_delete_app[
        "version_two"
    ].exists()


def test_delete_document_handles_files_already_missing(
    prepared_delete_app,
):
    test_app = prepared_delete_app["app"]
    client = test_app.test_client()

    prepared_delete_app[
        "original_path"
    ].unlink()

    prepared_delete_app[
        "version_one"
    ].unlink()

    prepared_delete_app[
        "version_two"
    ].unlink()

    token = make_token(test_app, user_id=100)

    response = client.delete(
        "/api/delete-document/1",
        headers=authorization_header(token),
    )

    assert response.status_code == 200

    body = response.get_json()

    assert body["deleted"] is True
    assert body["file_deleted"] == 0
    assert body["file_missing"] == 3
    assert body["cleanup_pending"] == 0

    with prepared_delete_app[
        "engine"
    ].connect() as conn:
        assert conn.execute(
            text("""
                SELECT COUNT(*)
                FROM Documents
            """)
        ).scalar_one() == 0

        assert conn.execute(
            text("""
                SELECT COUNT(*)
                FROM Versions
            """)
        ).scalar_one() == 0


def test_delete_document_keeps_database_when_staging_fails(
    prepared_delete_app,
    monkeypatch,
):
    test_app = prepared_delete_app["app"]
    client = test_app.test_client()

    original_path = prepared_delete_app[
        "original_path"
    ]

    real_replace = server_module.Path.replace

    def fail_original_rename(
        path_object,
        target,
    ):
        if path_object == original_path:
            raise OSError(
                "forced staging failure"
            )

        return real_replace(
            path_object,
            target,
        )

    monkeypatch.setattr(
        server_module.Path,
        "replace",
        fail_original_rename,
    )

    token = make_token(test_app, user_id=100)

    response = client.delete(
        "/api/delete-document/1",
        headers=authorization_header(token),
    )

    assert response.status_code == 500
    assert response.get_json() == {
        "error": "file deletion failed"
    }

    assert prepared_delete_app[
        "original_path"
    ].exists()

    assert prepared_delete_app[
        "version_one"
    ].exists()

    assert prepared_delete_app[
        "version_two"
    ].exists()

    with prepared_delete_app[
        "engine"
    ].connect() as conn:
        assert conn.execute(
            text("""
                SELECT COUNT(*)
                FROM Documents
            """)
        ).scalar_one() == 1

        assert conn.execute(
            text("""
                SELECT COUNT(*)
                FROM Versions
            """)
        ).scalar_one() == 2


def test_delete_document_restores_files_when_database_delete_fails(
    prepared_delete_app,
):
    test_app = prepared_delete_app["app"]
    client = test_app.test_client()

    # Force the DELETE statement to fail after all
    # files have already been staged by rename.
    with prepared_delete_app[
        "engine"
    ].begin() as conn:
        conn.execute(text("""
            CREATE TRIGGER prevent_document_delete
            BEFORE DELETE ON Documents
            BEGIN
                SELECT RAISE(
                    ABORT,
                    'forced delete failure'
                );
            END
        """))

    token = make_token(test_app, user_id=100)

    response = client.delete(
        "/api/delete-document/1",
        headers=authorization_header(token),
    )

    assert response.status_code == 503

    assert response.get_json() == {
        "error": "database error during delete:"
    }

    # Every staged file must be restored to its
    # original path after DB rollback.
    assert prepared_delete_app[
        "original_path"
    ].exists()

    assert prepared_delete_app[
        "version_one"
    ].exists()

    assert prepared_delete_app[
        "version_two"
    ].exists()

    storage_root = prepared_delete_app[
        "original_path"
    ].parent

    staged_files = list(
        storage_root.rglob(
            ".tatou-delete-*"
        )
    )

    assert staged_files == []

    with prepared_delete_app[
        "engine"
    ].connect() as conn:
        assert conn.execute(
            text("""
                SELECT COUNT(*)
                FROM Documents
            """)
        ).scalar_one() == 1

        assert conn.execute(
            text("""
                SELECT COUNT(*)
                FROM Versions
            """)
        ).scalar_one() == 2