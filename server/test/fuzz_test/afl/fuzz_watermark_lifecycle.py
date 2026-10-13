import argparse
import io
import json
import os
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

import afl
import fitz
from itsdangerous import URLSafeTimedSerializer
from sqlalchemy import create_engine, event, text
from sqlalchemy.pool import StaticPool

from lifecycle_mutator import DEFAULT, encode, valid_case

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / "server" / "src"))
TEST_SECRET = "afl-lifecycle-test-only-secret"
TEST_PASSWORD = "AflLifecycleOnly123!"
TEST_EMAIL = "lifecycle@example.test"
METHOD = "layered-identity-v1"
os.environ["SECRET_KEY"] = TEST_SECRET
_import_storage = TemporaryDirectory(prefix="tatou-afl-import-")
os.environ["STORAGE_DIR"] = _import_storage.name
for _name in (
    "RMAP_SERVER_PUBLIC_KEY_PATH", "RMAP_SERVER_PRIVATE_KEY_PATH",
    "RMAP_PRIVATE_KEY_PASSPHRASE", "RMAP_IDENTITIES_DIR", "RMAP_DOCUMENT_ID",
    "WATERMARK_HMAC_KEY",
):
    os.environ.pop(_name, None)

import server as server_module  # noqa: E402


def database():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:", poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )

    @event.listens_for(engine, "connect")
    def functions(dbapi, record):
        dbapi.execute("PRAGMA foreign_keys=ON")
        record.info["last_insert_id"] = 0
        dbapi.create_function("UNHEX", 1, lambda value: bytes.fromhex(value))
        dbapi.create_function("LAST_INSERT_ID", 0,
                              lambda: record.info["last_insert_id"])

    @event.listens_for(engine, "after_cursor_execute")
    def remember_id(connection, cursor, statement, params, context, many):
        if statement.lstrip().upper().startswith("INSERT"):
            connection.info["last_insert_id"] = cursor.lastrowid

    with engine.begin() as conn:
        for ddl in (
            """CREATE TABLE Users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE, hpassword TEXT NOT NULL,
                login TEXT NOT NULL)""",
            """CREATE TABLE Documents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL, path TEXT NOT NULL UNIQUE,
                ownerid INTEGER NOT NULL REFERENCES Users(id) ON DELETE CASCADE,
                creation TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                sha256 BLOB NOT NULL, size INTEGER NOT NULL)""",
            """CREATE TABLE Versions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                documentid INTEGER NOT NULL REFERENCES Documents(id) ON DELETE CASCADE,
                link TEXT NOT NULL UNIQUE, intended_for TEXT, secret TEXT NOT NULL,
                method TEXT NOT NULL, position TEXT, path TEXT NOT NULL)""",
        ):
            conn.execute(text(ddl))
    return engine


def make_pdf(case):
    width, height = {"a4": (595, 842), "landscape": (842, 595),
                     "small": (300, 400)}[case["size"]]
    with fitz.open() as doc:
        for _ in range(case["pages"]):
            page = doc.new_page(width=width, height=height)
            page.insert_text((40, 80), case["text"], fontsize=10)
            page.set_rotation(case["rotation"])
        return doc.tobytes()


def check_one(path, verbose=False):
    raw = Path(path).read_bytes()
    if len(raw) > 4096:
        raise ValueError("Input too large; run AFL with -G 4096")
    # Invalid scenario descriptors are harness inputs, not API failures.
    try:
        case = json.loads(raw)
        valid = valid_case(case)
    except (ValueError, UnicodeError, RecursionError, TypeError):
        valid = False
    if not valid:
        if verbose:
            raise ValueError("Invalid scenario; use the supplied lifecycle mutator")
        return False

    stage = "setup"
    engine = database()
    try:
        with TemporaryDirectory(prefix="tatou-afl-lifecycle-") as folder:
            storage = Path(folder)
            app = server_module.create_app()
            app.config.update(TESTING=True, PROPAGATE_EXCEPTIONS=False,
                              STORAGE_DIR=storage, _ENGINE=engine)
            app.logger.disabled = not verbose

            def expect(response, status):
                assert response.status_code == status, (
                    f"stage={stage}; expected={status}; actual={response.status_code}; "
                    f"response={response.get_data(as_text=True)[:1500]!r}; case={case!r}"
                )
                if verbose:
                    print(f"STEP_OK {stage}: status={status}")
                return response

            def body(response, status):
                expect(response, status)
                assert response.is_json, f"stage={stage}: expected JSON"
                result = response.get_json()
                assert isinstance(result, dict), f"stage={stage}: expected object"
                return result

            with app.test_client() as client:
                stage = "create-user"
                user = body(client.post("/api/create-user", json={
                    "email": TEST_EMAIL, "login": "afl-lifecycle",
                    "password": TEST_PASSWORD,
                }), 201)
                uid = user["id"]

                stage = "login"
                logged = body(client.post("/api/login", json={
                    "email": TEST_EMAIL, "password": TEST_PASSWORD,
                }), 200)
                token = logged["token"]
                claims = URLSafeTimedSerializer(TEST_SECRET, salt="tatou-auth").loads(
                    token, max_age=3600,
                )
                assert claims["uid"] == uid and claims["email"] == TEST_EMAIL
                auth = {"Authorization": "Bearer " + token}

                stage = "upload-document"
                original = make_pdf(case)
                uploaded = body(client.post("/api/upload-document", headers=auth,
                    data={"file": (io.BytesIO(original), case["filename"], "application/pdf")},
                    content_type="multipart/form-data"), 201)
                did = uploaded["id"]

                stage = "create-watermark"
                created = body(client.post(f"/api/create-watermark/{did}", headers=auth,
                    json={"method": METHOD, "intended_for": case["intended_for"],
                          "secret": case["secret"], "key": case["key"],
                          "position": case["position"]}), 201)
                vid, link = created["id"], created["link"]
                assert created["documentid"] == did and isinstance(link, str) and link

                stage = "list-versions"
                versions = body(client.get(f"/api/list-versions/{did}", headers=auth), 200)
                assert len(versions["versions"]) == 1
                assert versions["versions"][0]["id"] == vid
                assert versions["versions"][0]["secret"] == case["secret"]

                stage = "download-version"
                response = expect(client.get(f"/api/get-version/{link}"), 200)
                downloaded = response.get_data()
                response.close()
                assert downloaded.startswith(b"%PDF-")
                with fitz.open(stream=downloaded, filetype="pdf") as doc:
                    assert doc.page_count == case["pages"]

                stage = "read-watermark"
                read_body = {"document_id": did, "version_id": vid, "key": case["key"]}
                recovered = body(client.post("/api/read-watermark", headers=auth,
                                              json=read_body), 200)
                assert recovered["secret"] == case["secret"], f"stage={stage}: secret mismatch"

                stage = "wrong-key"
                wrong = body(client.post("/api/read-watermark", headers=auth,
                    json={**read_body, "key": case["key"] + "-wrong"}), 400)
                assert "secret" not in wrong

                stage = "original-unchanged"
                response = expect(client.get(f"/api/get-document/{did}", headers=auth), 200)
                assert response.get_data() == original
                response.close()

                with engine.connect() as conn:
                    paths = [Path(conn.execute(text(
                        "SELECT path FROM Documents WHERE id=:id"
                    ), {"id": did}).scalar_one()), Path(conn.execute(text(
                        "SELECT path FROM Versions WHERE id=:id"
                    ), {"id": vid}).scalar_one())]
                assert all(path.is_file() for path in paths)

                stage = "delete-document"
                deleted = body(client.delete(f"/api/delete-document/{did}", headers=auth), 200)
                assert deleted.get("deleted") is True
                assert deleted.get("cleanup_pending", 0) == 0

                stage = "deleted-link"
                expect(client.get(f"/api/get-version/{link}"), 404)
                stage = "deleted-original"
                expect(client.get(f"/api/get-document/{did}", headers=auth), 404)
                stage = "empty-document-list"
                listed = body(client.get("/api/list-documents", headers=auth), 200)
                assert listed["documents"] == []

            stage = "cleanup"
            with engine.connect() as conn:
                for table in ("Documents", "Versions"):
                    assert conn.execute(text(f"SELECT COUNT(*) FROM {table}")).scalar_one() == 0
            assert all(not path.exists() for path in paths)
            assert not any(path.is_file() for path in storage.rglob("*")), "Residual files after deletion"
            if verbose:
                print(f"LIFECYCLE_OK pages={case['pages']} position={case['position']}")
            return True
    except Exception as exc:
        raise AssertionError(f"Lifecycle failed at stage={stage}; case={case!r}") from exc
    finally:
        engine.dispose()


def prepare(directory):
    root = Path(directory)
    root.mkdir(parents=True, exist_ok=True)
    seeds = [dict(DEFAULT), {**DEFAULT, "pages": 2, "position": "header"},
             {**DEFAULT, "pages": 3, "position": "footer", "rotation": 90,
              "size": "landscape", "secret": "recipient:测试"}]
    for index, case in enumerate(seeds):
        path = root / f"normal_{index}.json"
        raw = encode(case)
        if path.exists() and path.read_bytes() != raw:
            raise FileExistsError(f"Seed differs: {path}")
        path.write_bytes(raw)
        print(f"Checking {path.name}")
        check_one(path, verbose=True)
    print("ALL_LIFECYCLE_SEEDS_OK count=3")


def main():
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--prepare", action="store_true")
    mode.add_argument("--replay", action="store_true")
    parser.add_argument("path")
    args = parser.parse_args()
    if args.prepare:
        prepare(args.path)
        _import_storage.cleanup()
        return
    if args.replay:
        check_one(args.path, verbose=True)
        _import_storage.cleanup()
        return
    afl.init()
    check_one(args.path)
    os._exit(0)


if __name__ == "__main__":
    main()
