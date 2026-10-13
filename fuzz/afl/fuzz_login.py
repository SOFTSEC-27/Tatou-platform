"""AFL login request-body campaign using an empty SQLite database.

Place at <repo>/fuzz/afl/fuzz_login.py. No live HTTP server is used.
Replay: python fuzz/afl/fuzz_login.py --replay input.json
Fuzz: py-afl-fuzz -i seeds -o findings -- python fuzz/afl/fuzz_login.py @@

Scope: raw JSON parsing, field validation and unknown-user lookup.
An empty database means this campaign cannot test successful authentication
or password-hash verification against an existing account.
"""

import argparse
import logging
import os
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

import afl
from sqlalchemy import create_engine, text
from sqlalchemy.pool import StaticPool


REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "server" / "src"))
# Set test configuration BEFORE importing server, which creates a WSGI app.
os.environ["SECRET_KEY"] = "afl-login-test-only-secret"
_storage = TemporaryDirectory(prefix="tatou-afl-login-")
os.environ["STORAGE_DIR"] = _storage.name
for _name in (
    "RMAP_SERVER_PUBLIC_KEY_PATH", "RMAP_SERVER_PRIVATE_KEY_PATH",
    "RMAP_PRIVATE_KEY_PASSPHRASE", "RMAP_IDENTITIES_DIR",
    "RMAP_DOCUMENT_ID", "WATERMARK_HMAC_KEY",
):
    os.environ.pop(_name, None)

from server import create_app  # noqa: E402


APP = create_app()
APP.config.update(TESTING=True, PROPAGATE_EXCEPTIONS=False)
APP.logger.disabled = True
logging.getLogger("sqlalchemy.engine").setLevel(logging.CRITICAL)


def check_one(input_path):
    raw = Path(input_path).read_bytes()
    if len(raw) > 4096:
        raise ValueError("Campaign input limit is 4096 bytes; use afl-fuzz -G 4096")

    # Construct database connections in the child AFTER afl.init(), rather
    # than inheriting an open database connection from the forkserver.
    engine = create_engine(
        "sqlite+pysqlite:///:memory:", poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    try:
        with engine.begin() as conn:
            conn.execute(text("""
                CREATE TABLE Users (
                    id INTEGER PRIMARY KEY,
                    email TEXT NOT NULL UNIQUE,
                    login TEXT NOT NULL UNIQUE,
                    hpassword TEXT NOT NULL
                )
            """))
        APP.config["_ENGINE"] = engine

        with APP.test_client() as client:
            response = client.post(
                "/api/login", data=raw, content_type="application/json",
            )

        detail = (
            f"body={raw!r}; status={response.status_code}; "
            f"response={response.get_data(as_text=True)!r}"
        )
        assert response.status_code in (400, 401), detail
        assert response.is_json, detail
        body = response.get_json()
        assert isinstance(body, dict), detail
        assert isinstance(body.get("error"), str) and body["error"], detail
        assert "token" not in body, detail

        # Login requests must leave the initially empty user table empty.
        with engine.connect() as conn:
            assert conn.execute(text("SELECT COUNT(*) FROM Users")).scalar_one() == 0
        return response.status_code
    finally:
        APP.config.pop("_ENGINE", None)
        engine.dispose()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--replay", action="store_true")
    parser.add_argument("input_path")
    args = parser.parse_args()

    if args.replay:
        status = check_one(args.input_path)
        print(f"REPLAY_OK status={status}")
        _storage.cleanup()
        return

    afl.init()
    check_one(args.input_path)
    # Successful cases exit normally. Assertions remain unhandled so the
    # python-afl exception hook can report them as crash signals to AFL.
    os._exit(0)


if __name__ == "__main__":
    main()
