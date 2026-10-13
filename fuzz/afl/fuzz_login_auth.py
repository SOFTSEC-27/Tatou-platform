"""AFL login campaign with one known account and an authentication oracle.

Place at <repo>/fuzz/afl/fuzz_login_auth.py.
Prepare: python fuzz/afl/fuzz_login_auth.py --prepare fuzz/afl/seeds_login_auth
Replay:  python fuzz/afl/fuzz_login_auth.py --replay input.json
Fuzz: py-afl-fuzz -i seeds -o findings -G 4096 -- python fuzz_login_auth.py @@

Scope: request parsing, known/unknown accounts, real password-hash checking,
and the returned token's signature and identity. Uses SQLite, not live MariaDB.
The oracle uses the API's existing email.strip() normalization; passwords
are compared exactly. Token expiration and protected routes are not tested.
"""

import argparse
import json
import logging
import os
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

import afl
from itsdangerous import URLSafeTimedSerializer
from sqlalchemy import create_engine, text
from sqlalchemy.pool import StaticPool
from werkzeug.security import generate_password_hash


TEST_SECRET = "afl-login-auth-test-only-secret"
ACCOUNT_ID = 1
ACCOUNT_EMAIL = "afl-user@example.test"
ACCOUNT_LOGIN = "afl-user"
ACCOUNT_PASSWORD = "AflTestOnly123!"
TOKEN_TTL = 3600

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "server" / "src"))
os.environ["SECRET_KEY"] = TEST_SECRET
_storage = TemporaryDirectory(prefix="tatou-afl-auth-")
os.environ["STORAGE_DIR"] = _storage.name
for _name in (
    "RMAP_SERVER_PUBLIC_KEY_PATH", "RMAP_SERVER_PRIVATE_KEY_PATH",
    "RMAP_PRIVATE_KEY_PASSPHRASE", "RMAP_IDENTITIES_DIR",
    "RMAP_DOCUMENT_ID", "WATERMARK_HMAC_KEY",
):
    os.environ.pop(_name, None)

from server import create_app  # noqa: E402


APP = create_app()
APP.config.update(
    TESTING=True, PROPAGATE_EXCEPTIONS=False, TOKEN_TTL_SECONDS=TOKEN_TTL,
)
APP.logger.disabled = True
logging.getLogger("sqlalchemy.engine").setLevel(logging.CRITICAL)

# Compute using Werkzeug's default password-hashing method, before starting
# the forkserver. Keep this one hash fixed throughout the campaign.
ACCOUNT_HASH = generate_password_hash(ACCOUNT_PASSWORD)
TOKEN_READER = URLSafeTimedSerializer(TEST_SECRET, salt="tatou-auth")


def expected_status(raw):
    """Independent plain-value oracle, without calling password-hash code."""
    try:
        payload = json.loads(raw)
    except (ValueError, UnicodeError, RecursionError):
        return 400
    if not isinstance(payload, dict):
        return 400
    email = payload.get("email")
    password = payload.get("password")
    if not isinstance(email, str) or not isinstance(password, str):
        return 400
    email = email.strip()
    if not email or not password:
        return 400
    if email == ACCOUNT_EMAIL and password == ACCOUNT_PASSWORD:
        return 200
    return 401


def check_one(input_path):
    raw = Path(input_path).read_bytes()
    if len(raw) > 4096:
        raise ValueError("Input limit is 4096 bytes; use afl-fuzz -G 4096")
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
            conn.execute(text("""
                INSERT INTO Users (id, email, login, hpassword)
                VALUES (:id, :email, :login, :hpassword)
            """), {
                "id": ACCOUNT_ID, "email": ACCOUNT_EMAIL,
                "login": ACCOUNT_LOGIN, "hpassword": ACCOUNT_HASH,
            })
        APP.config["_ENGINE"] = engine
        with APP.test_client() as client:
            response = client.post(
                "/api/login", data=raw, content_type="application/json",
            )

        expected = expected_status(raw)
        detail = (
            f"body={raw!r}; expected={expected}; "
            f"actual={response.status_code}; "
            f"response={response.get_data(as_text=True)!r}"
        )
        assert response.status_code == expected, detail
        assert response.is_json, detail
        body = response.get_json()
        assert isinstance(body, dict), detail
        if expected == 200:
            token = body.get("token")
            assert isinstance(token, str) and token, detail
            claims = TOKEN_READER.loads(token, max_age=TOKEN_TTL)
            assert claims == {
                "uid": ACCOUNT_ID, "login": ACCOUNT_LOGIN,
                "email": ACCOUNT_EMAIL,
            }, detail
            assert body.get("token_type") == "bearer", detail
            assert body.get("expires_in") == TOKEN_TTL, detail
            assert "error" not in body, detail
        else:
            assert "token" not in body, detail
            assert isinstance(body.get("error"), str) and body["error"], detail

        with engine.connect() as conn:
            rows = conn.execute(text(
                "SELECT id, email, login, hpassword FROM Users ORDER BY id"
            )).all()
        assert [tuple(row) for row in rows] == [(
            ACCOUNT_ID, ACCOUNT_EMAIL, ACCOUNT_LOGIN, ACCOUNT_HASH,
        )], "Login unexpectedly modified the test account"
        return expected, response.status_code
    finally:
        APP.config.pop("_ENGINE", None)
        engine.dispose()


def prepare_seeds(directory):
    root = Path(directory)
    root.mkdir(parents=True, exist_ok=True)
    seeds = {
        "correct.json": {"email": ACCOUNT_EMAIL, "password": ACCOUNT_PASSWORD},
        "wrong_password.json": {"email": ACCOUNT_EMAIL, "password": "wrong"},
        "unknown_account.json": {"email": "nobody@example.test", "password": ACCOUNT_PASSWORD},
        "trimmed_email.json": {"email": " " + ACCOUNT_EMAIL + " ", "password": ACCOUNT_PASSWORD},
        "password_space.json": {"email": ACCOUNT_EMAIL, "password": " " + ACCOUNT_PASSWORD},
        "unicode_wrong_password.json": {"email": ACCOUNT_EMAIL, "password": "测试密码"},
        "wrong_type.json": {"email": ACCOUNT_EMAIL, "password": [ACCOUNT_PASSWORD]},
        "missing_fields.json": {},
        "boolean.json": True,
        "array.json": [],
    }
    files = []
    for name, body in seeds.items():
        path = root / name
        raw = json.dumps(body, ensure_ascii=True).encode("utf-8")
        if path.exists():
            if path.read_bytes() != raw:
                raise FileExistsError(f"Seed differs; use a fresh directory: {path}")
        else:
            path.write_bytes(raw)
        files.append(path)
    malformed = root / "malformed.json"
    if malformed.exists():
        if malformed.read_bytes() != b'{"email":':
            raise FileExistsError(f"Seed differs: {malformed}")
    else:
        malformed.write_bytes(b'{"email":')
    files.append(malformed)
    # Validate baseline inputs before asking AFL to mutate them. Replay mode
    # enables Flask exception logs to help distinguish setup from API failures.
    APP.logger.disabled = False
    for path in files:
        expected, actual = check_one(path)
        print(f"SEED_OK {path.name}: expected={expected} actual={actual}")
    print(f"ALL_SEEDS_OK count={len(files)}")


def main():
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--prepare", action="store_true")
    mode.add_argument("--replay", action="store_true")
    parser.add_argument("path")
    args = parser.parse_args()
    if args.prepare:
        prepare_seeds(args.path)
        _storage.cleanup()
        return
    if args.replay:
        APP.logger.disabled = False
        expected, actual = check_one(args.path)
        print(f"REPLAY_OK expected={expected} actual={actual}")
        _storage.cleanup()
        return

    afl.init()
    check_one(args.path)
    os._exit(0)


if __name__ == "__main__":
    main()
