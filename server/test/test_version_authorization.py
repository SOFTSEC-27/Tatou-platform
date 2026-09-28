from itsdangerous import URLSafeTimedSerializer
from sqlalchemy import create_engine, text

from server import create_app


def make_token(app, user_id: int, login: str, email: str) -> str:
    serializer = URLSafeTimedSerializer(
        app.config["SECRET_KEY"],
        salt="tatou-auth",
    )
    return serializer.dumps({
        "uid": user_id,
        "login": login,
        "email": email,
    })


def authorization_header(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def create_test_app(tmp_path):
    app = create_app()
    app.config.update(
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
                id INTEGER PRIMARY KEY,
                email TEXT NOT NULL,
                login TEXT NOT NULL
            )
        """))

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
                link TEXT NOT NULL,
                intended_for TEXT,
                secret TEXT,
                method TEXT
            )
        """))

        # Deliberately use the same login to reproduce the old vulnerability.
        conn.execute(text("""
            INSERT INTO Users (id, email, login) VALUES
                (1, 'owner@example.test', 'duplicate-login'),
                (2, 'attacker@example.test', 'duplicate-login')
        """))

        conn.execute(text("""
            INSERT INTO Documents (id, name, path, ownerid) VALUES
                (101, 'owner.pdf', '/tmp/owner.pdf', 1),
                (202, 'attacker.pdf', '/tmp/attacker.pdf', 2)
        """))

        conn.execute(text("""
            INSERT INTO Versions (
                id,
                documentid,
                link,
                intended_for,
                secret,
                method
            ) VALUES
                (
                    1001,
                    101,
                    'owner-private-link',
                    'owner-recipient',
                    'owner-secret',
                    'layered-identity-v1'
                ),
                (
                    2002,
                    202,
                    'attacker-private-link',
                    'attacker-recipient',
                    'attacker-secret',
                    'layered-identity-v1'
                )
        """))

    app.config["_ENGINE"] = engine
    return app, engine


def test_list_all_versions_uses_user_id_not_login(tmp_path):
    app, engine = create_test_app(tmp_path)

    try:
        client = app.test_client()

        attacker_token = make_token(
            app,
            user_id=2,
            login="duplicate-login",
            email="attacker@example.test",
        )

        response = client.get(
            "/api/list-all-versions",
            headers=authorization_header(attacker_token),
        )

        assert response.status_code == 200

        body = response.get_json()
        links = {version["link"] for version in body["versions"]}

        assert links == {"attacker-private-link"}
        assert "owner-private-link" not in links
        assert "owner-secret" not in response.get_data(as_text=True)
        assert "attacker-secret" not in response.get_data(as_text=True)
    finally:
        engine.dispose()


def test_list_versions_rejects_other_users_document(tmp_path):
    app, engine = create_test_app(tmp_path)

    try:
        client = app.test_client()

        attacker_token = make_token(
            app,
            user_id=2,
            login="duplicate-login",
            email="attacker@example.test",
        )

        response = client.get(
            "/api/list-versions/101",
            headers=authorization_header(attacker_token),
        )

        assert response.status_code == 200
        assert response.get_json() == {"versions": []}
        assert "owner-private-link" not in response.get_data(as_text=True)
        assert "owner-secret" not in response.get_data(as_text=True)
    finally:
        engine.dispose()