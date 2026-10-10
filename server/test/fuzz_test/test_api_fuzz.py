import json

from hypothesis import given, settings, example, strategies as st
from server import create_app
from types import SimpleNamespace
from unittest.mock import MagicMock
from werkzeug.security import generate_password_hash
from itsdangerous import URLSafeTimedSerializer

non_object_json = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(-10, 10),
    st.text(max_size=32),
    st.lists(st.integers(-10, 10), max_size=5),
)

@settings(max_examples=100, deadline=None)
@example(body=True)
@given(body=non_object_json)
def test_login_rejects_non_object_json(body):
    app = create_app()
    app.config.update(
        TESTING=True,
        PROPAGATE_EXCEPTIONS=False,
    )

    with app.test_client() as client:
        response = client.post(
            "/api/login",
            data=json.dumps(body),
            content_type="application/json",
        )

    assert response.status_code == 400, (
        f"body={body!r}, status={response.status_code}, "
        f"response={response.get_data(as_text=True)}"
    )

    assert response.is_json
    result = response.get_json()
    assert isinstance(result, dict)
    assert "error" in result
    assert "token" not in result

non_string_email = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(-10, 10),
    st.lists(st.integers(-10, 10), max_size=5),
    st.dictionaries(
        keys=st.text(max_size=8),
        values=st.integers(-10, 10),
        max_size=3,
    ),
)


@settings(max_examples=100, deadline=None)
@example(email=True)
@given(email=non_string_email)
def test_login_rejects_non_string_email(email):
    app = create_app()
    app.config.update(
        TESTING=True,
        PROPAGATE_EXCEPTIONS=False,
    )

    with app.test_client() as client:
        response = client.post(
            "/api/login",
            data=json.dumps({
                "email": email,
                "password": "test-password",
            }),
            content_type="application/json",
        )

    assert response.status_code == 400, (
        f"email={email!r}, status={response.status_code}, "
        f"response={response.get_data(as_text=True)}"
    )
    assert response.is_json
    result = response.get_json()
    assert isinstance(result, dict)
    assert "error" in result
    assert "token" not in result

def test_login_rejects_non_string_password():
    user = SimpleNamespace(
        id=1,
        email="existing@example.test",
        login="existing-user",
        hpassword=generate_password_hash("CorrectPassword123!"),
    )

    @settings(max_examples=100, deadline=None)
    @example(password=True)
    @given(password=non_string_email)
    def check_password_type(password):
        engine = MagicMock()
        connection = engine.connect.return_value.__enter__.return_value
        connection.execute.return_value.first.return_value = user

        app = create_app()
        app.config.update(
            TESTING=True,
            PROPAGATE_EXCEPTIONS=False,
            _ENGINE=engine,
        )

        with app.test_client() as client:
            response = client.post(
                "/api/login",
                data=json.dumps({
                    "email": user.email,
                    "password": password,
                }),
                content_type="application/json",
            )

        assert response.status_code == 400, (
            f"password={password!r}, status={response.status_code}, "
            f"response={response.get_data(as_text=True)}"
        )
        assert response.is_json
        result = response.get_json()
        assert isinstance(result, dict)
        assert "error" in result
        assert "token" not in result

    check_password_type()

@settings(max_examples=100, deadline=None)
@example(body=1)
@given(body=non_object_json)
def test_create_user_rejects_non_object_json(body):
    app = create_app()
    app.config.update(
        TESTING=True,
        PROPAGATE_EXCEPTIONS=False,
    )

    with app.test_client() as client:
        response = client.post(
            "/api/create-user",
            data=json.dumps(body),
            content_type="application/json",
        )

    assert response.status_code == 400, (
        f"body={body!r}, status={response.status_code}, "
        f"response={response.get_data(as_text=True)}"
    )
    assert response.is_json
    result = response.get_json()
    assert isinstance(result, dict)
    assert "error" in result

invalid_document_id = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(-10, 10).map(lambda number: number + 0.5),
    st.text(alphabet="abcXYZ", max_size=16),
    st.lists(st.integers(-10, 10), max_size=3),
    st.dictionaries(st.text(max_size=8), st.integers(-10, 10), max_size=3),
)


@settings(max_examples=100, deadline=None)
@example(document_id=1.5)
@example(document_id=True)
@given(document_id=invalid_document_id)
def test_delete_document_rejects_invalid_id(document_id):
    app = create_app()
    engine = MagicMock()
    connection = engine.connect.return_value.__enter__.return_value
    connection.execute.return_value.first.return_value = None
    app.config.update(TESTING=True, PROPAGATE_EXCEPTIONS=False, _ENGINE=engine)

    serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="tatou-auth")
    token = serializer.dumps({"uid": 1, "login": "fuzz-user", "email": "fuzz@example.test"})

    with app.test_client() as client:
        response = client.delete(
            "/api/delete-document",
            data=json.dumps({"id": document_id}),
            content_type="application/json",
            headers={"Authorization": f"Bearer {token}"},
        )

    assert response.status_code == 400, (
        f"id={document_id!r}, status={response.status_code}, "
        f"database_called={engine.connect.called}, response={response.get_data(as_text=True)}"
    )
    assert response.is_json
    result = response.get_json()
    assert isinstance(result, dict)
    assert "error" in result
    engine.connect.assert_not_called()
    engine.begin.assert_not_called()

@settings(max_examples=100, deadline=None)
@example(body=True)
@example(body=1)
@given(body=non_object_json)
def test_delete_document_rejects_non_object_json(body):
    app = create_app()
    engine = MagicMock()
    app.config.update(
        TESTING=True,
        PROPAGATE_EXCEPTIONS=False,
        _ENGINE=engine,
    )

    serializer = URLSafeTimedSerializer(
        app.config["SECRET_KEY"],
        salt="tatou-auth",
    )
    token = serializer.dumps({
        "uid": 1,
        "login": "fuzz-user",
        "email": "fuzz@example.test",
    })

    with app.test_client() as client:
        response = client.delete(
            "/api/delete-document",
            data=json.dumps(body),
            content_type="application/json",
            headers={"Authorization": f"Bearer {token}"},
        )

    assert response.status_code == 400, (
        f"body={body!r}, status={response.status_code}, "
        f"response={response.get_data(as_text=True)}"
    )
    assert response.is_json
    result = response.get_json()
    assert isinstance(result, dict)
    assert "error" in result
    engine.connect.assert_not_called()
    engine.begin.assert_not_called()

invalid_document_query_id = st.one_of(
    st.integers(-10, 0).map(str),
    st.text(alphabet="abcXYZ", max_size=16),
    st.integers(-10, 10).map(lambda number: f"{number}.5"),
)


@settings(max_examples=100, deadline=None)
@example(document_id="0")
@given(document_id=invalid_document_query_id)
def test_get_document_rejects_invalid_id(document_id):
    app = create_app()
    engine = MagicMock()
    connection = engine.connect.return_value.__enter__.return_value
    connection.execute.return_value.first.return_value = None

    app.config.update(
        TESTING=True,
        PROPAGATE_EXCEPTIONS=False,
        _ENGINE=engine,
    )

    serializer = URLSafeTimedSerializer(
        app.config["SECRET_KEY"],
        salt="tatou-auth",
    )
    token = serializer.dumps({
        "uid": 1,
        "login": "fuzz-user",
        "email": "fuzz@example.test",
    })

    with app.test_client() as client:
        response = client.get(
            "/api/get-document",
            query_string={"id": document_id},
            headers={"Authorization": f"Bearer {token}"},
        )

    assert response.status_code == 400, (
        f"id={document_id!r}, status={response.status_code}, "
        f"database_called={engine.connect.called}, "
        f"response={response.get_data(as_text=True)}"
    )
    assert response.is_json
    result = response.get_json()
    assert isinstance(result, dict)
    assert "error" in result
    engine.connect.assert_not_called()

@settings(max_examples=100, deadline=None)
@example(email=True)
@given(email=non_string_email)
def test_create_user_rejects_non_string_email(email):
    app = create_app()
    engine = MagicMock()
    app.config.update(
        TESTING=True,
        PROPAGATE_EXCEPTIONS=False,
        _ENGINE=engine,
    )

    with app.test_client() as client:
        response = client.post(
            "/api/create-user",
            data=json.dumps({
                "email": email,
                "login": "fuzz-user",
                "password": "StrongPassword123!",
            }),
            content_type="application/json",
        )

    assert response.status_code == 400, (
        f"email={email!r}, status={response.status_code}, "
        f"response={response.get_data(as_text=True)}"
    )
    assert response.is_json
    result = response.get_json()
    assert isinstance(result, dict)
    assert "error" in result
    engine.connect.assert_not_called()
    engine.begin.assert_not_called()