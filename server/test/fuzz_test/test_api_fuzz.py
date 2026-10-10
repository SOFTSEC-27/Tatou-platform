import json

from hypothesis import given, settings, example, strategies as st
from server import create_app

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