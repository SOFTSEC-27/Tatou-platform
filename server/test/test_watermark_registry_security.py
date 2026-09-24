from server import create_app
import watermarking_utils as WMUtils


def test_unsafe_bash_bridge_is_not_registered():
    assert "bash-bridge-eof" not in WMUtils.METHODS


def test_watermark_methods_api_does_not_expose_bash_bridge():
    app = create_app()
    app.config.update(TESTING=True)

    client = app.test_client()
    response = client.get("/api/get-watermarking-methods")

    assert response.status_code == 200

    body = response.get_json()

    method_names = {
        method["name"]
        for method in body["methods"]
    }

    assert "bash-bridge-eof" not in method_names