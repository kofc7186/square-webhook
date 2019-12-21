# pylint: disable=redefined-outer-name,unused-argument,no-member

import flask
import pytest

from werkzeug.exceptions import BadRequest, UnsupportedMediaType, MethodNotAllowed

import main

# Create a fake "app" for generating test request contexts.
@pytest.fixture(scope="module")
def app():
    return flask.Flask(__name__)


KEY = "abc123def456"
@pytest.fixture
def mock_set_env_webhook_signature_key(monkeypatch):
    monkeypatch.setenv("SQUARE_WEBHOOK_SIGNATURE_KEY", KEY)
    monkeypatch.setenv("FUNCTION_NAME", "test_handle_webhook_valid")


def test_handle_webhook_empty_webhook_key(app, monkeypatch):
    monkeypatch.delenv("SQUARE_WEBHOOK_SIGNATURE_KEY", raising=False)
    with app.test_request_context(method='POST', json={}):
        with pytest.raises(KeyError):
            main.handle_webhook(flask.request)


def test_handle_webhook_invalid_method(app, mock_set_env_webhook_signature_key):
    with app.test_request_context(method='GET'):
        with pytest.raises(MethodNotAllowed):
            main.handle_webhook(flask.request)


def test_handle_webhook_invalid_signature(app, mock_set_env_webhook_signature_key):
    with app.test_request_context(method='POST',
                                  path="/test_handle_webhook_valid",
                                  base_url="functions.googlecloud.com",
                                  json={
                                      "merchant_id": "merchant",
                                      "location_id": "location",
                                      "event_type": "event",
                                      "entity_id": "entity"},
                                  headers={"X-Square-Signature": "NOT_A_VALID_SIGNATURE"}):
        with pytest.raises(BadRequest):
            main.handle_webhook(flask.request)


def test_handle_webhook_empty_json(app):
    with app.test_request_context(method='POST', content_type='application/json'):
        with pytest.raises(BadRequest):
            main.handle_webhook(flask.request)


def test_handle_webhook_send_non_json(app):
    with app.test_request_context(method='POST', content_type='text/plain', data='abc123'):
        with pytest.raises(UnsupportedMediaType):
            main.handle_webhook(flask.request)


def test_handle_webhook_valid_json_no_signature(app, mock_set_env_webhook_signature_key):
    content = {
        "merchant_id": "merchant",
        "location_id": "location",
        "event_type": "event",
        "entity_id": "entity"
    }
    with app.test_request_context(method='POST', json=content):
        with pytest.raises(KeyError):
            main.handle_webhook(flask.request)
