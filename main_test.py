# pylint: disable=redefined-outer-name,unused-argument

import base64
import hmac
import json
import os
from hashlib import sha1

import flask
import pytest

from google.auth import credentials
from google.cloud import pubsub_v1
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


def test_handle_webhook_empty_webhook_key(app, monkeypatch):
    monkeypatch.delenv("SQUARE_WEBHOOK_SIGNATURE_KEY", raising=False)
    with app.test_request_context(method='POST', json={}):
        with pytest.raises(KeyError):
            main.handle_webhook(flask.request)
            pytest.fail("os.environ")


def test_handle_webhook_invalid_method(app, mock_set_env_webhook_signature_key):
    with app.test_request_context(method='GET'):
        with pytest.raises(MethodNotAllowed):
            main.handle_webhook(flask.request)
            pytest.fail("Invalid Method")


def test_handle_webhook_invalid_signature(app, mock_set_env_webhook_signature_key):
    base_url = "functions.googlecloud.com"
    path = "/test_handle_webhook_valid"
    with app.test_request_context(method='POST',
                                  path=path,
                                  base_url=base_url,
                                  json={
                                      "merchant_id": "merchant",
                                      "location_id": "location",
                                      "event_type": "event",
                                      "entity_id": "entity"},
                                  headers={"X-Square-Signature": "NOT_A_VALID_SIGNATURE"}):
        with pytest.raises(ValueError):
            main.handle_webhook(flask.request)
            pytest.fail("Square Signature could not be verified")


def test_handle_webhook_empty_json(app):
    with app.test_request_context(method='POST', content_type='application/json'):
        with pytest.raises(BadRequest):
            main.handle_webhook(flask.request)
            pytest.fail("JSON is invalid, or missing required property")


def test_handle_webhook_send_non_json(app):
    with app.test_request_context(method='POST', content_type='text/plain', data='abc123'):
        with pytest.raises(UnsupportedMediaType):
            main.handle_webhook(flask.request)
            pytest.fail("JSON is invalid, or missing required property")


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
            pytest.fail("KeyError: 'HTTP_X_SQUARE_SIGNATURE'")


def test_handle_webhook_valid(app, mock_set_env_webhook_signature_key):
    client = pubsub_v1.PublisherClient()
    topic_name = "projects/{}/topics/orders".format(os.environ["GCP_PROJECT"])
    client.create_topic(topic_name)
    base_url = "functions.googlecloud.com"
    path = "/test_handle_webhook_valid"
    content = {
        "merchant_id": "merchant",
        "location_id": "location",
        "event_type": "event",
        "entity_id": "entity"
    }
    to_sign = "://" + base_url + path + json.dumps(content, sort_keys=True)
    signature = base64.b64encode(hmac.new(KEY.encode(), to_sign.encode(), sha1).digest())
    with app.test_request_context(method='POST',
                                  path=path,
                                  base_url=base_url,
                                  json=content,
                                  headers={"X-Square-Signature": signature}):
        res = main.handle_webhook(flask.request)
        assert res.status == '200 OK'
    client.delete_topic(topic_name)

# TODO: test failure of pubsub call
