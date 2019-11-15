# Copyright 2019 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the 'License');
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an 'AS IS' BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import hmac
from hashlib import sha1
import base64

import json
import flask
from werkzeug.exceptions import BadRequest, UnsupportedMediaType, MethodNotAllowed
import pytest

import main

# Create a fake "app" for generating test request contexts.
@pytest.fixture(scope="module")
def app():
    return flask.Flask(__name__)

key = "abc123def456"
@pytest.fixture
def mock_set_env_webhook_signature_key(monkeypatch):
    monkeypatch.setenv("SQUARE_WEBHOOK_SIGNATURE_KEY",key)


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
    with app.test_request_context(method='POST', path=path, base_url=base_url, json={
        "merchant_id":"merchant", 
        "location_id":"location", 
        "event_type":"event", 
        "entity_id":"entity"},
        headers = {"X-Square-Signature": "NOT_A_VALID_SIGNATURE"}):
        with pytest.raises(ValueError):
            main.handle_webhook(flask.request)
            pytest.fail("Square Signature could not be verified")

def test_handle_webhook_empty_json(app):
    with app.test_request_context(method='POST', content_type='application/json'):
        with pytest.raises(BadRequest):
            main.handle_webhook(flask.request)
            pytest.fail("JSON is invalid, or missing required property")


def test_handle_webhook_send_non_json(app):
    with app.test_request_context(method='POST', content_type='text/plain',data='abc123'):
        with pytest.raises(UnsupportedMediaType):
            main.handle_webhook(flask.request)
            pytest.fail("JSON is invalid, or missing required property")


def test_handle_webhook_valid_json_no_signature(app, mock_set_env_webhook_signature_key):
    content = {
        "merchant_id":"merchant", 
        "location_id":"location", 
        "event_type":"event", 
        "entity_id":"entity"
    }
    with app.test_request_context(method='POST', json=content):
        with pytest.raises(KeyError):
            main.handle_webhook(flask.request)
            pytest.fail("KeyError: 'HTTP_X_SQUARE_SIGNATURE'")


def test_handle_webhook_valid(app, mock_set_env_webhook_signature_key):
    base_url = "functions.googlecloud.com"
    path = "/test_handle_webhook_valid"
    content = {
        "merchant_id":"merchant", 
        "location_id":"location", 
        "event_type":"event", 
        "entity_id":"entity"
    }
    to_sign = "://" + base_url + path + json.dumps(content,sort_keys=True)
    signature = base64.b64encode(hmac.new(key.encode(),to_sign.encode(),sha1).digest())
    with app.test_request_context(method='POST', path=path, base_url=base_url, json=content, headers = {"X-Square-Signature": signature}):
        res = main.handle_webhook(flask.request)
        assert res.status == '200 OK'

#TODO: mock up pubsub
#TODO: test failure of pubsub call