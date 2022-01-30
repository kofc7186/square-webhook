""" Unit tests for the square-webhook cloud function """
# pylint: disable=redefined-outer-name,unused-argument,no-member

import base64
import datetime
from hashlib import sha1
import hmac
import json
import flask
import pytest

from google.cloud import pubsub_v1
from werkzeug.exceptions import BadRequest, UnsupportedMediaType, MethodNotAllowed,\
    InternalServerError

import main


@pytest.fixture(scope="module")
def app():
    """ Creates a fake Flask app for generating test request contents."""
    return flask.Flask(__name__)


KEY = "abc123def456"


@pytest.fixture
def mock_set_env_webhook_signature_key(monkeypatch):
    """ Pytest fixture that sets the environment variables required to run the function. """
    monkeypatch.setenv("SQUARE_WEBHOOK_SIGNATURE_KEY", KEY)
    monkeypatch.setenv("FUNCTION_NAME", "test_handle_webhook_valid")


def test_handle_webhook_empty_webhook_key(app, monkeypatch):
    """ Ensures that if the webhook key is not available to the function, the function fails. """
    monkeypatch.delenv("SQUARE_WEBHOOK_SIGNATURE_KEY", raising=False)

    base_url = "functions.googlecloud.com"
    function_name = "/test_handle_webhook_valid"
    path = "/test_handle_webhook_valid"
    content = {
        "merchant_id": "merchantID",
        "data": "data",
        "type": "order.created",
        "event_id": "uuid"
    }
    to_sign = "://" + base_url + function_name + path + json.dumps(content, sort_keys=True)
    signature = base64.b64encode(hmac.new(KEY.encode(), to_sign.encode(), sha1).digest())
    with app.test_request_context(method='POST',
                                  path="/test_handle_webhook_valid",
                                  base_url="functions.googlecloud.com",
                                  json=content,
                                  headers={'X-Square-Signature': signature}):
        with pytest.raises(KeyError):
            main.handle_webhook(flask.request)


@pytest.mark.parametrize("method", ["CONNECT", "DELETE", "GET", "HEAD", "OPTIONS", "PUT", "TRACE"])
def test_handle_webhook_invalid_method(method, app, mock_set_env_webhook_signature_key):
    """ Ensures that if the webhook only responds to POST requests. """
    with app.test_request_context(method=method):
        with pytest.raises(MethodNotAllowed):
            main.handle_webhook(flask.request)


def test_handle_webhook_invalid_signature(app, mock_set_env_webhook_signature_key):
    """ Ensures that if the signature is not correct, the message is rejected """
    with app.test_request_context(method='POST',
                                  path="/test_handle_webhook_valid",
                                  base_url="functions.googlecloud.com",
                                  json={
                                      "merchant_id": "merchantID",
                                      "data": "data",
                                      "type": "order.created",
                                      "event_id": "uuid"},
                                  headers={"X-Square-Signature": "NOT_A_VALID_SIGNATURE"}):
        with pytest.raises(BadRequest):
            main.handle_webhook(flask.request)


def test_handle_webhook_empty_json(app):
    """ Ensures that if there is no content, the message is rejected """
    with app.test_request_context(method='POST', content_type='application/json'):
        with pytest.raises(BadRequest):
            main.handle_webhook(flask.request)


def test_handle_webhook_send_non_json(app):
    """ Ensures that if there is content but it is not JSON, the message is rejected """
    with app.test_request_context(method='POST', content_type='text/plain', data='abc123'):
        with pytest.raises(UnsupportedMediaType):
            main.handle_webhook(flask.request)


def test_handle_webhook_valid_json_no_signature(app, mock_set_env_webhook_signature_key):
    """ Ensures that if there is JSON content but no signature, the message is rejected """
    content = {
        "merchant_id": "merchantID",
        "data": "data",
        "type": "order.created",
        "event_id": "uuid"
    }
    with app.test_request_context(method='POST', json=content):
        with pytest.raises(KeyError):
            main.handle_webhook(flask.request)


@pytest.fixture
def mock_pubsub_calls(mocker):
    """ Pytest fixture for mocking the pubsub client """
    mock_client = mocker.patch('google.cloud.pubsub_v1.PublisherClient', autospec=True)
    mock_client.return_value.publish.return_value.result.return_value = "message_id"
    return mock_client


def test_good_message(app, mock_pubsub_calls, mock_set_env_webhook_signature_key):
    """ tests complete path with only pubsub mocked out"""
    base_url = "functions.googlecloud.com"
    function_name = "/test_handle_webhook_valid"
    path = "/test_handle_webhook_valid"
    content = {
        "merchant_id": "merchantID",
        "data": "data",
        "type": "order.created",
        "event_id": "uuid"
    }
    to_sign = "://" + base_url + function_name + path + json.dumps(content, sort_keys=True)
    signature = base64.b64encode(hmac.new(KEY.encode(), to_sign.encode(), sha1).digest())
    with app.test_request_context(method='POST',
                                  path="/test_handle_webhook_valid",
                                  base_url="functions.googlecloud.com",
                                  json=content,
                                  headers={'x-square-signature': signature}):
        response = main.handle_webhook(flask.request)

    assert response.status_code == 200
    assert response.data == b'message_id'
    assert mock_pubsub_calls.return_value.publish.call_count == 1


def test_good_message_retry(app, mock_pubsub_calls, mock_set_env_webhook_signature_key):
    """ tests complete path sent as retry with only pubsub mocked out"""
    base_url = "functions.googlecloud.com"
    function_name = "/test_handle_webhook_valid"
    path = "/test_handle_webhook_valid"
    content = {
        "merchant_id": "merchantID",
        "data": "data",
        "type": "order.created",
        "event_id": "uuid"
    }
    to_sign = "://" + base_url + function_name + path + json.dumps(content, sort_keys=True)
    signature = base64.b64encode(hmac.new(KEY.encode(), to_sign.encode(), sha1).digest())
    with app.test_request_context(method='POST',
                                  path="/test_handle_webhook_valid",
                                  base_url="functions.googlecloud.com",
                                  json=content,
                                  headers={
                                      'X-Square-Signature': signature,
                                      'Square-Initial-Delivery-Timestamp':
                                          datetime.datetime.utcnow().isoformat("T") + "Z",
                                      'Square-Retry-Number': 1,
                                      'Square-Retry-Reason': "500 Internal Server Error",
                                  }):
        response = main.handle_webhook(flask.request)

    assert response.status_code == 200
    assert response.data == b'message_id'
    assert mock_pubsub_calls.return_value.publish.call_count == 1


def test_good_message_publish_timeout(app, mock_pubsub_calls, mock_set_env_webhook_signature_key):
    """ tests good message that times out when published to topic; ensures we send a non-200
        response
    """
    base_url = "functions.googlecloud.com"
    function_name = "/test_handle_webhook_valid"
    path = "/test_handle_webhook_valid"
    content = {
        "merchant_id": "merchantID",
        "data": "data",
        "type": "order.created",
        "event_id": "uuid"
    }
    to_sign = "://" + base_url + function_name + path + json.dumps(content, sort_keys=True)
    signature = base64.b64encode(hmac.new(KEY.encode(), to_sign.encode(), sha1).digest())
    with app.test_request_context(method='POST',
                                  path="/test_handle_webhook_valid",
                                  base_url="functions.googlecloud.com",
                                  json=content,
                                  headers={'X-Square-Signature': signature}):
        mock_pubsub_calls.return_value.publish.return_value.result.side_effect = \
            pubsub_v1.publisher.exceptions.TimeoutError
        with pytest.raises(InternalServerError):
            main.handle_webhook(flask.request)

        assert mock_pubsub_calls.return_value.publish.call_count == 1


def test_good_message_publish_unknown_error(app, mock_pubsub_calls,
                                            mock_set_env_webhook_signature_key):
    """ tests good message that raises unknown exception when published to topic; ensures we
        send a non-200 response
    """
    base_url = "functions.googlecloud.com"
    function_name = "/test_handle_webhook_valid"
    path = "/test_handle_webhook_valid"
    content = {
        "merchant_id": "merchantID",
        "data": "data",
        "type": "order.created",
        "event_id": "uuid"
    }
    to_sign = "://" + base_url + function_name + path + json.dumps(content, sort_keys=True)
    signature = base64.b64encode(hmac.new(KEY.encode(), to_sign.encode(), sha1).digest())
    with app.test_request_context(method='POST',
                                  path="/test_handle_webhook_valid",
                                  base_url="functions.googlecloud.com",
                                  json=content,
                                  headers={'X-Square-Signature': signature}):
        mock_pubsub_calls.return_value.publish.return_value.result.side_effect = Exception
        with pytest.raises(InternalServerError):
            main.handle_webhook(flask.request)

        assert mock_pubsub_calls.return_value.publish.call_count == 1


def test_insufficient_json_fields(app, mock_pubsub_calls, mock_set_env_webhook_signature_key):
    """ tests invalid message that is missing a required field in JSON but has a valid signature;
        ensures we return a non-200 response
    """
    base_url = "functions.googlecloud.com"
    function_name = "/test_handle_webhook_valid"
    path = "/test_handle_webhook_valid"
    content = {
        "merchant_id": "merchantID",
        "type": "order.created",
        "event_id": "uuid"
    }
    to_sign = "://" + base_url + function_name + path + json.dumps(content, sort_keys=True)
    signature = base64.b64encode(hmac.new(KEY.encode(), to_sign.encode(), sha1).digest())
    with app.test_request_context(method='POST',
                                  path="/test_handle_webhook_valid",
                                  base_url="functions.googlecloud.com",
                                  json=content,
                                  headers={'X-Square-Signature': signature}):
        mock_pubsub_calls.return_value.publish.return_value.result.side_effect = Exception
        with pytest.raises(BadRequest):
            main.handle_webhook(flask.request)

        assert mock_pubsub_calls.return_value.publish.call_count == 0
