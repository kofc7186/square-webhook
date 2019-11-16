# pylint: disable=redefined-outer-name,unused-argument

import base64
import hmac
import json
import os
from hashlib import sha1

import flask
import pytest
from unittest import mock

from google.auth import credentials
from google.cloud import pubsub_v1
from google.cloud.pubsub_v1.publisher import exceptions
from werkzeug.exceptions import BadRequest, UnsupportedMediaType, MethodNotAllowed, InternalServerError

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
        with pytest.raises(ValueError):
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


# TODO: test failure of pubsub call
def mock_future_request(*args, **kwargs):
    raise exceptions.TimeoutError()

@pytest.mark.skipif(os.environ.get("GITHUB_ACTION", None) is None, reason="Requires pubsub emulator to run")
def test_handle_webhook_publish_timeout(app, monkeypatch, mock_set_env_webhook_signature_key):
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
        with pytest.raises(InternalServerError):
            #monkeypatch.setattr(pubsub_v1, "publisher", mock_creds)
            monkeypatch.setattr(pubsub_v1.publisher.futures.Future,"result",mock_future_request)
            main.handle_webhook(flask.request)


@pytest.mark.skipif(os.environ.get("GITHUB_ACTION", None) is None, reason="Requires pubsub emulator to run")
def test_handle_webhook_valid(app, mock_set_env_webhook_signature_key):
    client = pubsub_v1.PublisherClient()
    topic_name = client.topic_path(os.environ["GCP_PROJECT"],"orders")
    topic = client.create_topic(topic_name)
    print ("Created topic: {}".format(topic))
    
    # must create subscription before message is sent
    subscriber = pubsub_v1.SubscriberClient()
    subscription_path = subscriber.subscription_path(os.environ["GCP_PROJECT"],"test_handle_webhook_valid")
    subscrip = subscriber.create_subscription(subscription_path,topic_name)
    print ("Subscription: {}".format(subscrip))

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

        response = subscriber.pull(subscription_path,max_messages=1)
        # ensure that what we sent over the webhook is what we got over pubsub
        assert json.loads(response.received_messages[0].message.data) == content

        ack_ids = [msg.ack_id for msg in response.received_messages]
        subscriber.acknowledge(subscription_path, ack_ids)
    subscriber.delete_subscription(subscription_path)
    client.delete_topic(topic_name)
