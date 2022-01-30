""" Integration tests for square-webhook cloud function """
# pylint: disable=redefined-outer-name,unused-argument,no-member

import base64
from hashlib import sha1
import hmac
import json
import os
import time

import flask
import pytest

from google.cloud import pubsub_v1
from google.cloud.pubsub_v1.publisher import exceptions
from google.protobuf.timestamp_pb2 import Timestamp

from werkzeug.exceptions import InternalServerError

import main


@pytest.fixture(scope="module")
def app():
    """ Creates a fake Flask app for generating test request contents."""
    return flask.Flask(__name__)


KEY = "abc123def456"
SUBSCRIPTION_PATH = "projects/%s/subscriptions/test_handle_webhook_valid" % \
                    os.environ['GCP_PROJECT']


@pytest.fixture
def mock_setup(monkeypatch):
    """ Pytest fixture to set up relevant mocks for pubsub client """
    monkeypatch.setenv("SQUARE_WEBHOOK_SIGNATURE_KEY", KEY)
    monkeypatch.setenv("FUNCTION_NAME", "test_handle_webhook_valid")

    client = pubsub_v1.PublisherClient()
    topic_name = client.topic_path(os.environ["GCP_PROJECT"], "square.order.created")
    topics = client.list_topics(request={"project": "projects/%s" % os.environ["GCP_PROJECT"]})
    if topic_name not in [x.name for x in topics]:
        client.create_topic(request={"name": topic_name})

    # must create subscription before message is sent
    subscriber = pubsub_v1.SubscriberClient()
    subscriptions = subscriber.list_subscriptions(request={"project": "projects/%s" % os.environ["GCP_PROJECT"]})
    if SUBSCRIPTION_PATH not in [x.name for x in subscriptions]:
        subscriber.create_subscription(request={"name": SUBSCRIPTION_PATH, "topic": topic_name,
                                       "retain_acked_messages": True})

    # ack all messages before the test case starts
    now = time.time()
    seconds = int(now)
    reset_ts = Timestamp(seconds=seconds, nanos=int((now-seconds) * 10**9))
    subscriber.seek(request={"subscription": SUBSCRIPTION_PATH, "time": reset_ts})

    return subscriber


def test_handle_webhook_publish_timeout(app, mocker, mock_setup):
    """ test that if the publish call to pubsub times out, we send a non-200 response """
    base_url = "functions.googlecloud.com"
    function_name = "/" + os.environ["FUNCTION_NAME"]
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
                                  path=path,
                                  base_url=base_url,
                                  json=content,
                                  headers={"X-Square-Signature": signature}):
        with pytest.raises(InternalServerError):
            mocker.patch.object(pubsub_v1.publisher.futures.Future, "result",
                                side_effect=exceptions.TimeoutError())
            main.handle_webhook(flask.request)


def test_handle_webhook_without_topic(app, mocker, mock_setup):
    """ test that if we receive a webhook for an event without a corresponding pubsub topic
        we fail elegantly
    """
    base_url = "functions.googlecloud.com"
    function_name = "/" + os.environ["FUNCTION_NAME"]
    path = "/test_handle_webhook_valid"
    content = {
        "merchant_id": "merchantID",
        "data": "data",
        "type": "bogus.event",
        "event_id": "uuid"
    }
    to_sign = "://" + base_url + function_name + path + json.dumps(content, sort_keys=True)
    signature = base64.b64encode(hmac.new(KEY.encode(), to_sign.encode(), sha1).digest())
    with app.test_request_context(method='POST',
                                  path=path,
                                  base_url=base_url,
                                  json=content,
                                  headers={"X-Square-Signature": signature}):
        with pytest.raises(InternalServerError):
            main.handle_webhook(flask.request)


def test_handle_webhook_valid(app, mock_setup):
    """ tests that a valid message is successfully processed by the function """
    base_url = "functions.googlecloud.com"
    function_name = "/" + os.environ["FUNCTION_NAME"]
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
                                  path=path,
                                  base_url=base_url,
                                  json=content,
                                  headers={"X-Square-Signature": signature}):
        res = main.handle_webhook(flask.request)
        assert res.status == '200 OK'

        response = mock_setup.pull(request={"subscription": SUBSCRIPTION_PATH, "max_messages": 1})
        # ensure that what we sent over the webhook is what we got over pubsub
        assert json.loads(response.received_messages[0].message.data) == content
