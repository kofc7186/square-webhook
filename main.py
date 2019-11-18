# pylint: disable=redefined-outer-name,unused-argument,no-member

import base64
import hmac
import json
import logging
import os

from hashlib import sha1
from flask import Response
from werkzeug.exceptions import BadRequest, UnsupportedMediaType, MethodNotAllowed, \
    InternalServerError

from google.cloud import pubsub_v1

logger = logging.getLogger(__name__)

# only configure stackdriver logging when running on GCP
if os.environ.get('FUNCTION_REGION', None):
    from google.cloud import logging as cloudlogging
    LOG_CLIENT = cloudlogging.Client()
    HANDLER = LOG_CLIENT.get_default_handler()
    CLOUD_LOGGER = logging.getLogger("cloudLogger")
    CLOUD_LOGGER.addHandler(HANDLER)

def handle_webhook(request):
    """ Validates that the webhook came from Square and triggers the order creation process.
    This function needs to return with an HTTP 200 within 3 seconds or else the webhook call will
    be retried.
    """

    if request.method != 'POST':
        raise MethodNotAllowed(valid_methods="POST")

    if 'Square-Initial-Delivery-Timestamp' in request.headers:
        logger.debug("Delivery time of initial notification: %s",
                    request.headers['Square-Initial-Delivery-Timestamp'])

    if 'Square-Retry-Number' in request.headers:
        logger.debug("Square has resent this notification %s times; "
                     "reason given for the last failure is '%s'",
                        request.headers['Square-Retry-Number'],
                        request.headers['Square-Retry-Reason'])

    content_type = request.headers['content-type']
    if content_type == 'application/json':
        request_json = request.get_json(silent=False)

        # ensure the request is signed as coming from Square
        try:
            validate_square_signature(request)
        except ValueError:
            raise BadRequest(description="Signature could not be validated")

        if request_json and request_json.keys() >= {"merchant_id",
                                                    "location_id",
                                                    "event_type",
                                                    "entity_id"}:
            # put message on topic to upsert order
            publisher = pubsub_v1.PublisherClient()
            topic_path = publisher.topic_path(os.environ["GCP_PROJECT"], "orders")
            future = publisher.publish(topic_path, data=json.dumps(request_json).encode('utf-8'))

            # this will block until the publish is complete;
            # or raise an exception if the publish fails which should trigger Square to
            # retry the notification
            try:
                message_id = future.result(timeout=2)
                return Response(message_id, status=200)
            except pubsub_v1.publisher.exceptions.TimeoutError:
                raise InternalServerError(description="Timeout publishing notification")
            except:
                raise InternalServerError(description="Unknown error")

        raise BadRequest(description="JSON is invalid, or missing required property")

    raise UnsupportedMediaType(description="Unknown content type: {}".format(content_type))


def validate_square_signature(request):
    """ Validates the signature for the webhook notification provided within the request.
    The HMAC-SHA1 digest is computed over the concatenation of the URL and the content body.

    The X-Square-Signature HTTP request header specifies the signed digest provided by Square,
    which should match what is calculated in this method.
    """

    key = os.environ['SQUARE_WEBHOOK_SIGNATURE_KEY']
    # cloud functions does not set flaskRequest.url with the correct values so we have to munge it
    url = request.url.replace("http","https").rstrip('/') + '/' + os.environ['FUNCTION_NAME']

    string_to_sign = url.encode() + request.data

    # Generate the HMAC-SHA1 signature of the string, signed with your webhook signature key
    string_signature = str(base64.b64encode(hmac.new(key.encode(),
                                                     string_to_sign,
                                                     sha1).digest()), 'utf-8')

    # Remove the trailing newline from the generated signature
    string_signature = string_signature.rstrip('\n')

    # Compare your generated signature with the signature included in the request
    if not hmac.compare_digest(string_signature, request.headers['X-Square-Signature']):
        raise ValueError("Square Signature could not be verified")
    return True
