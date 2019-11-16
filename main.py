import base64
import hmac
import json
import os

from hashlib import sha1
from flask import Response
from werkzeug.exceptions import BadRequest, UnsupportedMediaType, MethodNotAllowed

from google.cloud import pubsub_v1

# only configure stackdriver logging when running on GCP
#if os.environ.get('GCP_PROJECT', None):
#    import google.cloud.logging
#    from google.cloud.logging.resource import Resource
#
#    log_client = google.cloud.logging.Client()
#    log_name = 'cloudfunctions.googleapis.com%2Fcloud-functions'
#
#    # Inside the resource, nest the required labels specific to the resource type
#    res = Resource(type="cloud_function", labels={
#        "function_name": os.getenv('FUNCTION_NAME'),
#        "region": os.getenv('FUNCTION_REGION')
#        })
#    logger = log_client.logger(log_name.format("GCP_PROJECT"))
#else:
#    import logging
import logging


def handle_webhook(request):
    """ Validates that the webhook came from Square and triggers the order creation process.
    This function needs to return with an HTTP 200 within 3 seconds or else the webhook call will
    be retried.
    """

    if request.method != 'POST':
        raise MethodNotAllowed(valid_methods="POST")

    if 'Square-Initial-Delivery-Timestamp' in request.headers:
        logging.debug("Delivery time of initial notification: %s",
                      request.headers['Square-Initial-Delivery-Timestamp'])

    if 'Square-Retry-Number' in request.headers:
        logging.warning("Square has resent this notification %s times; "
                        "reason given for the last failure is '%s'",
                        request.headers['Square-Retry-Number'],
                        request.headers['Square-Retry-Reason'])

    content_type = request.headers['content-type']
    if content_type == 'application/json':
        request_json = request.get_json(silent=False)
        # ensure the request is signed as coming from Square
        validate_square_signature(request)

        if request_json and request_json.keys() >= {"merchant_id",
                                                    "location_id",
                                                    "event_type",
                                                    "entity_id"}:
            logging.debug(msg="notification content from webhook", data=request_json)

            # put message on topic to upsert order
            publisher = pubsub_v1.PublisherClient()
            topic_path = "projects/{}/topics/{}".format(os.environ["GCP_PROJECT"],"orders")#publisher.topic_path(os.environ["GCP_PROJECT"], "orders")
            future = publisher.publish(topic_path, data=json.dumps(request_json).encode('utf-8'))

            # this will block until the publish is complete;
            # or raise an exception if the publish fails which should trigger Square to
            # retry the notification
            message_id = future.result(timeout=2)
            return Response(message_id, status=200)

        raise BadRequest(description="JSON is invalid, or missing required property")

    raise UnsupportedMediaType(description="Unknown content type: {}".format(content_type))


def validate_square_signature(request):
    """ Validates the signature for the webhook notification provided within the request.
    The HMAC-SHA1 digest is computed over the concatenation of the URL and the content body.

    The X-Square-Signature HTTP request header specifies the signed digest provided by Square,
    which should match what is calculated in this method.
    """
    key = os.environ['SQUARE_WEBHOOK_SIGNATURE_KEY']
    string_to_sign = request.url.encode() + request.data

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
