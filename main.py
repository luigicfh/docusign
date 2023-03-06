import logging
import functions_framework
import os
import google.cloud.logging
from google.cloud import storage
import json
import traceback
from docusign.functions import *
from ghl.functions import *

service_account_credentials = 'at-api-hub-d1ddd021ac28.json'

logging_client = google.cloud.logging.Client() if not os.path.exists(
    service_account_credentials) else google.cloud.logging.Client().from_service_account_json(service_account_credentials)
logging_client.setup_logging()

not_allowed_message = {
    "message": "method not allowed"
}
invalid_query_message = {
    "message": "invalid query"
}
success_message = {
    "message": "success"
}
error_message = {
    "message": "error"
}
log_message = {
    "message": "log"
}


def send_document_to_ghl_contact(request_json):
    try:
        docusign_envelope_signers = request_json['data']['envelopeSummary']['recipients']['signers']
    except KeyError as e:
        return log_error(traceback.format_exc(), request_json)
    # DocuSign
    docusign_envelope_id = request_json['data']['envelopeId']
    docusign_uri = request_json['uri']
    docusign_document_content = get_docusign_document_content(docusign_uri)
    # GCS
    gcs_download_url = write_to_gcs(
        docusign_document_content, docusign_envelope_id)
    # GHL
    ghl_location_api_key = os.environ.get("LOCATION_KEY")
    ghl_headers = {
        "Authorization": f"Bearer {ghl_location_api_key}"
    }
    ghl_custom_value_payload = generate_ghl_contact_payload(
        ghl_headers, gcs_download_url)
    for signer in docusign_envelope_signers:
        signer_email = signer['email']
        ghl_contact_data = find_ghl_contact(ghl_headers, signer_email)
        if ghl_contact_data is None:
            log_info(
                "Contact does not exist in GHL", request_json
            )
            continue
        ghl_contact_id = ghl_contact_data['id']
        try:
            response = update_ghl_contact(
                ghl_headers, ghl_contact_id, ghl_custom_value_payload)
            log_info("Contact updated successfully", response.json())
        except Exception as e:
            return log_error(traceback.format_exc(), request_json)


def request_signature_via_email(request_json):
    docusign_jwt_token = generate_docusign_jwt_token()
    docusign_access_token = get_docusign_access_token(docusign_jwt_token)
    docusign_user_info = get_docusign_user_info(
        docusign_access_token['access_token'])
    docusign_base_uri = docusign_user_info['accounts'][0]['base_uri']
    return


@functions_framework.http
def docusign_webhook(request):
    if request.method != "POST":
        return not_allowed_message
    request_json = request.get_json()
    if not request.args:
        return invalid_query_message
    if 'action' not in request.args:
        return invalid_query_message
    action = request.args.get('action')
    if action == 'send_to_ghl':
        try:
            send_document_to_ghl_contact(request_json)
        except Exception as e:
            return log_error(
                traceback.format_exc(),
                request_json
            )
    if action == 'request_signature':
        try:
            request_signature_via_email(request_json)
        except Exception as e:
            return log_error(
                traceback.format_exc(),
                request_json
            )
    return success_message


def log_error(error, request):
    logging.error(
        f"""
            Docusign integration error:\n
            Exception: {error}\n
            Payload: {json.dumps(request, indent=4)}
        """
    )
    return error_message


def log_info(msg, request):
    logging.info(
        f"""
        Docusign integration info:\n
        Message: {msg}\n
        Payload: {json.dumps(request, indent=4)}
        """
    )
    return log_message


def write_to_gcs(content, envelope_id):
    storage_client = storage.Client() if not os.path.exists(
        service_account_credentials) else storage.Client().from_service_account_json(
            service_account_credentials)
    bucket = storage_client.bucket(os.environ.get("BUCKET_NAME"))
    blob_name = f"{envelope_id}.pdf"
    blob = bucket.blob(blob_name)
    with blob.open('wb') as file:
        file.write(content)
    return blob._get_download_url(storage_client)


if __name__ == "__main__":
    with open('docusign_test_data.json') as file:
        test_data = json.loads(file.read())
    send_document_to_ghl_contact(test_data)
