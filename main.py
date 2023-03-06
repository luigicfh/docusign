import logging
import functions_framework
import os
import requests
import google.cloud.logging
from google.cloud import storage
import json
import traceback
import jwt
import datetime

service_account_credentials = 'at-api-hub-d1ddd021ac28.json'

logging_client = google.cloud.logging.Client() if not os.path.exists(
    service_account_credentials) else google.cloud.logging.Client().from_service_account_json(service_account_credentials)
logging_client.setup_logging()


def send_document_to_ghl_contact(request_json):
    try:
        docusign_envelope_signers = request_json['data']['envelopeSummary']['recipients']['signers']
    except KeyError as e:
        return log_error(traceback.format_exc(), request_json)
    # DocuSign
    docusign_envelope_id = request_json['data']['envelopeId']
    docusign_document_content = get_docusign_document_content(
        docusign_envelope_id)
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


@functions_framework.http
def docusign_webhook(request):
    if request.method != "POST":
        return 404, "Not Found."
    request_json = request.get_json()
    if request.args and 'action' in request.args:
        action = request.args.get('action')
        if action == 'send_to_ghl':
            try:
                send_document_to_ghl_contact(request_json)
            except Exception as e:
                return log_error(traceback.format_exc(), request_json)
    return "OK"


def log_error(error, request):
    logging.error(
        f"""
            Docusign integration error:\n
            Exception: {error}\n
            Payload: {json.dumps(request, indent=4)}
        """
    )
    return "OK"


def log_info(msg, request):
    logging.info(
        f"""
        Docusign integration info:\n
        Message: {msg}\n
        Payload: {json.dumps(request, indent=4)}
        """
    )
    return "OK"


def generate_ghl_contact_payload(ghl_headers, gcs_download_url):
    ghl_custom_fields = get_ghl_custom_fields(ghl_headers)
    ghl_target_custom_field_id = set_document_field_id(ghl_custom_fields)
    if ghl_target_custom_field_id == '':
        raise Exception(
            "Signed Document URL field has not been created"
        )
    ghl_custom_value_payload = json.dumps({
        "customField": {
            ghl_target_custom_field_id: gcs_download_url
        }
    })
    return ghl_custom_value_payload


def find_ghl_contact(ghl_headers, email):
    contact_lookup_ep = f"https://rest.gohighlevel.com/v1/contacts/lookup?email={email}"
    response = requests.get(contact_lookup_ep, headers=ghl_headers)
    if response.status_code != 200:
        return None
    return response.json()['contacts'][0]


def get_ghl_custom_fields(ghl_headers):
    custom_fields_ep = "https://rest.gohighlevel.com/v1/custom-fields/"
    response = requests.get(custom_fields_ep, headers=ghl_headers)
    if response.status_code != 200:
        return None
    return response.json()['customFields']


def set_document_field_id(custom_fields):
    field_unique_key = os.environ.get("FIELD_KEY")
    field_id = ''
    for field in custom_fields:
        if field['fieldKey'] == field_unique_key:
            field_id = field['id']
            break
    return field_id


def update_ghl_contact(ghl_headers, contact_id, custom_value):
    contact_update_ep = f"https://rest.gohighlevel.com/v1/contacts/{contact_id}"
    ghl_headers['Content-Type'] = 'application/json'
    response = requests.put(
        contact_update_ep, headers=ghl_headers, data=custom_value)
    if response.status_code != 200:
        raise Exception(f"""
        Status code: {str(response.status_code)}\n
        Body: {json.dumps(response.json())}
        """)
    return response


def generate_docusign_jwt_token():
    algorithm = "RS256"
    payload = {
        "iss": os.environ.get("INTEGRATION_KEY"),
        "sub": os.environ.get("USER_ID"),
        "aud": os.environ.get("BASE_URL"),
        "iat": datetime.datetime.utcnow(),
        "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=30),
        "scope": "signature impersonation"
    }
    private_key = os.environ.get("PRIVATE_KEY")
    jwt_header = {
        "alg": algorithm,
        "typ": "JWT"
    }
    jwt_token = jwt.encode(
        payload,
        private_key,
        algorithm=algorithm,
        headers=jwt_header
    )
    return jwt_token


def get_docusign_document_content(docusign_envelope_id):
    docusign_jwt_token = generate_docusign_jwt_token()
    docusign_access_token = get_docusign_access_token(docusign_jwt_token)
    docusign_user_info = get_docusign_user_info(
        docusign_access_token['access_token'])
    docusign_document_content = download_docusign_document(
        docusign_user_info['accounts'][0]['base_uri'],
        docusign_user_info['accounts'][0]['account_id'],
        docusign_envelope_id,
        docusign_access_token['access_token']
    )
    return docusign_document_content


def get_docusign_access_token(jwt_token):
    access_token_ep = 'https://' + os.environ.get("BASE_URL") + "/oauth/token"
    form_data = {
        "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
        "assertion": jwt_token
    }
    response = requests.post(access_token_ep, data=form_data)
    if response.status_code != 200:
        return None
    return response.json()


def get_docusign_user_info(access_token):
    user_info_ep = 'https://' + os.environ.get("BASE_URL") + "/oauth/userinfo"
    headers = {
        "Authorization": f"Bearer {access_token}"
    }
    response = requests.get(user_info_ep, headers=headers)
    if response.status_code != 200:
        return None
    return response.json()


def download_docusign_document(base_uri, account_id, envelope_id, access_token):
    document_download_ep = f"{base_uri}/restapi/v2.1/accounts/{account_id}/envelopes/{envelope_id}/documents/combined"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json",
        "Content-Type": "application/json"
    }
    response = requests.get(document_download_ep, headers=headers)
    if response.status_code != 200:
        return None
    return response.content


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
    with open('test_data.json') as file:
        test_data = json.loads(file.read())
    send_document_to_ghl_contact(test_data)
