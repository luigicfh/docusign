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


def send_document_to_ghl(request_json):
    try:
        contact_email = request_json['data']['envelopeSummary']['recipients']['signers'][0]['email']
    except KeyError as e:
        return log_error(traceback.format_exc(), request_json)
    location_api_key = os.environ.get("LOCATION_KEY")
    ghl_headers = {
        "Authorization": f"Bearer {location_api_key}"
    }
    contact_data = find_contact(ghl_headers, contact_email)
    if contact_data is None:
        return log_info(
            "Contact does not exist in GHL", request_json
        )
    custom_fields = get_custom_fields(ghl_headers)
    contact_id = contact_data['id']
    target_field_id = get_document_field_id(custom_fields)
    if target_field_id == '':
        raise Exception(
            "Signed Document URL field has not been created"
        )
    jwt_token = generate_jwt_token()
    access_token = get_access_token(jwt_token)
    user_info = get_user_info(access_token['access_token'])
    document_content = download_doc(
        user_info['accounts'][0]['base_uri'],
        user_info['accounts'][0]['account_id'],
        request_json['data']['envelopeId'],
        access_token['access_token']
    )
    gcs_download_url = write_to_gcs(
        document_content, request_json['data']['envelopeId'])
    custom_value = json.dumps({
        "customField": {
            target_field_id: gcs_download_url
        }
    })
    try:
        response = update_contact(ghl_headers, contact_id, custom_value)
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
                send_document_to_ghl(request_json)
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


def find_contact(ghl_headers, email):
    contact_lookup_ep = f"https://rest.gohighlevel.com/v1/contacts/lookup?email={email}"
    response = requests.get(contact_lookup_ep, headers=ghl_headers)
    if response.status_code != 200:
        return None
    return response.json()['contacts'][0]


def get_custom_fields(ghl_headers):
    custom_fields_ep = "https://rest.gohighlevel.com/v1/custom-fields/"
    response = requests.get(custom_fields_ep, headers=ghl_headers)
    if response.status_code != 200:
        return None
    return response.json()['customFields']


def get_document_field_id(custom_fields):
    field_unique_key = os.environ.get("FIELD_KEY")
    field_id = ''
    for field in custom_fields:
        if field['fieldKey'] == field_unique_key:
            field_id = field['id']
            break
    return field_id


def update_contact(ghl_headers, contact_id, custom_value):
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


def generate_jwt_token():
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


def get_access_token(jwt_token):
    access_token_ep = 'https://' + os.environ.get("BASE_URL") + "/oauth/token"
    form_data = {
        "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
        "assertion": jwt_token
    }
    response = requests.post(access_token_ep, data=form_data)
    if response.status_code != 200:
        return None
    return response.json()


def get_user_info(access_token):
    user_info_ep = 'https://' + os.environ.get("BASE_URL") + "/oauth/userinfo"
    headers = {
        "Authorization": f"Bearer {access_token}"
    }
    response = requests.get(user_info_ep, headers=headers)
    if response.status_code != 200:
        return None
    return response.json()


def download_doc(base_uri, account_id, envelope_id, access_token):
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


def set_storage_client():
    if os.path.exists(service_account_credentials):
        return storage.Client().from_service_account_json(
            service_account_credentials)
    return storage.Client()


def write_to_gcs(content, envelope_id):
    storage_client = set_storage_client()
    bucket = storage_client.bucket(os.environ.get("BUCKET_NAME"))
    blob_name = f"{envelope_id}.pdf"
    blob = bucket.blob(blob_name)
    with blob.open('wb') as file:
        file.write(content)
    return blob._get_download_url(storage_client)


if __name__ == "__main__":
    with open('test_data.json') as file:
        test_data = json.loads(file.read())
    send_document_to_ghl(test_data)
