import logging
import functions_framework
import os
import requests
import google.cloud.logging
import json
import traceback

logging_client = google.cloud.logging.Client()
logging_client.setup_logging()


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
        print(response.status_code)
        print(response.json())
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


def main(request_json):
    try:
        contact_email = request_json['data']['envelopeSummary']['recipients']['signers'][0]['email']
    except KeyError as e:
        return log_error(traceback.format_exc(), request_json)
    location_api_key = os.environ.get("LOCATION_KEY")
    docusign_download_uri = "https://app.docusign.com/api/accounts/{}/envelopes/{}/documents/1"
    ghl_headers = {
        "Authorization": f"Bearer {location_api_key}"
    }
    contact_data = find_contact(ghl_headers, contact_email)
    if contact_data is None:
        return log_error(
            "Contact does not exist in GHL", request_json
        )
    custom_fields = get_custom_fields(ghl_headers)
    contact_id = contact_data['id']
    target_field_id = get_document_field_id(custom_fields)
    if target_field_id == '':
        return log_error(
            "Signed Document URL field has not been created",
            request_json
        )
    document_download_url = docusign_download_uri.format(
        request_json['data']['accountId'], request_json['data']['envelopeId'])
    custom_value = json.dumps({
        "customField": {
            target_field_id: document_download_url
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
    main(request_json)
    return "OK"


if __name__ == "__main__":
    with open('test_data.json') as file:
        test_data = json.loads(file.read())
    main(test_data)
