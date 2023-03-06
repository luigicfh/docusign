import requests
import json
import os


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
