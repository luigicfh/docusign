import requests
import os
import datetime
import jwt


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


def get_docusign_document_content(uri):
    docusign_jwt_token = generate_docusign_jwt_token()
    docusign_access_token = get_docusign_access_token(docusign_jwt_token)
    docusign_user_info = get_docusign_user_info(
        docusign_access_token['access_token'])
    docusign_base_uri = docusign_user_info['accounts'][0]['base_uri']
    document_download_ep = f"{docusign_base_uri}{uri}/documents/combined"
    docusign_document_content = download_docusign_document(
        document_download_ep,
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


def download_docusign_document(document_download_ep, access_token):
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json",
        "Content-Type": "application/json"
    }
    response = requests.get(document_download_ep, headers=headers)
    if response.status_code != 200:
        return None
    return response.content
