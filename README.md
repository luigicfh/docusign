# DocuSign integration

## GHL Setup

- Create custom field in GHL
    - Custom field name: Signed Document URL
    - Unique key: contact.signed_document_url
- Go to Settings > Business Profile > Copy API Key
- Share the API Key with Appointments Today PoC

## DocuSign configuration steps

- Go to **Settings > Connect > ADD CONFIGURATION > Custom**
- Set Name to **ghl_webhook**
- Set URL to Publish to <replace-with-cf-url>
- Enable Log and Require Acknowledgement
- Expand Envelope and Recipients to enable Recipient Signed/Completed
- Expand Include Data to enable Recipients
- Leave the rest as default and click **ADD CONFIGURATION**

---

Required environment variables

- GHL Location API Key
- Custom field unique key

---

Code Repository

```bash
git clone https://github.com/luigicfh/docusign.git
```

Set environment variables before running locally

```bash
export LOCATION_KEY=<replace-with-ghl-location-key>
```

```bash
export FIELD_KEY=contact.signed_document_url
```

```bash
# Document download url structure
https://app.docusign.com/api/accounts/${accountId}/envelopes/${documentId}/documents/1
```

Deployment command

```bash
gcloud functions deploy docusign --region=us-east1 --set-env-vars=LOCATION_KEY=$LOCATION_KEY,FIELD_KEY=$FIELD_KEY
```