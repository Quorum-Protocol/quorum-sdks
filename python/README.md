# quorum-sdk (Python)

Python SDK for the Quorum Protocol API — server-side request creation,
webhook verification, group management.

## Install

```bash
pip install quorum-sdk
```

## Quick start

```python
from quorum import QuorumClient, verify_webhook_signature

client = QuorumClient(
    base_url="https://api.quorum.dev",
    api_key="qrm_..."
)

# Create an auth request
req = client.create_request(
    group_id="your-group-uuid",
    action_descriptor="Approve payment instruction",
    payload_hash="sha256_hex_of_payload",
    expires_in=300,
)
print(req.id, req.status)  # pending

# Verify webhook (e.g. in a Flask handler)
from flask import request

@app.post("/webhooks/quorum")
def handle():
    sig = request.headers.get("X-Quorum-Signature-256", "")
    if not verify_webhook_signature(request.data, WEBHOOK_SECRET, sig):
        return "Unauthorized", 401
    event = request.json
    if event["event"] == "request.approved":
        # handle approval
        pass
    return "ok"
```

## Server-side share derivation (USSD / server path)

```python
from quorum.crypto import derive_share

share_hex = derive_share(pin="284751", salt_hex="a3f2e1d4..." * 2)
client.authorize(request_id=req.id, member_id=member_id, share_hex=share_hex, token=token)
```
