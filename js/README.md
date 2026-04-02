# @quorum-sdk/sdk

JavaScript/TypeScript SDK for the Quorum Protocol API.
Works in browsers (via Argon2 WebAssembly) and Node.js.

## Install

```bash
npm install @quorum-sdk/sdk
```

## Quick start

```typescript
import { QuorumClient, deriveShare, verifyWebhookSignature } from '@quorum-sdk/sdk';

const client = new QuorumClient({
  baseURL: 'https://api.quorum.dev',
  apiKey:  'qrm_...',
});

// Server side — create an auth request
const req = await client.createRequest({
  groupId:          'your-group-uuid',
  actionDescriptor: 'Approve fund transfer of UGX 5,000,000',
  payloadHash:      'sha256_hex_of_your_payload',
  expiresIn:        300,
});
console.log(req.id, req.status); // "pending"

// Member side — derive share and authorise (browser)
const shareHex = await deriveShare(memberPin, memberSaltHex);
await client.authorize({ requestId: req.id, memberId, shareHex, token });

// Webhook receiver — verify signature
const ok = await verifyWebhookSignature(requestBody, webhookSecret, signatureHeader);
```

## Argon2id parameters

The SDK uses identical parameters to `quorum-engine`:

| Parameter | Value |
|---|---|
| Algorithm | Argon2id |
| Memory | 64 MB (65,536 KiB) |
| Time | 3 passes |
| Parallelism | 1 |
| Output | 32 bytes |
