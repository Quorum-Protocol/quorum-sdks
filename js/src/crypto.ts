// src/crypto.ts — Argon2id share derivation and HMAC-SHA256 webhook verification
//
// # Share derivation
// deriveShare() runs Argon2id with the platform parameters enforced by the
// engine. It works in both browsers (via argon2-browser WebAssembly) and
// Node.js (via @node-rs/argon2 if available, fallback to argon2-browser).
//
// # Argon2id parameters
// These MUST match the engine constants in quorum-engine/src/crypto/kdf.rs:
//   M_COST = 65_536 KiB   (64 MB)
//   T_COST = 3
//   P_COST = 1
//   OUTPUT = 32 bytes

const ARGON2_M_COST = 65536; // 64 MB
const ARGON2_T_COST = 3;
const ARGON2_P_COST = 1;
const ARGON2_HASH_LEN = 32;
const MIN_PIN_LEN = 6;
const SALT_LEN = 32;

// ── Argon2id share derivation ────────────────────────────────────────────────

/**
 * Derive an Argon2id key share from a PIN and hex-encoded salt.
 *
 * @param pin     - The member's PIN or passphrase (min 6 characters)
 * @param saltHex - The member's unique 32-byte salt, hex-encoded (64 hex chars)
 * @returns       - The 32-byte share as a lowercase hex string
 *
 * @example
 * const share = await deriveShare('284751', 'a3f2e1d4....');
 * // submit share to POST /v1/authorize
 */
export async function deriveShare(pin: string, saltHex: string): Promise<string> {
  if (pin.length < MIN_PIN_LEN) {
    throw new Error(`PIN must be at least ${MIN_PIN_LEN} characters`);
  }
  if (saltHex.length !== SALT_LEN * 2) {
    throw new Error(`salt_hex must be ${SALT_LEN * 2} hex characters (${SALT_LEN} bytes)`);
  }

  const salt = hexToBytes(saltHex);
  const pinBytes = new TextEncoder().encode(pin);

  // Try Node.js native path first (server-side SDK usage)
  if (typeof process !== 'undefined' && process.versions?.node) {
    return deriveShareNode(pinBytes, salt);
  }

  // Browser path: argon2-browser WebAssembly
  return deriveShareBrowser(pinBytes, salt);
}

async function deriveShareBrowser(pin: Uint8Array, salt: Uint8Array): Promise<string> {
  // Dynamic import so the WASM only loads when needed
  const { hash, ArgonType } = await import('argon2-browser');

  const result = await hash({
    pass: pin,
    salt,
    type: ArgonType.Argon2id,
    mem: ARGON2_M_COST,
    time: ARGON2_T_COST,
    parallelism: ARGON2_P_COST,
    hashLen: ARGON2_HASH_LEN,
  });

  return bytesToHex(result.hash);
}

async function deriveShareNode(pin: Uint8Array, salt: Uint8Array): Promise<string> {
  // Node.js: use @node-rs/argon2 if available (native bindings, ~10x faster)
  // Falls back to argon2-browser WASM if not installed.
  try {
    const { hash } = await import('@node-rs/argon2');
    const result = await hash(pin, {
      salt,
      algorithm: 2, // Argon2id
      memoryCost: ARGON2_M_COST,
      timeCost: ARGON2_T_COST,
      parallelism: ARGON2_P_COST,
      outputLen: ARGON2_HASH_LEN,
    });
    // @node-rs/argon2 returns the raw hash as a Buffer
    return bytesToHex(typeof result === 'string' ? hexToBytes(result) : new Uint8Array(result));
  } catch {
    // Fallback to browser WASM
    return deriveShareBrowser(pin, salt);
  }
}

// ── Webhook signature verification ───────────────────────────────────────────

/**
 * Verify a Quorum webhook signature.
 *
 * Quorum signs webhook payloads with HMAC-SHA256. The signature is sent in
 * the `X-Quorum-Signature-256` header as `sha256=<hex>`.
 *
 * @param payload   - The raw request body bytes
 * @param secret    - The webhook signing secret set at registration
 * @param signature - The full value of the X-Quorum-Signature-256 header
 * @returns         - true if the signature is valid
 *
 * @example
 * const body = await request.text();
 * const sig  = request.headers.get('X-Quorum-Signature-256');
 * const ok   = await verifyWebhookSignature(
 *   new TextEncoder().encode(body), process.env.WEBHOOK_SECRET!, sig!
 * );
 */
export async function verifyWebhookSignature(
  payload:   Uint8Array | string,
  secret:    string,
  signature: string,
): Promise<boolean> {
  const data = typeof payload === 'string'
    ? new TextEncoder().encode(payload)
    : new Uint8Array(payload);

  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );

  const mac = await crypto.subtle.sign('HMAC', keyMaterial, data);
  const expected = 'sha256=' + bytesToHex(new Uint8Array(mac));

  // Constant-time comparison
  return timingSafeEqual(expected, signature);
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

/** Timing-safe string comparison to prevent timing attacks on HMAC checks. */
function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}
