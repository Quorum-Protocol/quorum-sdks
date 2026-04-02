// src/config.ts — API key resolution and storage guidance
//
// This module handles how your API key reaches the SDK in different
// environments (Node.js server, browser app, CI pipeline).
//
// TL;DR:
//   Server-side (Node.js):  set QUORUM_API_KEY env var → QuorumClient reads it
//   Browser (widget):       NEVER put your live key here — use a widget token
//   CI/CD:                  set QUORUM_API_KEY as a secret in your pipeline

/**
 * Resolve the API key from the environment.
 *
 * Resolution order:
 *   1. Explicit value passed to QuorumClient constructor
 *   2. QUORUM_API_KEY environment variable (Node.js)
 *   3. VITE_QUORUM_TEST_KEY / REACT_APP_QUORUM_TEST_KEY (dev only, test keys only)
 *   4. Error — key is required
 *
 * @throws if no key can be resolved and none was explicitly provided
 */
export function resolveAPIKey(explicit?: string): string {
  if (explicit) return explicit;

  // Node.js server environment
  if (typeof process !== 'undefined' && process.env) {
    if (process.env.QUORUM_API_KEY) return process.env.QUORUM_API_KEY;
  }

  // Vite dev environment — test keys only
  if (typeof import.meta !== 'undefined') {
    const viteKey = (import.meta as any).env?.VITE_QUORUM_TEST_KEY;
    if (viteKey) {
      if (!viteKey.startsWith('qrm_test_')) {
        throw new Error(
          'VITE_QUORUM_TEST_KEY must be a test key (qrm_test_...). ' +
          'Never expose live keys in browser bundles.'
        );
      }
      return viteKey;
    }
  }

  throw new Error(
    'Quorum API key not found.\n\n' +
    'Server-side: set QUORUM_API_KEY environment variable\n' +
    '  export QUORUM_API_KEY="qrm_live_..."\n\n' +
    'Or pass it explicitly:\n' +
    '  new QuorumClient({ apiKey: "qrm_live_..." })\n\n' +
    'Never put live keys in browser code. ' +
    'For the widget, use a widget token from POST /v1/widget-tokens.'
  );
}

/**
 * Validate that an API key looks structurally correct.
 * Does not make a network call — just checks the format.
 */
export function validateKeyFormat(key: string): void {
  if (!key.startsWith('qrm_live_') && !key.startsWith('qrm_test_')) {
    throw new Error(
      `Invalid API key format. Keys must start with 'qrm_live_' or 'qrm_test_'. Got: ${key.slice(0, 12)}...`
    );
  }
  if (key.length < 40) {
    throw new Error('API key is too short — it may be truncated');
  }
}

/**
 * True if running in a browser environment.
 * Use this to guard against accidentally shipping live keys to browsers.
 */
export function isBrowser(): boolean {
  return typeof window !== 'undefined' && typeof document !== 'undefined';
}

/**
 * Warn loudly in development if a live key is being used in a browser.
 * In production this is a hard error.
 */
export function assertNotLiveKeyInBrowser(key: string): void {
  if (!isBrowser()) return;
  if (!key.startsWith('qrm_live_')) return;

  const msg =
    'SECURITY: You are passing a live Quorum API key (qrm_live_...) to browser code.\n' +
    'Live keys give full API access and must never be exposed in the browser.\n\n' +
    'For the widget, your SERVER should call POST /v1/widget-tokens to get\n' +
    'a short-lived scoped token, then pass that token to the widget as `token`.\n\n' +
    'See: https://docs.quorum.dev/sdks/js/security#api-key-storage';

  if (process.env.NODE_ENV === 'production') {
    throw new Error(msg);
  } else {
    console.error('[Quorum SDK]', msg);
  }
}

/**
 * Returns storage instructions for the given key type.
 * Embed in your onboarding UI.
 */
export function getStorageInstructions(keyType: 'live' | 'test'): StorageInstructions {
  if (keyType === 'live') {
    return {
      environment: 'server-only',
      neverIn: ['browser bundles', 'mobile apps', 'git repositories', '.env files that are committed'],
      recommended: [
        { method: 'Environment variable', example: 'export QUORUM_API_KEY="qrm_live_..."' },
        { method: 'AWS Secrets Manager', example: 'aws secretsmanager create-secret --name /quorum/api-key' },
        { method: 'Kubernetes Secret',   example: 'kubectl create secret generic quorum-key --from-literal=key=qrm_live_...' },
        { method: 'HashiCorp Vault',     example: 'vault kv put secret/quorum api_key=qrm_live_...' },
        { method: 'Docker secret',       example: 'echo "qrm_live_..." | docker secret create quorum_api_key -' },
      ],
      widgetNote: 'For the widget, call POST /v1/widget-tokens server-side and pass the result as the `token` prop.',
    };
  }
  return {
    environment: 'server-or-dev',
    neverIn: ['production deployments', 'git repositories'],
    recommended: [
      { method: 'Environment variable', example: 'export QUORUM_API_KEY="qrm_test_..."' },
      { method: '.env file (gitignored)', example: 'echo "QUORUM_API_KEY=qrm_test_..." >> .env' },
    ],
    widgetNote: 'Test keys can be used directly in Vite dev server via VITE_QUORUM_TEST_KEY.',
  };
}

export interface StorageInstructions {
  environment: string;
  neverIn:     string[];
  recommended: Array<{ method: string; example: string }>;
  widgetNote:  string;
}
