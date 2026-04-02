class A {
  constructor(e) {
    this.baseURL = e.baseURL.replace(/\/$/, ""), this.headers = {
      Authorization: `Bearer ${e.apiKey}`,
      "Content-Type": "application/json"
    };
  }
  // ── Requests ──────────────────────────────────────────────────────────────
  async createRequest(e) {
    return this.post("/v1/requests", {
      group_id: e.groupId,
      action_descriptor: e.actionDescriptor,
      payload_hash: e.payloadHash,
      expires_in: e.expiresIn ?? 300,
      metadata: e.metadata
    });
  }
  async getRequest(e) {
    return this.get(`/v1/requests/${e}`);
  }
  async revokeRequest(e) {
    await this.delete(`/v1/requests/${e}`);
  }
  // ── Authorisation ─────────────────────────────────────────────────────────
  async authorize(e) {
    return this.post("/v1/authorize", {
      request_id: e.requestId,
      member_id: e.memberId,
      share_hex: e.shareHex,
      token: e.token
    });
  }
  // ── Webhooks ──────────────────────────────────────────────────────────────
  async createWebhook(e, t, s) {
    return this.post("/v1/webhooks", { url: e, events: t, secret: s });
  }
  async listWebhooks() {
    return this.get("/v1/webhooks");
  }
  async deleteWebhook(e) {
    await this.delete(`/v1/webhooks/${e}`);
  }
  // ── Groups ────────────────────────────────────────────────────────────────
  async getGroup(e) {
    return this.get(`/v1/groups/${e}`);
  }
  // ── API Keys ──────────────────────────────────────────────────────────────
  /** Creates an API key. The raw key is returned ONCE — store it securely. */
  async createAPIKey(e) {
    return this.post("/v1/api-keys", { name: e });
  }
  async listAPIKeys() {
    return this.get("/v1/api-keys");
  }
  async revokeAPIKey(e) {
    await this.delete(`/v1/api-keys/${e}`);
  }
  // ── Audit ─────────────────────────────────────────────────────────────────
  async getAuditLog(e) {
    const t = new URLSearchParams();
    e != null && e.requestId && t.set("request_id", e.requestId), e != null && e.groupId && t.set("group_id", e.groupId), e != null && e.eventType && t.set("event_type", e.eventType), e != null && e.since && t.set("since", e.since), e != null && e.until && t.set("until", e.until), e != null && e.limit && t.set("limit", String(e.limit)), e != null && e.cursor && t.set("cursor", e.cursor);
    const s = t.toString() ? `?${t.toString()}` : "";
    return this.get(`/v1/audit${s}`);
  }
  // ── Internal HTTP helpers ─────────────────────────────────────────────────
  async get(e) {
    const t = await fetch(`${this.baseURL}${e}`, { headers: this.headers });
    return this.parseResponse(t);
  }
  async post(e, t) {
    const s = await fetch(`${this.baseURL}${e}`, {
      method: "POST",
      headers: this.headers,
      body: JSON.stringify(t)
    });
    return this.parseResponse(s);
  }
  async delete(e) {
    const t = await fetch(`${this.baseURL}${e}`, {
      method: "DELETE",
      headers: this.headers
    });
    t.status !== 204 && await this.parseResponse(t);
  }
  async parseResponse(e) {
    let t;
    if ((e.headers.get("content-type") ?? "").includes("application/json") ? t = await e.json() : t = await e.text(), !e.ok) {
      const i = t;
      throw Object.assign(new Error((i == null ? void 0 : i.error) ?? `HTTP ${e.status}`), {
        statusCode: e.status
      });
    }
    return t;
  }
}
const h = 65536, u = 3, a = 1, y = 32, c = 6, r = 32;
async function v(n, e) {
  var i;
  if (n.length < c)
    throw new Error(`PIN must be at least ${c} characters`);
  if (e.length !== r * 2)
    throw new Error(`salt_hex must be ${r * 2} hex characters (${r} bytes)`);
  const t = l(e), s = new TextEncoder().encode(n);
  return typeof process < "u" && ((i = process.versions) != null && i.node) ? w(s, t) : d(s, t);
}
async function d(n, e) {
  const { hash: t, ArgonType: s } = await import("argon2-browser"), i = await t({
    pass: n,
    salt: e,
    type: s.Argon2id,
    mem: h,
    time: u,
    parallelism: a,
    hashLen: y
  });
  return o(i.hash);
}
async function w(n, e) {
  try {
    const { hash: t } = await import("@node-rs/argon2"), s = await t(n, {
      salt: e,
      algorithm: 2,
      // Argon2id
      memoryCost: h,
      timeCost: u,
      parallelism: a,
      outputLen: y
    });
    return o(typeof s == "string" ? l(s) : new Uint8Array(s));
  } catch {
    return d(n, e);
  }
}
async function _(n, e, t) {
  const s = typeof n == "string" ? new TextEncoder().encode(n) : new Uint8Array(n), i = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(e),
    { name: "HMAC", hash: "SHA-256" },
    !1,
    ["sign"]
  ), g = await crypto.subtle.sign("HMAC", i, s), f = "sha256=" + o(new Uint8Array(g));
  return b(f, t);
}
function l(n) {
  const e = new Uint8Array(n.length / 2);
  for (let t = 0; t < n.length; t += 2)
    e[t / 2] = parseInt(n.substring(t, t + 2), 16);
  return e;
}
function o(n) {
  return Array.from(n).map((e) => e.toString(16).padStart(2, "0")).join("");
}
function b(n, e) {
  if (n.length !== e.length) return !1;
  let t = 0;
  for (let s = 0; s < n.length; s++)
    t |= n.charCodeAt(s) ^ e.charCodeAt(s);
  return t === 0;
}
export {
  A as QuorumClient,
  v as deriveShare,
  _ as verifyWebhookSignature
};
