"""quorum.client — synchronous and async REST API client."""
from __future__ import annotations

import httpx
from typing import Any, Optional

from .models import AuthRequest, AuthorizeResult, Webhook, APIKey


class QuorumClient:
    """Full REST API wrapper for the Quorum Protocol API.

    Supports both synchronous (default) and async usage.

    Example — synchronous::

        from quorum import QuorumClient
        client = QuorumClient(base_url="https://api.quorum.dev", api_key="qrm_...")
        req = client.create_request(
            group_id="...",
            action_descriptor="Approve fund transfer of UGX 5,000,000",
            payload_hash="sha256_of_the_payload",
        )

    Example — async::

        async with QuorumClient(...) as client:
            req = await client.async_create_request(...)
    """

    def __init__(self, base_url: str, api_key: str, timeout: float = 30.0) -> None:
        self._base = base_url.rstrip("/")
        self._headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }
        self._timeout = timeout

    # ── Context manager support ───────────────────────────────────────────────

    def __enter__(self) -> "QuorumClient":
        return self

    def __exit__(self, *_: Any) -> None:
        pass

    async def __aenter__(self) -> "QuorumClient":
        return self

    async def __aexit__(self, *_: Any) -> None:
        pass

    # ── Auth Requests (sync) ──────────────────────────────────────────────────

    def create_request(
        self,
        *,
        group_id: str,
        action_descriptor: str,
        payload_hash: str,
        expires_in: int = 300,
        metadata: Optional[dict] = None,
    ) -> AuthRequest:
        """Create a new multi-party auth request.

        Args:
            group_id:          UUID of the quorum group.
            action_descriptor: Human-readable description of the action.
            payload_hash:      SHA-256 of the action payload (hex).
            expires_in:        Seconds until the request expires (default 300).
            metadata:          Optional key/value pairs stored with the request.

        Returns:
            AuthRequest with status 'pending'.
        """
        resp = self._post("/v1/requests", {
            "group_id":          group_id,
            "action_descriptor": action_descriptor,
            "payload_hash":      payload_hash,
            "expires_in":        expires_in,
            **({"metadata": metadata} if metadata else {}),
        })
        return AuthRequest(**resp)

    def get_request(self, request_id: str) -> AuthRequest:
        """Fetch a request by ID."""
        return AuthRequest(**self._get(f"/v1/requests/{request_id}"))

    def revoke_request(self, request_id: str) -> None:
        """Revoke a pending request."""
        self._delete(f"/v1/requests/{request_id}")

    # ── Webhooks (sync) ───────────────────────────────────────────────────────

    def create_webhook(self, url: str, events: list[str], secret: str) -> Webhook:
        """Register a webhook endpoint."""
        resp = self._post("/v1/webhooks", {"url": url, "events": events, "secret": secret})
        return Webhook(**resp)

    def list_webhooks(self) -> list[Webhook]:
        """List all registered webhooks."""
        return [Webhook(**w) for w in self._get("/v1/webhooks")]

    def delete_webhook(self, webhook_id: str) -> None:
        """Delete a webhook registration."""
        self._delete(f"/v1/webhooks/{webhook_id}")

    # ── API Keys (sync) ───────────────────────────────────────────────────────

    def create_api_key(self, name: str) -> APIKey:
        """Create an API key. The raw key is returned ONCE — store it immediately."""
        return APIKey(**self._post("/v1/api-keys", {"name": name}))

    def list_api_keys(self) -> list[APIKey]:
        return [APIKey(**k) for k in self._get("/v1/api-keys")]

    def revoke_api_key(self, key_id: str) -> None:
        self._delete(f"/v1/api-keys/{key_id}")

    # ── Groups (sync) ─────────────────────────────────────────────────────────

    def get_group(self, group_id: str) -> dict:
        return self._get(f"/v1/groups/{group_id}")

    # ── Audit log (sync) ──────────────────────────────────────────────────────

    def get_audit_log(
        self,
        *,
        request_id: Optional[str] = None,
        event_type: Optional[str] = None,
        since: Optional[str] = None,
        until: Optional[str] = None,
        limit: int = 50,
        cursor: Optional[str] = None,
    ) -> dict:
        params: dict[str, Any] = {"limit": limit}
        if request_id: params["request_id"] = request_id
        if event_type: params["event_type"] = event_type
        if since:      params["since"]      = since
        if until:      params["until"]      = until
        if cursor:     params["cursor"]     = cursor
        return self._get("/v1/audit", params=params)

    # ── Async equivalents ─────────────────────────────────────────────────────

    async def async_create_request(self, **kwargs) -> AuthRequest:
        resp = await self._async_post("/v1/requests", {
            "group_id":          kwargs["group_id"],
            "action_descriptor": kwargs["action_descriptor"],
            "payload_hash":      kwargs["payload_hash"],
            "expires_in":        kwargs.get("expires_in", 300),
        })
        return AuthRequest(**resp)

    async def async_get_request(self, request_id: str) -> AuthRequest:
        return AuthRequest(**await self._async_get(f"/v1/requests/{request_id}"))

    async def async_create_webhook(self, url: str, events: list[str], secret: str) -> Webhook:
        return Webhook(**await self._async_post("/v1/webhooks", {"url": url, "events": events, "secret": secret}))

    # ── Internal HTTP helpers ─────────────────────────────────────────────────

    def _get(self, path: str, params: Optional[dict] = None) -> Any:
        with httpx.Client(headers=self._headers, timeout=self._timeout) as c:
            resp = c.get(f"{self._base}{path}", params=params)
            return self._parse(resp)

    def _post(self, path: str, body: dict) -> Any:
        with httpx.Client(headers=self._headers, timeout=self._timeout) as c:
            resp = c.post(f"{self._base}{path}", json=body)
            return self._parse(resp)

    def _delete(self, path: str) -> None:
        with httpx.Client(headers=self._headers, timeout=self._timeout) as c:
            resp = c.delete(f"{self._base}{path}")
            if resp.status_code == 204:
                return
            self._parse(resp)

    async def _async_get(self, path: str) -> Any:
        async with httpx.AsyncClient(headers=self._headers, timeout=self._timeout) as c:
            resp = await c.get(f"{self._base}{path}")
            return self._parse(resp)

    async def _async_post(self, path: str, body: dict) -> Any:
        async with httpx.AsyncClient(headers=self._headers, timeout=self._timeout) as c:
            resp = await c.post(f"{self._base}{path}", json=body)
            return self._parse(resp)

    @staticmethod
    def _parse(resp: httpx.Response) -> Any:
        if resp.status_code == 204:
            return None
        data = resp.json()
        if not resp.is_success:
            raise QuorumAPIError(
                message=data.get("error", f"HTTP {resp.status_code}"),
                status_code=resp.status_code,
            )
        return data


class QuorumAPIError(Exception):
    """Raised when the Quorum API returns a non-2xx response."""

    def __init__(self, message: str, status_code: int) -> None:
        super().__init__(message)
        self.status_code = status_code
