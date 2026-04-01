"""quorum.crypto — Argon2id share derivation and webhook signature verification.

Argon2id parameters match quorum-engine/src/crypto/kdf.rs exactly:
    m_cost   = 65_536 KiB  (64 MB)
    t_cost   = 3
    p_cost   = 1
    hash_len = 32 bytes
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
from typing import Union

from argon2.low_level import hash_secret_raw, Type

# ── Constants — must match quorum-engine kdf.rs ───────────────────────────────
_M_COST    = 65_536   # KiB
_T_COST    = 3
_P_COST    = 1
_HASH_LEN  = 32
_SALT_LEN  = 32
_MIN_PIN   = 6


def derive_share(pin: str, salt_hex: str) -> str:
    """Derive an Argon2id key share from a PIN and hex-encoded salt.

    This is the server-side path for USSD members or server-to-server
    share computation. Browser members use the JS SDK instead.

    Args:
        pin:      The member's PIN or passphrase (min 6 characters).
        salt_hex: The member's unique 32-byte salt, hex-encoded (64 chars).

    Returns:
        The 32-byte share as a lowercase hex string.

    Raises:
        ValueError: If the PIN is too short or the salt is the wrong length.

    Example::

        share = derive_share("284751", "a3f2e1d4..." * 2)
        # submit to POST /v1/authorize as share_hex
    """
    if len(pin) < _MIN_PIN:
        raise ValueError(f"PIN must be at least {_MIN_PIN} characters")

    if len(salt_hex) != _SALT_LEN * 2:
        raise ValueError(f"salt_hex must be {_SALT_LEN * 2} hex characters")

    try:
        salt = bytes.fromhex(salt_hex)
    except ValueError as exc:
        raise ValueError(f"salt_hex is not valid hex: {exc}") from exc

    raw = hash_secret_raw(
        secret=pin.encode(),
        salt=salt,
        time_cost=_T_COST,
        memory_cost=_M_COST,
        parallelism=_P_COST,
        hash_len=_HASH_LEN,
        type=Type.ID,
    )
    return raw.hex()


def verify_webhook_signature(
    payload:   Union[bytes, str],
    secret:    str,
    signature: str,
) -> bool:
    """Verify a Quorum webhook HMAC-SHA256 signature.

    Quorum signs webhook payloads with HMAC-SHA256. The signature arrives in
    the ``X-Quorum-Signature-256`` header as ``sha256=<hex>``.

    Uses ``hmac.compare_digest`` for constant-time comparison.

    Args:
        payload:   The raw request body (bytes or str).
        secret:    The webhook signing secret provided at registration.
        signature: The full value of the X-Quorum-Signature-256 header.

    Returns:
        True if the signature is valid, False otherwise.

    Example (Flask)::

        from flask import request
        from quorum import verify_webhook_signature

        @app.route("/webhooks/quorum", methods=["POST"])
        def handle():
            sig = request.headers.get("X-Quorum-Signature-256", "")
            if not verify_webhook_signature(request.data, WEBHOOK_SECRET, sig):
                return "Unauthorized", 401
            event = request.json
            ...
    """
    if isinstance(payload, str):
        payload = payload.encode()

    mac = hmac.new(secret.encode(), payload, hashlib.sha256)
    expected = f"sha256={mac.hexdigest()}"
    return hmac.compare_digest(expected, signature)


def generate_salt() -> str:
    """Generate a cryptographically random 32-byte salt, hex-encoded.

    Used during group enrolment ceremonies. Each member gets a unique salt.

    Returns:
        64-character lowercase hex string.
    """
    return secrets.token_hex(_SALT_LEN)
