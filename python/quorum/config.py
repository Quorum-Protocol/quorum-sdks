"""quorum.config — API key resolution and storage guidance.

The QuorumClient constructor can accept a key explicitly, or it will
look for one automatically in the environment.

Resolution order
----------------
1. Explicit ``api_key=`` argument to ``QuorumClient()``.
2. ``QUORUM_API_KEY`` environment variable.
3. ``QUORUM_TEST_KEY`` environment variable (test keys only).
4. Raises ``QuorumConfigError`` with storage instructions.

Recommended storage by environment
-----------------------------------
Production server (Django, FastAPI, Flask, etc.)::

    export QUORUM_API_KEY="qrm_live_..."

    # Python reads it automatically:
    client = QuorumClient(base_url="https://api.quorum.dev")

AWS Lambda / ECS::

    # Store in AWS Secrets Manager, inject as env var at runtime
    aws secretsmanager create-secret \\
        --name /quorum/api-key \\
        --secret-string "qrm_live_..."

    # In your Lambda handler, boto3 reads it:
    import boto3
    secret = boto3.client('secretsmanager').get_secret_value(
        SecretId='/quorum/api-key')['SecretString']
    client = QuorumClient(base_url=..., api_key=secret)

CI/CD (GitHub Actions, GitLab CI, CircleCI)::

    # Set QUORUM_API_KEY as a CI secret (never in the YAML file itself)
    # GitHub: Settings → Secrets → Actions → New repository secret
    # The SDK will find it automatically from the environment.

Django settings.py::

    import os
    QUORUM_API_KEY = os.environ["QUORUM_API_KEY"]  # fails fast if missing

    # Then in your view:
    from quorum import QuorumClient
    client = QuorumClient(base_url=settings.QUORUM_BASE_URL,
                          api_key=settings.QUORUM_API_KEY)

NEVER:
- Hardcode keys in source code
- Commit .env files that contain live keys
- Use live keys (qrm_live_...) in browser or mobile code
"""
from __future__ import annotations

import os
from typing import Optional


class QuorumConfigError(Exception):
    """Raised when no API key can be resolved."""


def resolve_api_key(explicit: Optional[str] = None) -> str:
    """Resolve an API key from the environment.

    Args:
        explicit: Key passed directly to the constructor. Takes priority.

    Returns:
        The resolved API key string.

    Raises:
        QuorumConfigError: If no key is found anywhere.
    """
    if explicit:
        return explicit

    if key := os.environ.get("QUORUM_API_KEY"):
        return key

    if key := os.environ.get("QUORUM_TEST_KEY"):
        _assert_test_key(key, "QUORUM_TEST_KEY")
        return key

    raise QuorumConfigError(
        "Quorum API key not found.\n\n"
        "Option 1 — environment variable (recommended):\n"
        "  export QUORUM_API_KEY='qrm_live_...'\n\n"
        "Option 2 — pass explicitly:\n"
        "  client = QuorumClient(base_url=..., api_key='qrm_live_...')\n\n"
        "Option 3 — Django/Flask settings:\n"
        "  QUORUM_API_KEY = os.environ['QUORUM_API_KEY']  # in settings.py\n\n"
        "See https://docs.quorum.dev/sdks/python#api-key-storage"
    )


def validate_key_format(key: str) -> None:
    """Validate that a key looks structurally correct.

    Raises:
        ValueError: If the key format is wrong.
    """
    if not (key.startswith("qrm_live_") or key.startswith("qrm_test_")):
        raise ValueError(
            f"Invalid API key format. Keys must start with 'qrm_live_' or "
            f"'qrm_test_'. Got: {key[:12]}..."
        )
    if len(key) < 40:
        raise ValueError("API key appears truncated — check your environment variable.")


def _assert_test_key(key: str, source: str) -> None:
    if not key.startswith("qrm_test_"):
        raise QuorumConfigError(
            f"{source} must be a test key (qrm_test_...). "
            "Never store live keys in test-designated variables."
        )
