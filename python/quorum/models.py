"""quorum.models — Response model dataclasses."""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class AuthRequest:
    id: str
    group_id: str
    action_descriptor: str
    payload_hash: str
    status: str
    authorisations_received: int = 0
    threshold_required: int = 0
    expires_at: str = ""
    created_at: str = ""
    updated_at: str = ""
    org_id: str = ""
    metadata: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        # camelCase → snake_case aliases from API
        pass


@dataclass
class AuthorizeResult:
    status: str
    approved: Optional[bool] = None
    progress: Optional[int] = None
    threshold: Optional[int] = None


@dataclass
class Webhook:
    id: str
    url: str
    events: list
    created_at: str = ""
    org_id: str = ""


@dataclass
class APIKey:
    id: str
    name: str
    prefix: str
    created_at: str = ""
    key: Optional[str] = None   # only present at creation
