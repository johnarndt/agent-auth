from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


class AgentCreateRequest(BaseModel):
    slug: str
    name: str
    type: Literal["interactive", "service", "workflow", "mcp", "cli"]
    ownerType: Literal["user", "organization", "app", "environment"]
    ownerId: str
    createdByUserId: str | None = None
    trustLevel: Literal["unverified", "verified", "internal", "privileged"] = "unverified"
    authMethod: Literal["api_key", "oauth_client", "device_code", "signed_token"] = "api_key"
    description: str | None = None
    metadata: dict[str, Any] | None = None


class EnrollmentTokenCreateRequest(BaseModel):
    ownerType: Literal["user", "organization", "app", "environment"]
    ownerId: str
    intendedAgentType: Literal["interactive", "service", "workflow", "mcp", "cli"]
    ttlMinutes: int = Field(default=60, ge=5, le=1440)
    createdByUserId: str | None = None


class AgentEnrollRequest(BaseModel):
    registrationToken: str
    name: str
    type: Literal["interactive", "service", "workflow", "mcp", "cli"]
    requestedCapabilities: list[str]
    metadata: dict[str, Any] | None = None
    requestedByType: Literal["cli", "api", "web"] = "api"


class GrantCreateRequest(BaseModel):
    capability: str
    scopeType: Literal["organization", "project", "workspace", "resource"]
    scopeId: str
    conditions: dict[str, Any] | None = None
    expiresAt: str | None = None
    grantedByUserId: str | None = None


class AuthorizeRequest(BaseModel):
    agentId: str
    capability: str
    resource: dict[str, str]
    context: dict[str, Any] | None = None


class ActionReportRequest(BaseModel):
    agentId: str
    actionType: str
    capability: str | None = None
    resourceType: str | None = None
    resourceId: str | None = None
    metadata: dict[str, Any] | None = None


class DecisionResponse(BaseModel):
    allowed: bool
    reason: str
    policy: dict[str, Any] | None = None
