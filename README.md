# AgentOS for Better Auth

Machine identities, capability grants, signup flows, and agent governance for apps that already solved user auth.

Better Auth can handle core user identity and authentication. This project focuses on the lifecycle around **non-human actors**: org-owned agents, service identities, scoped capabilities, registration, approval, revocation, and auditability.

## Product thesis

This layer answers:

- How does an agent get created?
- Who owns it?
- What can it do?
- How does it authenticate?
- Does it need human approval?
- What does it get access to right now?
- How do we rotate, suspend, or kill it?
- How do we prove what it did?

## Core product modules

### 1) Agent Identity

Machine principal model:

- `Agent`
- `AgentCredential`
- `AgentSession`
- `AgentOwner`
- `AgentInstallation`
- `AgentProfile`

```ts
type Agent = {
  id: string
  slug: string
  name: string
  type: "interactive" | "service" | "workflow" | "mcp" | "cli"
  ownerType: "user" | "organization" | "app" | "environment"
  ownerId: string
  createdByUserId?: string
  status: "pending" | "active" | "suspended" | "revoked" | "archived"
  trustLevel: "unverified" | "verified" | "internal" | "privileged"
  authMethod: "api_key" | "oauth_client" | "device_code" | "signed_token"
  description?: string
  metadata?: Record<string, any>
  createdAt: Date
  updatedAt: Date
}
```

### 2) Capabilities + Policy

Authorization model objects:

- `Capability`
- `CapabilityGrant`
- `Policy`
- `ApprovalRequirement`
- `ResourceScope`

```ts
type CapabilityGrant = {
  id: string
  agentId: string
  capability: string
  scopeType: "organization" | "project" | "workspace" | "resource"
  scopeId: string
  conditions?: {
    maxRequestsPerMinute?: number
    allowedHours?: string[]
    ipAllowlist?: string[]
    humanApprovalRequired?: boolean
    readOnly?: boolean
  }
  expiresAt?: Date
  grantedByUserId?: string
  createdAt: Date
}
```

### 3) Agent Signup + Enrollment

Enrollment objects:

- `RegistrationToken`
- `EnrollmentRequest`
- `ApprovalFlow`
- `ConsentRecord`

Supports:

- CLI signup
- API signup
- browser approval flow
- admin approval queue
- device-code pairing
- org policy enforcement before activation

### 4) Audit + Operations

Operational governance events:

- `AuthEvent`
- `CapabilityCheckEvent`
- `ActionEvent`
- `SecretRotationEvent`
- `SuspensionEvent`

## Better Auth vs this layer

### Better Auth handles

- user signup/login
- sessions
- OAuth/OIDC basics
- API key primitives
- org membership

### This layer handles

- org-owned agents and service identities
- enrollment/bootstrap
- capability grants and approval workflows
- runtime authorization checks
- action-level audit trail

## MVP (v1)

### Core

- Create org-owned agents
- Issue agent credentials
- Define and grant capabilities
- CLI/API signup
- Optional browser-based approval
- Capability-check middleware
- Audit log of auth + actions
- Suspend/revoke/rotate credentials

### Auth modes

- API key (service/workflow)
- Device flow or one-time enrollment code (CLI/local)

### Agent types

- `service`
- `cli`
- `mcp`

## Initial schema

### `agents`

```sql
id
slug
name
type
owner_type
owner_id
created_by_user_id
status
trust_level
auth_method
description
metadata_json
created_at
updated_at
```

### `agent_credentials`

```sql
id
agent_id
kind              -- api_key, oauth_client, device_secret, jwt_signing_key
public_id
secret_hash
last_used_at
expires_at
revoked_at
created_at
```

### `capabilities`

```sql
id
key               -- calendar.read, email.send
name
description
resource_type
risk_level
created_at
```

### `agent_capability_grants`

```sql
id
agent_id
capability_id
scope_type
scope_id
conditions_json
expires_at
granted_by_user_id
created_at
```

### `enrollment_requests`

```sql
id
agent_id
requested_by_type
registration_token_id
requested_capabilities_json
status
reviewed_by_user_id
review_notes
created_at
reviewed_at
```

### `registration_tokens`

```sql
id
owner_type
owner_id
token_hash
intended_agent_type
expires_at
used_at
created_by_user_id
created_at
```

### `agent_audit_events`

```sql
id
agent_id
event_type
actor_type
actor_id
resource_type
resource_id
capability
decision
reason
metadata_json
created_at
```

## Suggested API surface

### Admin

- `POST /v1/agents`
- `GET /v1/agents`
- `GET /v1/agents/:id`
- `POST /v1/agents/:id/suspend`
- `POST /v1/agents/:id/revoke`
- `POST /v1/agents/:id/rotate-credential`

### Enrollment

- `POST /v1/enrollment-tokens`
- `POST /v1/agents/enroll`
- `POST /v1/enrollment-requests/:id/approve`
- `POST /v1/enrollment-requests/:id/deny`

### Capabilities

- `GET /v1/capabilities`
- `POST /v1/agents/:id/grants`
- `DELETE /v1/grants/:id`

### Runtime

- `POST /v1/authorize`
- `POST /v1/introspect`
- `POST /v1/report-action`

### Audit

- `GET /v1/audit-events`

## Best wedge

Start with **Invite + CLI/device-style signup**:

1. Admin creates invite
2. Agent starts signup with invite code
3. Agent requests capabilities
4. Human reviews and approves in browser
5. Agent receives bootstrap token
6. Agent exchanges token for renewable credential/session
7. Every action is checked against capability grants and logged

## One-line pitch

**Better Auth solved user auth. This adds agent enrollment, scoped authorization, and operational control.**
