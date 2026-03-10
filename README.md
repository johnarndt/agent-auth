# AgentOS for Better Auth

Agent identity + authorization service for non-human actors.

This repository now includes a working API service with:

- Agent lifecycle (`create`, `list`, `suspend`, `revoke`)
- Enrollment token issuance + agent enrollment requests
- Approval/denial flow that can issue API credentials
- Capability catalog + capability grants
- Runtime authorization checks (`/v1/authorize`)
- Action/audit event reporting (`/v1/report-action`, `/v1/audit-events`)

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn agent_auth.main:app --reload
```

Service starts on `http://127.0.0.1:8000`.

## Core endpoints

### Admin / Agent lifecycle

- `POST /v1/agents`
- `GET /v1/agents`
- `GET /v1/agents/{id}`
- `POST /v1/agents/{id}/suspend`
- `POST /v1/agents/{id}/revoke`

### Enrollment

- `POST /v1/enrollment-tokens`
- `POST /v1/agents/enroll`
- `POST /v1/enrollment-requests/{id}/approve`
- `POST /v1/enrollment-requests/{id}/deny`

### Capability + runtime auth

- `GET /v1/capabilities`
- `POST /v1/agents/{id}/grants`
- `DELETE /v1/grants/{id}`
- `POST /v1/authorize`

### Audit

- `POST /v1/report-action`
- `GET /v1/audit-events`

## Storage

SQLite database initialized automatically at:

- `data/agent_auth.db`

Schema includes:

- `agents`
- `agent_credentials`
- `capabilities`
- `agent_capability_grants`
- `registration_tokens`
- `enrollment_requests`
- `agent_audit_events`
