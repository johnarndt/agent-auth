from __future__ import annotations

from fastapi import FastAPI, HTTPException, Query

from agent_auth.db import init_db
from agent_auth.schemas import (
    ActionReportRequest,
    AgentCreateRequest,
    AgentEnrollRequest,
    AuthorizeRequest,
    DecisionResponse,
    EnrollmentTokenCreateRequest,
    GrantCreateRequest,
)
from agent_auth.service import (
    approve_enrollment,
    authorize,
    create_agent,
    create_grant,
    create_registration_token,
    delete_grant,
    enroll_agent,
    get_agent,
    list_agents,
    list_audit_events,
    list_capabilities,
    report_action,
    revoke_agent,
    suspend_agent,
)

app = FastAPI(title="AgentOS Auth", version="0.1.0")
init_db()


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/v1/agents")
def create_agent_route(request: AgentCreateRequest) -> dict:
    try:
        return create_agent(request.model_dump())
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/v1/agents")
def list_agents_route() -> list[dict]:
    return list_agents()


@app.get("/v1/agents/{agent_id}")
def get_agent_route(agent_id: str) -> dict:
    try:
        return get_agent(agent_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.post("/v1/agents/{agent_id}/suspend")
def suspend_agent_route(agent_id: str, actorId: str | None = None) -> dict:
    return suspend_agent(agent_id, actorId)


@app.post("/v1/agents/{agent_id}/revoke")
def revoke_agent_route(agent_id: str, actorId: str | None = None) -> dict:
    return revoke_agent(agent_id, actorId)


@app.post("/v1/enrollment-tokens")
def create_enrollment_token_route(request: EnrollmentTokenCreateRequest) -> dict:
    return create_registration_token(request.model_dump())


@app.post("/v1/agents/enroll")
def enroll_agent_route(request: AgentEnrollRequest) -> dict:
    try:
        return enroll_agent(request.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/v1/enrollment-requests/{request_id}/approve")
def approve_enrollment_route(request_id: str, reviewerId: str | None = None, notes: str | None = None) -> dict:
    try:
        return approve_enrollment(request_id, reviewerId, notes, approve=True)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/v1/enrollment-requests/{request_id}/deny")
def deny_enrollment_route(request_id: str, reviewerId: str | None = None, notes: str | None = None) -> dict:
    try:
        return approve_enrollment(request_id, reviewerId, notes, approve=False)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/v1/capabilities")
def capabilities_route() -> list[dict]:
    return list_capabilities()


@app.post("/v1/agents/{agent_id}/grants")
def grant_route(agent_id: str, request: GrantCreateRequest) -> dict:
    try:
        return create_grant(agent_id, request.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.delete("/v1/grants/{grant_id}", status_code=204)
def delete_grant_route(grant_id: str) -> None:
    delete_grant(grant_id)


@app.post("/v1/authorize", response_model=DecisionResponse)
def authorize_route(request: AuthorizeRequest) -> dict:
    return authorize(request.model_dump())


@app.post("/v1/report-action")
def report_action_route(request: ActionReportRequest) -> dict:
    return report_action(request.model_dump())


@app.get("/v1/audit-events")
def audit_events_route(limit: int = Query(default=100, ge=1, le=500)) -> list[dict]:
    return list_audit_events(limit)
