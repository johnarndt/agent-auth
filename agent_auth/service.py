from __future__ import annotations

import hashlib
import json
import secrets
import uuid
from datetime import datetime, timedelta, timezone

from agent_auth.db import connection_ctx


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _hash_secret(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:16]}"


def create_agent(payload: dict) -> dict:
    agent = {
        "id": _id("agt"),
        "slug": payload["slug"],
        "name": payload["name"],
        "type": payload["type"],
        "owner_type": payload["ownerType"],
        "owner_id": payload["ownerId"],
        "created_by_user_id": payload.get("createdByUserId"),
        "status": "active",
        "trust_level": payload["trustLevel"],
        "auth_method": payload["authMethod"],
        "description": payload.get("description"),
        "metadata_json": json.dumps(payload.get("metadata") or {}),
        "created_at": _now_iso(),
        "updated_at": _now_iso(),
    }

    with connection_ctx() as conn:
        conn.execute(
            """
            INSERT INTO agents (id, slug, name, type, owner_type, owner_id, created_by_user_id,
                                status, trust_level, auth_method, description, metadata_json,
                                created_at, updated_at)
            VALUES (:id, :slug, :name, :type, :owner_type, :owner_id, :created_by_user_id,
                    :status, :trust_level, :auth_method, :description, :metadata_json,
                    :created_at, :updated_at)
            """,
            agent,
        )

    log_event(agent["id"], "agent.created", "user", agent["created_by_user_id"], "agent", agent["id"], None, "allow", "created")
    return get_agent(agent["id"])


def create_registration_token(payload: dict) -> dict:
    token_plain = f"rtk_{secrets.token_urlsafe(24)}"
    token = {
        "id": _id("rtk"),
        "owner_type": payload["ownerType"],
        "owner_id": payload["ownerId"],
        "token_hash": _hash_secret(token_plain),
        "intended_agent_type": payload["intendedAgentType"],
        "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=payload["ttlMinutes"])).isoformat(),
        "used_at": None,
        "created_by_user_id": payload.get("createdByUserId"),
        "created_at": _now_iso(),
    }
    with connection_ctx() as conn:
        conn.execute(
            """
            INSERT INTO registration_tokens
            (id, owner_type, owner_id, token_hash, intended_agent_type, expires_at, used_at, created_by_user_id, created_at)
            VALUES (:id, :owner_type, :owner_id, :token_hash, :intended_agent_type, :expires_at, :used_at, :created_by_user_id, :created_at)
            """,
            token,
        )
    return {
        "tokenId": token["id"],
        "registrationToken": token_plain,
        "expiresAt": token["expires_at"],
    }


def enroll_agent(payload: dict) -> dict:
    token_hash = _hash_secret(payload["registrationToken"])
    with connection_ctx() as conn:
        row = conn.execute(
            "SELECT * FROM registration_tokens WHERE token_hash = ?",
            (token_hash,),
        ).fetchone()
        if not row:
            raise ValueError("invalid_registration_token")
        if row["used_at"] is not None:
            raise ValueError("registration_token_already_used")
        if datetime.fromisoformat(row["expires_at"]) < datetime.now(timezone.utc):
            raise ValueError("registration_token_expired")

        agent_id = _id("agt")
        conn.execute(
            """
            INSERT INTO agents (id, slug, name, type, owner_type, owner_id, status, trust_level,
                                auth_method, metadata_json, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                agent_id,
                f"{payload['name'].lower().replace(' ', '-')}-{agent_id[-6:]}",
                payload["name"],
                payload["type"],
                row["owner_type"],
                row["owner_id"],
                "pending",
                "unverified",
                "api_key",
                json.dumps(payload.get("metadata") or {}),
                _now_iso(),
                _now_iso(),
            ),
        )

        request_id = _id("enr")
        conn.execute(
            """
            INSERT INTO enrollment_requests
            (id, agent_id, requested_by_type, registration_token_id, requested_capabilities_json, status, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                request_id,
                agent_id,
                payload.get("requestedByType", "api"),
                row["id"],
                json.dumps(payload.get("requestedCapabilities") or []),
                "pending",
                _now_iso(),
            ),
        )
        conn.execute("UPDATE registration_tokens SET used_at = ? WHERE id = ?", (_now_iso(), row["id"]))

    log_event(agent_id, "agent.enrollment_requested", "agent", agent_id, "enrollment_request", request_id, None, "allow", "pending_approval")
    return {
        "agentId": agent_id,
        "status": "pending_approval",
        "enrollmentRequestId": request_id,
        "nextAction": {"type": "browser_approval", "url": f"/enroll/{request_id}"},
    }


def approve_enrollment(request_id: str, reviewer_id: str | None, notes: str | None, approve: bool) -> dict:
    with connection_ctx() as conn:
        req = conn.execute("SELECT * FROM enrollment_requests WHERE id = ?", (request_id,)).fetchone()
        if not req:
            raise ValueError("enrollment_request_not_found")
        if req["status"] != "pending":
            raise ValueError("enrollment_request_not_pending")

        status = "approved" if approve else "denied"
        conn.execute(
            "UPDATE enrollment_requests SET status = ?, reviewed_by_user_id = ?, review_notes = ?, reviewed_at = ? WHERE id = ?",
            (status, reviewer_id, notes, _now_iso(), request_id),
        )

        agent_status = "active" if approve else "revoked"
        conn.execute("UPDATE agents SET status = ?, updated_at = ? WHERE id = ?", (agent_status, _now_iso(), req["agent_id"]))

        credential = None
        if approve:
            secret = f"ask_{secrets.token_urlsafe(24)}"
            cred = {
                "id": _id("acr"),
                "agent_id": req["agent_id"],
                "kind": "api_key",
                "public_id": f"pk_{secrets.token_hex(6)}",
                "secret_hash": _hash_secret(secret),
                "last_used_at": None,
                "expires_at": None,
                "revoked_at": None,
                "created_at": _now_iso(),
            }
            conn.execute(
                """
                INSERT INTO agent_credentials
                (id, agent_id, kind, public_id, secret_hash, last_used_at, expires_at, revoked_at, created_at)
                VALUES (:id, :agent_id, :kind, :public_id, :secret_hash, :last_used_at, :expires_at, :revoked_at, :created_at)
                """,
                cred,
            )
            requested = json.loads(req["requested_capabilities_json"])
            for cap_key in requested:
                cap = conn.execute("SELECT id FROM capabilities WHERE key = ?", (cap_key,)).fetchone()
                if not cap:
                    continue
                conn.execute(
                    """
                    INSERT INTO agent_capability_grants
                    (id, agent_id, capability_id, scope_type, scope_id, conditions_json, expires_at, granted_by_user_id, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (_id("grt"), req["agent_id"], cap["id"], "organization", "default", "{}", None, reviewer_id, _now_iso()),
                )
            credential = {"type": "api_key", "token": secret}

    log_event(req["agent_id"], "agent.enrollment_reviewed", "user", reviewer_id, "enrollment_request", request_id, None, "allow" if approve else "deny", status)
    return {
        "agentId": req["agent_id"],
        "status": "active" if approve else "denied",
        "credential": credential,
    }


def create_grant(agent_id: str, payload: dict) -> dict:
    with connection_ctx() as conn:
        cap = conn.execute("SELECT id, key FROM capabilities WHERE key = ?", (payload["capability"],)).fetchone()
        if not cap:
            raise ValueError("capability_not_found")
        grant = {
            "id": _id("grt"),
            "agent_id": agent_id,
            "capability_id": cap["id"],
            "scope_type": payload["scopeType"],
            "scope_id": payload["scopeId"],
            "conditions_json": json.dumps(payload.get("conditions") or {}),
            "expires_at": payload.get("expiresAt"),
            "granted_by_user_id": payload.get("grantedByUserId"),
            "created_at": _now_iso(),
        }
        conn.execute(
            """
            INSERT INTO agent_capability_grants
            (id, agent_id, capability_id, scope_type, scope_id, conditions_json, expires_at, granted_by_user_id, created_at)
            VALUES (:id, :agent_id, :capability_id, :scope_type, :scope_id, :conditions_json, :expires_at, :granted_by_user_id, :created_at)
            """,
            grant,
        )
    log_event(agent_id, "grant.created", "user", payload.get("grantedByUserId"), "grant", grant["id"], payload["capability"], "allow", "granted")
    return {
        "id": grant["id"],
        "agentId": agent_id,
        "capability": payload["capability"],
        "scopeType": payload["scopeType"],
        "scopeId": payload["scopeId"],
        "conditions": payload.get("conditions") or {},
        "expiresAt": payload.get("expiresAt"),
    }


def list_capabilities() -> list[dict]:
    with connection_ctx() as conn:
        rows = conn.execute("SELECT key, name, description, resource_type, risk_level FROM capabilities ORDER BY key").fetchall()
    return [dict(r) for r in rows]


def authorize(payload: dict) -> dict:
    with connection_ctx() as conn:
        agent = conn.execute("SELECT id, status FROM agents WHERE id = ?", (payload["agentId"],)).fetchone()
        if not agent:
            reason = "agent_not_found"
            allowed = False
        elif agent["status"] != "active":
            reason = "agent_not_active"
            allowed = False
        else:
            grant = conn.execute(
                """
                SELECT g.conditions_json, g.scope_type, g.scope_id
                FROM agent_capability_grants g
                JOIN capabilities c ON c.id = g.capability_id
                WHERE g.agent_id = ? AND c.key = ?
                """,
                (payload["agentId"], payload["capability"]),
            ).fetchone()
            if not grant:
                reason = "capability_not_granted"
                allowed = False
            else:
                conditions = json.loads(grant["conditions_json"] or "{}")
                resource = payload.get("resource") or {}
                if resource.get("id") and grant["scope_id"] not in ("default", resource.get("id")):
                    reason = "resource_scope_mismatch"
                    allowed = False
                elif conditions.get("humanApprovalRequired"):
                    reason = "human_approval_required"
                    allowed = False
                else:
                    reason = "allowed"
                    allowed = True

    log_event(payload["agentId"], "capability.check", "agent", payload["agentId"], payload.get("resource", {}).get("type"), payload.get("resource", {}).get("id"), payload["capability"], "allow" if allowed else "deny", reason)
    return {"allowed": allowed, "reason": reason, "policy": None if allowed else {"approvalRequired": reason == "human_approval_required"}}


def report_action(payload: dict) -> dict:
    log_event(
        payload["agentId"],
        "action.reported",
        "agent",
        payload["agentId"],
        payload.get("resourceType"),
        payload.get("resourceId"),
        payload.get("capability"),
        "allow",
        payload["actionType"],
        payload.get("metadata"),
    )
    return {"status": "recorded"}


def log_event(agent_id, event_type, actor_type, actor_id, resource_type, resource_id, capability, decision, reason, metadata=None):
    with connection_ctx() as conn:
        conn.execute(
            """
            INSERT INTO agent_audit_events
            (id, agent_id, event_type, actor_type, actor_id, resource_type, resource_id, capability, decision, reason, metadata_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                _id("evt"),
                agent_id,
                event_type,
                actor_type,
                actor_id,
                resource_type,
                resource_id,
                capability,
                decision,
                reason,
                json.dumps(metadata or {}),
                _now_iso(),
            ),
        )


def get_agent(agent_id: str) -> dict:
    with connection_ctx() as conn:
        row = conn.execute("SELECT * FROM agents WHERE id = ?", (agent_id,)).fetchone()
    if not row:
        raise ValueError("agent_not_found")
    data = dict(row)
    data["metadata"] = json.loads(data.pop("metadata_json") or "{}")
    return data


def list_agents() -> list[dict]:
    with connection_ctx() as conn:
        rows = conn.execute("SELECT * FROM agents ORDER BY created_at DESC").fetchall()
    agents = []
    for row in rows:
        data = dict(row)
        data["metadata"] = json.loads(data.pop("metadata_json") or "{}")
        agents.append(data)
    return agents


def list_audit_events(limit: int = 100) -> list[dict]:
    with connection_ctx() as conn:
        rows = conn.execute("SELECT * FROM agent_audit_events ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
    events = []
    for row in rows:
        event = dict(row)
        event["metadata"] = json.loads(event.pop("metadata_json") or "{}")
        events.append(event)
    return events


def revoke_agent(agent_id: str, actor_id: str | None = None) -> dict:
    with connection_ctx() as conn:
        conn.execute("UPDATE agents SET status = 'revoked', updated_at = ? WHERE id = ?", (_now_iso(), agent_id))
    log_event(agent_id, "agent.revoked", "user", actor_id, "agent", agent_id, None, "allow", "revoked")
    return {"agentId": agent_id, "status": "revoked"}


def suspend_agent(agent_id: str, actor_id: str | None = None) -> dict:
    with connection_ctx() as conn:
        conn.execute("UPDATE agents SET status = 'suspended', updated_at = ? WHERE id = ?", (_now_iso(), agent_id))
    log_event(agent_id, "agent.suspended", "user", actor_id, "agent", agent_id, None, "allow", "suspended")
    return {"agentId": agent_id, "status": "suspended"}


def delete_grant(grant_id: str) -> None:
    with connection_ctx() as conn:
        row = conn.execute("SELECT agent_id FROM agent_capability_grants WHERE id = ?", (grant_id,)).fetchone()
        conn.execute("DELETE FROM agent_capability_grants WHERE id = ?", (grant_id,))
    if row:
        log_event(row["agent_id"], "grant.revoked", "user", None, "grant", grant_id, None, "allow", "revoked")
