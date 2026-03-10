from agent_auth.db import init_db
from agent_auth.service import create_agent, list_agents


def test_create_agent_and_list():
    init_db()
    payload = {
        "slug": "billing-bot",
        "name": "Billing Bot",
        "type": "service",
        "ownerType": "organization",
        "ownerId": "org_123",
        "trustLevel": "internal",
        "authMethod": "api_key",
    }
    created = create_agent(payload)
    assert created["slug"] == "billing-bot"

    agents = list_agents()
    assert any(a["id"] == created["id"] for a in agents)
