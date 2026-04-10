"""Tests for Phase 5: Agent is Resource."""

import pytest
import asyncio
import threading
import time
from participants.agent import Agent
from participants.auth_server import AuthServer
from participants.user_simulator import UserSimulator
from aauth.tokens.auth_token import parse_token_claims


def run_server(server):
    """Run a server in a separate thread."""
    try:
        server.run()
    except:
        pass


@pytest.mark.asyncio
async def test_agent_is_resource_flow():
    """Test that agent can request authorization to itself."""
    agent_id = "http://127.0.0.1:8051"
    auth_id = "http://127.0.0.1:8053"
    agent = Agent(agent_id, port=8051, use_user_simulator=True)
    auth_server = AuthServer(auth_id, port=8053, require_user_consent=True)

    # Start agent server (auth server needs to fetch agent's JWKS)
    agent_thread = threading.Thread(target=run_server, args=(agent,), daemon=True)
    agent_thread.start()

    # Start auth server in background
    auth_thread = threading.Thread(target=run_server, args=(auth_server,), daemon=True)
    auth_thread.start()

    # Wait for servers to start
    await asyncio.sleep(1)
    
    try:
        # Request self-authorization
        scope = "profile email"
        auth_token = await agent.request_self_authorization(
            scope=scope,
            auth_server=auth_id,
        )
        
        # Verify token was obtained
        assert auth_token is not None, "Auth token should be obtained"
        
        # Parse token claims
        claims = parse_token_claims(auth_token)
        payload = claims["payload"]
        
        # Verify aud = agent identifier
        assert payload.get("aud") == agent_id, f"aud should be agent identifier, got {payload.get('aud')}"
        
        # Verify agent claim is omitted
        assert "agent" not in payload, "agent claim should be omitted when agent is resource"
        
        # Verify sub claim is present (user identifier)
        assert payload.get("sub") is not None, "sub claim should be present after user consent"
        
        # Verify scope
        assert payload.get("scope") == scope, f"scope should match requested scope, got {payload.get('scope')}"
        
    finally:
        # Cleanup
        pass


@pytest.mark.asyncio
async def test_auth_token_claims_when_agent_is_resource():
    """Test that auth token has correct claims when agent is resource."""
    agent_id = "http://127.0.0.1:8061"
    auth_id = "http://127.0.0.1:8063"
    agent = Agent(agent_id, port=8061, use_user_simulator=True)
    auth_server = AuthServer(auth_id, port=8063, require_user_consent=True)

    # Start agent server (auth server needs to fetch agent's JWKS)
    agent_thread = threading.Thread(target=run_server, args=(agent,), daemon=True)
    agent_thread.start()

    # Start auth server in background
    auth_thread = threading.Thread(target=run_server, args=(auth_server,), daemon=True)
    auth_thread.start()

    # Wait for servers to start
    await asyncio.sleep(1)
    
    try:
        # Request self-authorization
        scope = "profile email"
        auth_token = await agent.request_self_authorization(
            scope=scope,
            auth_server=auth_id,
        )
        
        assert auth_token is not None
        
        # Parse and verify claims
        claims = parse_token_claims(auth_token)
        payload = claims["payload"]
        header = claims["header"]
        
        # Verify token type
        assert header.get("typ") == "aa-auth+jwt", "Token type should be auth+jwt"
        
        # Verify aud = agent identifier
        assert payload.get("aud") == agent_id
        
        # Verify agent claim is omitted
        assert "agent" not in payload
        
        # Verify sub is present
        assert "sub" in payload
        assert payload.get("sub") == "testuser"  # From user simulator
        
        # Verify scope
        assert payload.get("scope") == scope
        
        # Verify cnf.jwk is present
        assert "cnf" in payload
        assert "jwk" in payload["cnf"]
        
    finally:
        pass

