"""
Agent Authentication Module

Provides authentication and authorization for inter-agent communication.

All inter-agent calls must be authenticated using a valid token issued by
AgentAuthenticator. Tokens are validated on every request. The is_internal
flag does not bypass security checks; all agents must present a valid,
verified identity regardless of origin.
"""

from .agent_auth import AgentAuthenticator, AgentIdentity, AuthResult

__all__ = ["AgentAuthenticator", "AgentIdentity", "AuthResult"]
