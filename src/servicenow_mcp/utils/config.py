"""
Configuration module for the ServiceNow MCP server.
"""

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class AuthType(str, Enum):
    """Authentication types supported by the ServiceNow MCP server."""

    BASIC = "basic"
    OAUTH = "oauth"
    API_KEY = "api_key"


class BasicAuthConfig(BaseModel):
    """Configuration for basic authentication."""

    username: str
    password: str


class OAuthConfig(BaseModel):
        """Configuration for OAuth authentication.

        Supports:
            - client_credentials (username/password omitted)
            - password grant (username/password provided)
            - authorization code + PKCE (redirect_url provided; code exchanged via callback)
        The AuthManager first attempts client_credentials, then password grant (if creds present),
        or uses a previously set access token (PKCE flow).
        """

        client_id: str
        client_secret: str
        username: Optional[str] = None
        password: Optional[str] = None
        token_url: Optional[str] = None
        redirect_url: Optional[str] = None  # Needed for authorization code flow


class ApiKeyConfig(BaseModel):
    """Configuration for API key authentication."""

    api_key: str
    header_name: str = "X-ServiceNow-API-Key"


class AuthConfig(BaseModel):
    """Authentication configuration."""

    type: AuthType
    basic: Optional[BasicAuthConfig] = None
    oauth: Optional[OAuthConfig] = None
    api_key: Optional[ApiKeyConfig] = None


class ServerConfig(BaseModel):
    """Server configuration."""

    instance_url: str
    auth: AuthConfig
    debug: bool = False
    timeout: int = 30

    @property
    def api_url(self) -> str:
        """Get the API URL for the ServiceNow instance."""
        return f"{self.instance_url}/api/now"
