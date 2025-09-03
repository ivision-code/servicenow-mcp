"""Authentication helper tools for interactive credential provisioning."""

from __future__ import annotations

import logging
from typing import Optional

from pydantic import BaseModel, Field

from servicenow_mcp.auth.auth_manager import AuthManager
from servicenow_mcp.utils.config import (
    ApiKeyConfig,
    AuthConfig,
    AuthType,
    BasicAuthConfig,
    OAuthConfig,
    ServerConfig,
)

logger = logging.getLogger(__name__)


class LoginBasicParams(BaseModel):
    username: str = Field(..., description="ServiceNow username")
    password: str = Field(..., description="ServiceNow password")


class LoginApiKeyParams(BaseModel):
    api_key: str = Field(..., description="API key value")
    header_name: str = Field(
        "X-ServiceNow-API-Key", description="HTTP header name for the API key"
    )


class LoginOAuthPasswordParams(BaseModel):
    client_id: str = Field(..., description="OAuth client ID")
    client_secret: str = Field(..., description="OAuth client secret")
    username: str = Field(..., description="Resource owner username")
    password: str = Field(..., description="Resource owner password")
    token_url: Optional[str] = Field(
        None, description="Explicit token URL (defaults to <instance>/oauth_token.do)"
    )


class LogoutParams(BaseModel):
    reason: Optional[str] = Field(
        None, description="Optional reason for logging out (informational only)"
    )


class AuthOperationResult(BaseModel):
    success: bool = Field(..., description="Whether the operation succeeded")
    message: str = Field(..., description="Human-readable status message")
    auth_type: Optional[str] = Field(
        None, description="Active authentication type after operation (if any)"
    )


def login_basic(
    config: ServerConfig, auth_manager: AuthManager, params: LoginBasicParams
) -> AuthOperationResult:
    """Set / overwrite Basic authentication credentials at runtime."""
    logger.info("Applying basic auth credentials via login_basic tool (username logged only)")
    config.auth.basic = BasicAuthConfig(
        username=params.username, password=params.password
    )
    config.auth.type = AuthType.BASIC
    auth_manager.token = None
    auth_manager.token_type = None
    return AuthOperationResult(
        success=True,
        message="Basic authentication credentials set successfully.",
        auth_type=config.auth.type.value,
    )


def login_api_key(
    config: ServerConfig, auth_manager: AuthManager, params: LoginApiKeyParams
) -> AuthOperationResult:
    """Set / overwrite API key authentication at runtime."""
    logger.info("Applying API key via login_api_key tool (header name logged only)")
    config.auth.api_key = ApiKeyConfig(
        api_key=params.api_key, header_name=params.header_name
    )
    config.auth.type = AuthType.API_KEY
    config.auth.basic = None
    config.auth.oauth = None
    auth_manager.token = None
    auth_manager.token_type = None
    return AuthOperationResult(
        success=True,
        message="API key authentication configured successfully.",
        auth_type=config.auth.type.value,
    )


def login_oauth_password(
    config: ServerConfig, auth_manager: AuthManager, params: LoginOAuthPasswordParams
) -> AuthOperationResult:
    """Configure OAuth password grant credentials and fetch token immediately."""
    logger.info(
        "Applying OAuth password grant configuration via login_oauth_password tool (client_id logged only)"
    )
    config.auth.oauth = OAuthConfig(
        client_id=params.client_id,
        client_secret=params.client_secret,
        username=params.username,
        password=params.password,
        token_url=params.token_url,
    )
    config.auth.type = AuthType.OAUTH
    config.auth.basic = None
    config.auth.api_key = None
    auth_manager.token = None
    auth_manager.token_type = None
    try:
        auth_manager._get_oauth_token()  # noqa: SLF001
        msg = "OAuth token acquired successfully."
        success = True
    except Exception as e:  # noqa: BLE001
        logger.error("Failed to obtain OAuth token: %s", e)
        msg = f"OAuth configuration set but token acquisition failed: {e}"
        success = False
    return AuthOperationResult(
        success=success,
        message=msg,
        auth_type=config.auth.type.value,
    )


def logout(
    config: ServerConfig, auth_manager: AuthManager, params: LogoutParams
) -> AuthOperationResult:
    """Clear all in-memory authentication credentials."""
    logger.info("Clearing in-memory authentication credentials via logout tool")
    previous_type = config.auth.type.value if isinstance(config.auth.type, AuthType) else None
    config.auth.basic = None
    config.auth.oauth = None
    config.auth.api_key = None
    auth_manager.token = None
    auth_manager.token_type = None
    return AuthOperationResult(
        success=True,
        message=(
            f"All credentials cleared. Previous auth type was '{previous_type}'. "
            + (f"Reason: {params.reason}" if params.reason else "")
        ).strip(),
        auth_type=None,
    )
