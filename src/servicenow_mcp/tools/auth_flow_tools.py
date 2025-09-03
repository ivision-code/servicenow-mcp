"""Tools for OAuth Authorization Code + PKCE flow."""
import base64
import hashlib
import os
import secrets
import time
from typing import Optional, Dict

from pydantic import BaseModel, Field

from servicenow_mcp.auth.auth_manager import AuthManager
from servicenow_mcp.utils.config import ServerConfig, AuthType

_SESSION_STORE: Dict[str, Dict] = {}


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


class StartPKCEParams(BaseModel):
    session_hint: Optional[str] = Field(None, description="Optional client provided label")


class StartPKCEResult(BaseModel):
    session_id: str
    state: str
    authorize_url: str
    expires_in: int
    message: str


class OAuthStatusParams(BaseModel):
    session_id: str


class OAuthStatusResult(BaseModel):
    session_id: str
    authorized: bool
    expires_at: Optional[float]
    has_refresh: bool
    message: str


class SelectSessionParams(BaseModel):
    session_id: str


class SimpleResult(BaseModel):
    success: bool
    message: str


def start_oauth_pkce(config: ServerConfig, auth_manager: AuthManager, params: StartPKCEParams) -> StartPKCEResult:
    if config.auth.type != AuthType.OAUTH or not config.auth.oauth:
        raise ValueError("Server not configured for OAuth")
    oauth_cfg = config.auth.oauth
    if not oauth_cfg.redirect_url:
        raise ValueError("redirect_url not configured for OAuth PKCE flow")
    state_base = secrets.token_urlsafe(16)
    code_verifier = _b64url(os.urandom(40))
    code_challenge = _b64url(hashlib.sha256(code_verifier.encode()).digest())
    session_id = secrets.token_urlsafe(20)
    # Store session
    _SESSION_STORE[session_id] = {
    "state": state_base,
        "code_verifier": code_verifier,
        "created": time.time(),
        "authorized": False,
        "token": None,
    }
    instance_base = config.instance_url.rstrip("/")
    authorize_base = f"{instance_base}/oauth_authorize.do"
    # Encode session id into state so callback can recover it (state = base.session)
    composite_state = f"{state_base}:{session_id}"
    q = (
        f"response_type=code&client_id={oauth_cfg.client_id}"
        f"&redirect_uri={oauth_cfg.redirect_url}"
        f"&state={composite_state}&code_challenge={code_challenge}&code_challenge_method=S256"
    )
    authorize_url = f"{authorize_base}?{q}"
    return StartPKCEResult(
        session_id=session_id,
    state=composite_state,
        authorize_url=authorize_url,
        expires_in=600,
        message="Open authorize_url in a browser, approve, then status will turn authorized."
    )


def oauth_status(config: ServerConfig, auth_manager: AuthManager, params: OAuthStatusParams) -> OAuthStatusResult:
    sess = _SESSION_STORE.get(params.session_id)
    if not sess:
        return OAuthStatusResult(
            session_id=params.session_id,
            authorized=False,
            expires_at=None,
            has_refresh=False,
            message="Unknown session",
        )
    token_info = sess.get("token") or {}
    return OAuthStatusResult(
        session_id=params.session_id,
        authorized=sess.get("authorized", False),
        expires_at=token_info.get("expiry"),
        has_refresh=bool(token_info.get("refresh_token")),
        message="Authorized" if sess.get("authorized") else "Pending user authorization",
    )


def select_session(config: ServerConfig, auth_manager: AuthManager, params: SelectSessionParams) -> SimpleResult:
    sess = _SESSION_STORE.get(params.session_id)
    if not sess or not sess.get("authorized"):
        return SimpleResult(success=False, message="Session not authorized or not found")
    token_info = sess["token"]
    auth_manager.set_token(
        access_token=token_info["access_token"],
        token_type=token_info.get("token_type", "Bearer"),
        refresh_token=token_info.get("refresh_token"),
        expires_in=token_info.get("expires_in"),
    )
    return SimpleResult(success=True, message="Session selected")


def store_pkce_token(session_id: str, access_token: str, token_type: str, refresh_token: str | None, expires_in: int | None):
    sess = _SESSION_STORE.get(session_id)
    if not sess:
        return False
    sess["authorized"] = True
    sess["token"] = {
        "access_token": access_token,
        "token_type": token_type,
        "refresh_token": refresh_token,
        "expires_in": expires_in,
        "expiry": time.time() + expires_in if expires_in else None,
    }
    return True


def get_pkce_session(session_id: str) -> Dict | None:
    return _SESSION_STORE.get(session_id)
