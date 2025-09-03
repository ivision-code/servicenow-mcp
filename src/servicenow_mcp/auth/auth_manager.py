"""Authentication manager for ServiceNow MCP with Basic/OAuth/API Key and PKCE support."""

import base64
import logging
import time
from typing import Dict, Optional

import requests

from servicenow_mcp.utils.config import AuthConfig, AuthType

logger = logging.getLogger(__name__)


class AuthManager:
    def __init__(self, config: AuthConfig, instance_url: str | None = None):
        self.config = config
        self.instance_url = instance_url
        self.token: Optional[str] = None
        self.refresh_token: Optional[str] = None
        self.token_expiry: Optional[float] = None
        self.token_type: Optional[str] = None

    def get_headers(self) -> Dict[str, str]:
        headers = {"Accept": "application/json", "Content-Type": "application/json"}
        if self.config.type == AuthType.BASIC:
            if not self.config.basic:
                raise ValueError("Basic auth configuration is required")
            auth_str = f"{self.config.basic.username}:{self.config.basic.password}"
            encoded = base64.b64encode(auth_str.encode()).decode()
            headers["Authorization"] = f"Basic {encoded}"
        elif self.config.type == AuthType.OAUTH:
            if not self.token:
                if (
                    self.config.oauth
                    and self.config.oauth.redirect_url
                    and not (self.config.oauth.username and self.config.oauth.password)
                ):
                    raise ValueError(
                        "No OAuth token set. Run start_oauth_pkce, authorize, then select_session."
                    )
                self._get_oauth_token()
            else:
                if self.token_expiry and time.time() > self.token_expiry - 30 and self.refresh_token:
                    try:
                        self._refresh_oauth_token()
                    except Exception:
                        self._get_oauth_token()
            headers["Authorization"] = f"{self.token_type or 'Bearer'} {self.token}"
        elif self.config.type == AuthType.API_KEY:
            if not self.config.api_key:
                raise ValueError("API key configuration is required")
            headers[self.config.api_key.header_name] = self.config.api_key.api_key
        return headers

    def _get_oauth_token(self):
        if not self.config.oauth:
            raise ValueError("OAuth configuration is required")
        oauth_config = self.config.oauth
        token_url = oauth_config.token_url
        if not token_url:
            if not self.instance_url:
                raise ValueError("Instance URL is required for OAuth authentication")
            instance_name = self.instance_url.split("//")[-1].split(".")[0]
            token_url = f"https://{instance_name}.service-now.com/oauth_token.do"
        auth_str = f"{oauth_config.client_id}:{oauth_config.client_secret}"
        auth_header = base64.b64encode(auth_str.encode()).decode()
        headers = {"Authorization": f"Basic {auth_header}", "Content-Type": "application/x-www-form-urlencoded"}
        resp = requests.post(token_url, headers=headers, data={"grant_type": "client_credentials"})
        if resp.status_code == 200:
            self._assign_token_data(resp.json())
            return
        if oauth_config.username and oauth_config.password:
            resp = requests.post(
                token_url,
                headers=headers,
                data={
                    "grant_type": "password",
                    "username": oauth_config.username,
                    "password": oauth_config.password,
                },
            )
            if resp.status_code == 200:
                self._assign_token_data(resp.json())
                return
        raise ValueError("Failed to obtain OAuth token via client_credentials or password grant")

    def refresh_access_token(self):
        if self.config.type == AuthType.OAUTH:
            if self.refresh_token:
                self._refresh_oauth_token()
            else:
                self._get_oauth_token()

    def refresh_token(self):  # alias for existing references
        self.refresh_access_token()

    def _refresh_oauth_token(self):
        if not (self.config.oauth and self.refresh_token):
            raise ValueError("No refresh token available")
        oauth_config = self.config.oauth
        token_url = oauth_config.token_url
        if not token_url:
            if not self.instance_url:
                raise ValueError("Instance URL is required for OAuth authentication")
            instance_name = self.instance_url.split("//")[-1].split(".")[0]
            token_url = f"https://{instance_name}.service-now.com/oauth_token.do"
        auth_str = f"{oauth_config.client_id}:{oauth_config.client_secret}"
        auth_header = base64.b64encode(auth_str.encode()).decode()
        headers = {"Authorization": f"Basic {auth_header}", "Content-Type": "application/x-www-form-urlencoded"}
        resp = requests.post(
            token_url,
            headers=headers,
            data={"grant_type": "refresh_token", "refresh_token": self.refresh_token},
        )
        if resp.status_code == 200:
            self._assign_token_data(resp.json())
        else:
            raise ValueError("Failed to refresh token")

    def set_token(
        self,
        access_token: str,
        token_type: str = "Bearer",
        refresh_token: str | None = None,
        expires_in: int | None = None,
    ):
        self.token = access_token
        self.token_type = token_type
        if refresh_token:
            self.refresh_token = refresh_token
        if expires_in:
            self.token_expiry = time.time() + int(expires_in)

    def _assign_token_data(self, token_data: Dict):
        self.token = token_data.get("access_token")
        self.token_type = token_data.get("token_type", "Bearer")
        self.refresh_token = token_data.get("refresh_token")
        expires_in = token_data.get("expires_in")
        if expires_in:
            self.token_expiry = time.time() + int(expires_in)

    # External token validation (used when ChatGPT supplies bearer each call)
    def validate_current_token(self) -> bool:
        if not self.token:
            return False
        try:
            base = self.instance_url.rstrip("/") if self.instance_url else None
            if not base:
                return False
            # Lightweight validation: fetch 1 sys_user record
            url = f"{base}/api/now/table/sys_user?sysparm_limit=1"
            headers = {
                "Authorization": f"{self.token_type or 'Bearer'} {self.token}",
                "Accept": "application/json",
            }
            resp = requests.get(url, headers=headers, timeout=5)
            if resp.status_code == 200:
                return True
            if resp.status_code in (401, 403):
                # Invalidate local token cache if denied
                self.token = None
                return False
            return False
        except Exception:
            return False