"""
ServiceNow MCP Server

This module provides the main implementation of the ServiceNow MCP server.
"""

import argparse
import os
from typing import Dict, Union

import uvicorn
from dotenv import load_dotenv
from mcp.server import Server
from mcp.server.fastmcp import FastMCP
from mcp.server.sse import SseServerTransport
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.routing import Mount, Route
from starlette.responses import PlainTextResponse, JSONResponse

from servicenow_mcp.server import ServiceNowMCP
from servicenow_mcp.tools.auth_flow_tools import store_pkce_token, get_pkce_session
from servicenow_mcp.utils.config import (
    AuthConfig,
    AuthType,
    BasicAuthConfig,
    OAuthConfig,
    ApiKeyConfig,
    ServerConfig,
)
def create_starlette_app(controller: 'ServiceNowSSEMCP', mcp_server: Server, *, debug: bool = False) -> Starlette:
    """Create a Starlette application that can serve the provided MCP server with SSE.

    Adds a lightweight health endpoint at /health returning plain text 'ok'.
    Includes /oauth/callback for PKCE authorization code exchange.
    """
    sse = SseServerTransport("/messages/")

    async def _validate_and_set_token(req: Request) -> JSONResponse | None:
        headers = {k.lower(): v for k, v in req.headers.items()}
        auth = headers.get("authorization")
        if not auth or not auth.lower().startswith("bearer "):
            # Enforce bearer for OAuth external-token mode
            if controller.config.auth.type == AuthType.OAUTH:
                return JSONResponse({"error": "missing_bearer"}, status_code=401)
            return None
        token = auth.split(" ", 1)[1].strip()
        controller.auth_manager.set_token(token)
        if not controller.auth_manager.validate_current_token():
            return JSONResponse({"error": "invalid_token"}, status_code=401)
        return None

    async def handle_sse(request: Request) -> None:  # SSE endpoint with auth gate
        auth_fail = await _validate_and_set_token(request)
        if auth_fail is not None:
            await auth_fail(scope=request.scope, receive=request.receive, send=request._send)  # noqa: SLF001
            return
        async with sse.connect_sse(
            request.scope,
            request.receive,
            request._send,  # noqa: SLF001
        ) as (read_stream, write_stream):
            await mcp_server.run(
                read_stream,
                write_stream,
                mcp_server.create_initialization_options(),
            )

    async def oauth_callback(request: Request):  # PKCE callback
        params = dict(request.query_params)
        code = params.get("code")
        state = params.get("state")
        if not (code and state):
            return PlainTextResponse("Missing code/state", status_code=400)
        # state = state_base:session_id
        if ":" not in state:
            return PlainTextResponse("Invalid state format", status_code=400)
        state_base, session_id = state.split(":", 1)
        sess = get_pkce_session(session_id)
        if not sess or sess.get("state") != state_base:
            return PlainTextResponse("State mismatch or unknown session", status_code=400)
        oauth_cfg = controller.config.auth.oauth if controller.config.auth else None
        if not oauth_cfg or not oauth_cfg.token_url:
            return PlainTextResponse("Server not configured for OAuth", status_code=500)
        import base64, requests
        auth_header = base64.b64encode(f"{oauth_cfg.client_id}:{oauth_cfg.client_secret}".encode()).decode()
        headers = {"Authorization": f"Basic {auth_header}", "Content-Type": "application/x-www-form-urlencoded"}
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": oauth_cfg.redirect_url,
            "code_verifier": sess.get("code_verifier"),
        }
        resp = requests.post(oauth_cfg.token_url, headers=headers, data=data)
        if resp.status_code != 200:
            return PlainTextResponse(
                f"Token exchange failed: {resp.status_code} {resp.text}", status_code=500
            )
        jd = resp.json()
        store_pkce_token(
            session_id=session_id,
            access_token=jd.get("access_token"),
            token_type=jd.get("token_type", "Bearer"),
            refresh_token=jd.get("refresh_token"),
            expires_in=jd.get("expires_in"),
        )
        return PlainTextResponse(
            "Authorization complete. Return to ChatGPT and call select_session with session_id.",
            status_code=200,
        )

    async def health(_: Request):  # noqa: D401
        return PlainTextResponse("ok", status_code=200)

    async def oauth_metadata(request: Request):
        inst = controller.config.instance_url.rstrip("/")
        proto_version = request.headers.get("MCP-Protocol-Version")
        meta = {
            "issuer": inst,
            "authorization_endpoint": f"{inst}/oauth_authorize.do",
            "token_endpoint": f"{inst}/oauth_token.do",
            # Optional / best-effort endpoints (may not exist in every ServiceNow instance; included for discovery friendliness)
            "revocation_endpoint": f"{inst}/oauth_revoke.do",
            "scopes_supported": ["useraccount", "openid"],
            "response_types_supported": ["code"],
            "grant_types_supported": [
                "authorization_code",
                "client_credentials",
                "password",
                "refresh_token",
            ],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["client_secret_basic"],
        }
        if proto_version:
            meta["mcp_protocol_version_received"] = proto_version
        return JSONResponse(meta, headers={"MCP-Protocol-Version": proto_version or "unknown"})

    # Wrap messages app to inject/validate bearer tokens from inbound Authorization header
    original_messages_app = sse.handle_post_message

    class AuthMessageWrapper:
        def __init__(self, inner, controller):
            self.inner = inner
            self.controller = controller

        async def __call__(self, scope, receive, send):
            if scope.get("type") == "http":
                # Convert to Request for shared validator
                headers = {k.decode(): v.decode() for k, v in scope.get("headers", [])}
                from starlette.requests import Request as _Req
                req = _Req(scope, receive=receive)
                auth_fail = await _validate_and_set_token(req)
                if auth_fail is not None:
                    await auth_fail(scope, receive, send)
                    return
            await self.inner(scope, receive, send)

    wrapped_messages_app = AuthMessageWrapper(original_messages_app, controller)

    return Starlette(
        debug=debug,
        routes=[
            Route("/", endpoint=lambda request: PlainTextResponse("ServiceNow MCP Server up. Use start_oauth_pkce tool to begin authorization if required.")),
            Route("/sse", endpoint=handle_sse),
            Route("/oauth/callback", endpoint=oauth_callback),
            Route("/health", endpoint=health),
            Route("/.well-known/oauth-authorization-server", endpoint=oauth_metadata),
            Mount("/messages/", app=wrapped_messages_app),
        ],
    )


class ServiceNowSSEMCP(ServiceNowMCP):
    """
    ServiceNow MCP Server implementation.

    This class provides a Model Context Protocol (MCP) server for ServiceNow,
    allowing LLMs to interact with ServiceNow data and functionality.
    """

    def __init__(self, config: Union[Dict, ServerConfig]):
        """
        Initialize the ServiceNow MCP server.

        Args:
            config: Server configuration, either as a dictionary or ServerConfig object.
        """
        super().__init__(config)

    def start(self, host: str = "0.0.0.0", port: int = 8080):
        """
        Start the MCP server with SSE transport using Starlette and Uvicorn.

        Args:
            host: Host address to bind to
            port: Port to listen on
        """
    # Create Starlette app with SSE transport
        starlette_app = create_starlette_app(self, self.mcp_server, debug=True)

        # Run using uvicorn
        uvicorn.run(starlette_app, host=host, port=port)


def create_servicenow_mcp(
    instance_url: str,
    auth_type: AuthType = AuthType.BASIC,
    username: str | None = None,
    password: str | None = None,
    client_id: str | None = None,
    client_secret: str | None = None,
    token_url: str | None = None,
    redirect_url: str | None = None,
    api_key: str | None = None,
    api_key_header: str = "X-ServiceNow-API-Key",
):
    """Create a ServiceNow MCP server supporting Basic, OAuth, or API Key auth.

    For OAuth:
      - Provide client_id & client_secret for client_credentials grant.
      - Optionally add username & password to enable password grant fallback.
    """

    if auth_type == AuthType.BASIC:
        if not (username and password):
            raise ValueError("Basic auth requires username and password")
        auth_config = AuthConfig(
            type=AuthType.BASIC, basic=BasicAuthConfig(username=username, password=password)
        )
    elif auth_type == AuthType.OAUTH:
        if not (client_id and client_secret):
            raise ValueError("OAuth requires client_id and client_secret at minimum")
        oauth_cfg = OAuthConfig(
            client_id=client_id,
            client_secret=client_secret,
            username=username,
            password=password,
            token_url=token_url,
            redirect_url=redirect_url,
        )
        auth_config = AuthConfig(type=AuthType.OAUTH, oauth=oauth_cfg)
    elif auth_type == AuthType.API_KEY:
        if not api_key:
            raise ValueError("API key auth requires api_key")
        auth_config = AuthConfig(
            type=AuthType.API_KEY, api_key=ApiKeyConfig(api_key=api_key, header_name=api_key_header)
        )
    else:
        raise ValueError(f"Unsupported auth type: {auth_type}")

    config = ServerConfig(instance_url=instance_url, auth=auth_config)
    return ServiceNowSSEMCP(config)


def main():
    load_dotenv()

    # Parse command line arguments
    parser = argparse.ArgumentParser(description="Run ServiceNow MCP SSE-based server")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind to")
    parser.add_argument("--port", type=int, default=8080, help="Port to listen on")
    parser.add_argument(
        "--auth-type",
        default=os.getenv("SERVICENOW_AUTH_TYPE", "basic"),
        choices=["basic", "oauth", "api_key"],
        help="Authentication type (basic|oauth|api_key)",
    )
    parser.add_argument("--username", default=os.getenv("SERVICENOW_USERNAME"))
    parser.add_argument("--password", default=os.getenv("SERVICENOW_PASSWORD"))
    parser.add_argument("--client-id", default=os.getenv("SERVICENOW_CLIENT_ID"))
    parser.add_argument("--client-secret", default=os.getenv("SERVICENOW_CLIENT_SECRET"))
    parser.add_argument("--token-url", default=os.getenv("SERVICENOW_TOKEN_URL"))
    parser.add_argument("--redirect-url", default=os.getenv("SERVICENOW_REDIRECT_URL"))
    parser.add_argument("--api-key", default=os.getenv("SERVICENOW_API_KEY"))
    parser.add_argument(
        "--api-key-header",
        default=os.getenv("SERVICENOW_API_KEY_HEADER", "X-ServiceNow-API-Key"),
    )
    args = parser.parse_args()

    instance_url = os.getenv("SERVICENOW_INSTANCE_URL")
    if not instance_url:
        raise SystemExit("SERVICENOW_INSTANCE_URL is required")

    auth_type = AuthType(args.auth_type)
    server = create_servicenow_mcp(
        instance_url=instance_url,
        auth_type=auth_type,
        username=args.username,
        password=args.password,
        client_id=args.client_id,
        client_secret=args.client_secret,
        token_url=args.token_url,
        redirect_url=args.redirect_url,
        api_key=args.api_key,
        api_key_header=args.api_key_header,
    )
    server.start(host=args.host, port=args.port)


if __name__ == "__main__":
    main()
