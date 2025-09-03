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
from starlette.responses import PlainTextResponse

from servicenow_mcp.server import ServiceNowMCP
from servicenow_mcp.utils.config import (
    AuthConfig,
    AuthType,
    BasicAuthConfig,
    OAuthConfig,
    ApiKeyConfig,
    ServerConfig,
)


def create_starlette_app(mcp_server: Server, *, debug: bool = False) -> Starlette:
    """Create a Starlette application that can serve the provided MCP server with SSE.

    Adds a lightweight health endpoint at /health returning plain text 'ok'.
    """
    sse = SseServerTransport("/messages/")

    async def handle_sse(request: Request) -> None:
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

    async def health(_: Request):  # noqa: D401
        return PlainTextResponse("ok", status_code=200)

    return Starlette(
        debug=debug,
        routes=[
            Route("/sse", endpoint=handle_sse),
            Route("/health", endpoint=health),
            Mount("/messages/", app=sse.handle_post_message),
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
        starlette_app = create_starlette_app(self.mcp_server, debug=True)

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
        api_key=args.api_key,
        api_key_header=args.api_key_header,
    )
    server.start(host=args.host, port=args.port)


if __name__ == "__main__":
    main()
