"""Step 0.4 SDK spike: stateless HTTP, per-principal tools/list, structuredContent.

Throwaway. Fake bearer tokens map to principals; each principal sees a different tool set.
"""

from typing import Any

import mcp_types as types
from mcp.server import Server, ServerRequestContext
from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.provider import AccessToken
from mcp.server.auth.settings import AuthSettings
from mcp.server.transport_security import TransportSecuritySettings
from starlette.applications import Starlette

TOKENS = {"token-alice": ("alice", ["okta.users.read"]), "token-bob": ("bob", ["okta.groups.read"])}

TOOLS = {
    "okta.users.read": types.Tool(
        name="users_get",
        description="Get a user",
        input_schema={"type": "object", "properties": {"id": {"type": "string"}}},
        output_schema={"type": "object", "properties": {"id": {"type": "string"}}},
        annotations=types.ToolAnnotations(read_only_hint=True, open_world_hint=True),
    ),
    "okta.groups.read": types.Tool(
        name="groups_list",
        description="List groups",
        input_schema={"type": "object"},
        annotations=types.ToolAnnotations(read_only_hint=True, open_world_hint=True),
    ),
}


class FakeVerifier:
    async def verify_token(self, token: str) -> AccessToken | None:
        if token not in TOKENS:
            return None
        sub, scopes = TOKENS[token]
        return AccessToken(token=token, client_id="spike", scopes=scopes, subject=sub)


def _scopes() -> list[str]:
    token = get_access_token()
    assert token is not None
    return token.scopes


async def list_tools(
    ctx: ServerRequestContext, params: types.PaginatedRequestParams | None
) -> types.ListToolsResult:
    tools = [TOOLS[s] for s in _scopes() if s in TOOLS]
    return types.ListToolsResult(tools=tools, ttl_ms=60_000, cache_scope="private")


async def call_tool(
    ctx: ServerRequestContext, params: types.CallToolRequestParams
) -> types.CallToolResult:
    allowed = {TOOLS[s].name for s in _scopes() if s in TOOLS}
    if params.name not in allowed:
        return types.CallToolResult(
            content=[types.TextContent(type="text", text="unknown tool")], is_error=True
        )
    args: dict[str, Any] = params.arguments or {}
    data = {"id": args.get("id", ""), "principal": ctx.request.user.access_token.subject}  # pyright: ignore
    return types.CallToolResult(
        content=[types.TextContent(type="text", text=str(data))], structured_content=data
    )


def build_app() -> Starlette:
    server = Server("spike", version="0.0.0", on_list_tools=list_tools, on_call_tool=call_tool)
    return server.streamable_http_app(
        stateless_http=True,
        json_response=True,
        host="example.com",
        transport_security=TransportSecuritySettings(
            enable_dns_rebinding_protection=True, allowed_hosts=["example.com"]
        ),
        auth=AuthSettings(
            issuer_url="https://example.okta.com/oauth2/default",  # pyright: ignore[reportArgumentType]
            resource_server_url="https://example.com/mcp",  # pyright: ignore[reportArgumentType]
            validate_token_resource=False,
        ),
        token_verifier=FakeVerifier(),
    )
