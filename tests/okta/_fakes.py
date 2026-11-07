from okta_mcp.okta.token import ServiceToken


class FakeTokenProvider:
    """A `TokenProvider` for client tests: a fixed token, with a call count and the tokens
    invalidated."""

    def __init__(self, token: ServiceToken | None = None) -> None:
        self._token = token or ServiceToken("fake-token", "Bearer")
        self.calls = 0
        self.invalidated: list[ServiceToken] = []

    async def token(self) -> ServiceToken:
        self.calls += 1
        return self._token

    def invalidate(self, token: ServiceToken) -> None:
        self.invalidated.append(token)
