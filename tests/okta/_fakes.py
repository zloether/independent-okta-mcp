from okta_mcp.okta.token import ServiceToken


class FakeTokenProvider:
    """A `TokenProvider` for client tests: a fixed token, with a call count."""

    def __init__(self, token: ServiceToken | None = None) -> None:
        self._token = token or ServiceToken("fake-token", "Bearer")
        self.calls = 0

    async def token(self) -> ServiceToken:
        self.calls += 1
        return self._token
