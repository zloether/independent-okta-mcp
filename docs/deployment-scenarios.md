# Deployment scenarios

Where to run independent-okta-mcp, and how. This page helps you choose; the [runbook](runbook.md) has the steps for each choice.

The server is one stateless process: no database, no disk writes, no session store. Everything it needs is a config, a policy file and two secrets: the service app's private key and the cursor key. So the hosting choice comes down to who can reach the endpoint, how much downtime you can accept, and how much platform you already run. Not to capacity.

## Choose

| | A. One host, internal | B. One host, internet-facing | C. Replicated, behind a load balancer |
|---|---|---|---|
| **For** | A team on one network or VPN, local MCP clients | A small team, or any hosted MCP client | A business service other teams depend on |
| **Runs on** | A VM or on-prem server: Docker Compose and a reverse proxy | The same, plus edge rate limiting | A container platform with 2+ replicas across zones |
| **Reachable from** | The private network only | The internet; auth on every request | The internet or a private load balancer |
| **Hosted clients** (a client that runs in its vendor's cloud) | ✗ Can't reach it | ✓ | ✓ (needs a public or allowlisted endpoint) |
| **Downtime** | A host failure or reboot is an outage until you fix it; restarts take seconds | The same | A replica or zone can fail without one |
| **Ops effort** | Lowest | Low, plus watching the edge | Platform skills: IaC, secrets manager, LB, alarms |
| **Rough cost** | One small VM | One small VM | Load balancer + WAF + 2 small tasks; several times A [rough] |

Rules of thumb:

- **Start with A if you can.** Keeping the endpoint off the internet removes the largest class of risk (unauthenticated traffic and probing) at no cost. It works when every user runs a local MCP client, such as Claude Code, and can reach the network.
- **You need B or C if anyone uses a hosted client.** A client that runs in its vendor's cloud connects from the vendor's network, not the user's. Narrow B or C to that vendor's published egress ranges where it publishes them. [`compatibility-matrix.md`](compatibility-matrix.md) lists which clients have been tried.
- **Choose C when an outage would page someone.** Not for load: one process is enough for most teams (see [Capacity](#capacity)).

## Every scenario

These hold whatever you pick. The runbook explains each one.

- **TLS ends at a reverse proxy or load balancer, and nothing else reaches the server's port** ([runbook §3.3](runbook.md#33-proxy-and-exposure)). The container speaks plain HTTP. Docker's published ports bypass host firewalls such as ufw.
- **`MCP_TRUST_PROXY` trusts `X-Forwarded-*` from any peer.** Turn it on only once nothing but the proxy can reach the port. It changes log lines only: identity, limits and audit key on the token.
- **Secrets as files** (`OKTA_PRIVATE_KEY_FILE`, `MCP_CURSOR_KEY_FILE`). They never go in environment variables or the image. On a platform, mount them from its secrets manager as files. The policy is a file too (`MCP_POLICY_FILE`), mounted read-only. All three must be readable by uid 10001, the container's user: a root-owned `0600` mount fails at startup.
- **A pinned image.** Run an image tag pinned by digest (`image:tag@sha256:…`), never `:latest`, and bump it deliberately after reading the changelog. To build on your own base image (an internal mirror or a hardened base), pass `--build-arg BASE_IMAGE=<image>@sha256:<digest>`; the build refuses a tag. The base must be Debian or Ubuntu with Python ≥ 3.12, and you own its updates, since Dependabot tracks only the default. Run `tests/container/` against the result before using it (`OKTA_MCP_IMAGE=<tag> uv run pytest tests/container`).
- **The runtime hardening in [`docker/compose.example.yaml`](../docker/compose.example.yaml)**: read-only root filesystem, all capabilities dropped, `no-new-privileges`. Carry it over to any platform, for example Kubernetes' `readOnlyRootFilesystem`, `capabilities.drop: [ALL]`, `allowPrivilegeEscalation: false` and `runAsNonRoot`.
- **Health:** `/healthz` answers while the process runs. `/readyz` turns 503 without a service token or the issuer's signing keys. Both need no token, so keep `/readyz` internal; the proxy needs to route only `/mcp`, the two `/.well-known/oauth-protected-resource` paths (also tokenless, by design), and `/healthz` if an outside uptime check uses it.
- **A request body limit and timeouts at the proxy.** The proxy's timeout for the upstream's response must be above `MCP_CALL_TIMEOUT` (default 60 s), or a long list ends in the proxy's 504 instead of the server's own `timeout` error. nginx's `proxy_read_timeout` defaults to exactly 60 s, so raise it; with Caddy, its server `write` timeout. Don't cache responses: tool lists differ per user.
- **Logs:** the audit log goes to stdout by default, one JSON line per call. Ship it to your log store or SIEM, restrict who can read it, and set a retention period. The default, `MCP_AUDIT_ARGS=full`, keeps tool arguments in clear, and they are personal data (logins, names); set `hash` for keyed hashes instead ([runbook §4.6](runbook.md#46-audit-log)). Alert on the operational events in [runbook §4.7](runbook.md#47-operational-logs-and-alerts).
- **No proxy access log**, or one without request headers: each request carries a bearer token.
- **Okta's side is unchanged by any of this.** The [Okta-side controls](runbook.md#2-okta-setup) apply to every scenario: role-group membership, MFA on the client apps, and the service app's rate-limit share.

## A. One host, internal

The [runbook](runbook.md) as written: the compose example on one Linux host, a reverse proxy on the same host, and the endpoint reachable only from your network or VPN.

- **TLS:** a certificate for an internal name, from your internal CA or a public CA with DNS validation. MCP clients must trust it.
- **Firewall:** at the network edge, not only on the host. Check from another host that the server's own port doesn't answer (runbook §3.3).
- **Patching:** host OS updates, and a rebuild of the image when its base image or dependencies get fixes.
- **Recovery:** everything worth keeping is the config, the policy and the secrets. Keep the first two in version control and the secrets in a secrets manager, and a rebuild is a fresh host plus the runbook.

## B. One host, internet-facing

A, with the endpoint public. `/mcp` answers 401 to a request without a valid token (503 while the server can't yet verify tokens, 403 for a foreign `Origin`), and the health and metadata paths answer without one. Nothing in the server limits unauthenticated senders.

- **Edge rate limiting per client address.** Use the proxy's own (Caddy needs a plugin for this; nginx has `limit_req`), or a CDN or WAF in front. The server limits each signed-in user (`MCP_REQUESTS_PER_MINUTE`), not anonymous traffic.
- **An allowlist where you can:** the egress ranges of your hosted clients, plus your offices or VPN.
- **Expose only the paths clients need** (see [Every scenario](#every-scenario)). Everything else gets a 404 at the proxy.
- **A spending or billing alert** on the host's account. A flood costs bandwidth even when every request is refused.

## C. Replicated, behind a load balancer

Two or more replicas in different zones behind a load balancer: a managed container service (for example ECS on Fargate, Cloud Run or Azure Container Apps) or Kubernetes. The server is stateless, so replicas need no coordination. Four things change:

- **The limits are per process.** Each replica keeps its own counts, so with N replicas:
  - `MCP_REQUESTS_PER_MINUTE` is a cap on Okta requests **per signed-in user, per replica**. A user whose calls the load balancer spreads over N replicas gets up to N times it; it never was a total across users. Set it to the per-user budget you want divided by N, or accept the multiple. The org-wide ceiling is the service app's rate-limit share in Okta, not this setting.
  - `MCP_OKTA_MAX_INFLIGHT` (default 10) is the replica's concurrent Okta requests; one user may hold at most half of them, rounded up. Keep it at 4 or more per replica, so one slow list doesn't take every slot. Scaling out adds slots; that is usually what you want.
- **Give every replica the same cursor key.** A list's `next_cursor` is signed with `MCP_CURSOR_KEY`, and a resumed call can land on any replica. The audit log's `hash` mode is keyed from it too, so replicas with different keys hash the same argument differently. Rotate it on all of them together ([runbook §4.5](runbook.md#45-cursor-key-rotation)).
- **Give every replica the same policy file and config.** Roll out a policy change as a new deployment, after `okta-mcp --check` passes on it ([runbook §4.2](runbook.md#42-policy-change)). A replica set running two policies at once grants two sets of access.
- **Expect one service token per replica.** Each replica gets its own service token and its own DPoP key. That's fine, but each one draws on the service app's rate-limit share.

The load balancer does TLS and health checks. **Health-check on `/healthz`, alert on `/readyz`.** `/readyz` fails when the service token or the issuer's keys can't be had, and every replica shares the service app and the issuer: an Okta-side failure fails them all at once, and a load balancer checking `/readyz` would then drain every replica and answer clients with its own 502s instead of the server's errors. Put a WAF with per-address rate rules on a public load balancer, or use an internal load balancer if every client is on your network. The [every-scenario](#every-scenario) requirements still apply to the tasks. The secrets come from the platform's secrets manager as files, and the platform's own role reads them, not the containers'.

## Capacity

The bottleneck is Okta, not the host. One process serves many users at once: calls are async, and the work per call is token checks and reshaping JSON. Each tool call makes one or more Okta requests:

- a get makes one;
- a paged list makes one per page;
- `diagnostics login-failures` makes several.

All of them draw on your org's rate limits, which the service app shares with every other integration. Plan from those limits, and set the service app's rate-limit share in Okta so that independent-okta-mcp gets 429s before your other integrations do. A small VM (1 vCPU, 1 GB) is a reasonable start for a team. Measure under your own load before sizing up: run a load test against a mocked Okta, which costs none of your org's quota.
