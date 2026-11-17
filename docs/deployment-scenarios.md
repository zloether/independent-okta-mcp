# Deployment scenarios

Where to run okta-mcp, and how. This page helps you choose; the [runbook](runbook.md) has the steps for each choice.

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
- **Secrets as files** (`OKTA_PRIVATE_KEY_FILE`, `MCP_CURSOR_KEY_FILE`), readable by uid 10001. They never go in environment variables or the image. On a platform, mount them from its secrets manager as files.
- **The runtime hardening in [`docker/compose.example.yaml`](../docker/compose.example.yaml)**: read-only root filesystem, all capabilities dropped, `no-new-privileges`. Carry it over to any platform, for example Kubernetes' `readOnlyRootFilesystem`, `capabilities.drop: [ALL]`, `allowPrivilegeEscalation: false` and `runAsNonRoot`.
- **Health:** `/healthz` for liveness, `/readyz` for readiness. `/readyz` turns 503 without a service token or the issuer's signing keys. Keep `/readyz` internal; the proxy needs to route only `/mcp`, the two `/.well-known/oauth-protected-resource` paths, and `/healthz` if an outside uptime check uses it.
- **A request body limit and timeouts at the proxy.** The proxy's write timeout must be above `MCP_CALL_TIMEOUT` (default 60 s). Don't cache responses: tool lists differ per user.
- **Logs:** the audit log goes to stdout by default, one JSON line per call. Ship it to your log store or SIEM, restrict who can read it, and set a retention period. `MCP_AUDIT_ARGS=full` keeps tool arguments in clear, which are personal data. Alert on the operational events in [runbook §4.7](runbook.md#47-operational-logs-and-alerts).
- **No proxy access log**, or one without request headers: each request carries a bearer token.
- **Okta's side is unchanged by any of this.** The [Okta-side controls](runbook.md#2-okta-setup) apply to every scenario: role-group membership, MFA on the client apps, and the service app's rate-limit share.

## A. One host, internal

The [runbook](runbook.md) as written: the compose example on one Linux host, a reverse proxy on the same host, and the endpoint reachable only from your network or VPN.

- **TLS:** a certificate for an internal name, from your internal CA or a public CA with DNS validation. MCP clients must trust it.
- **Firewall:** at the network edge, not only on the host. Check from another host that the server's own port doesn't answer (runbook §3.3).
- **Patching:** host OS updates, and a rebuild of the image when its base image or dependencies get fixes.
- **Recovery:** everything worth keeping is the config, the policy and the secrets. Keep the first two in version control and the secrets in a secrets manager, and a rebuild is a fresh host plus the runbook.

## B. One host, internet-facing

A, with the endpoint public. Every request without a valid token gets a 401, but nothing in the server limits unauthenticated senders.

- **Edge rate limiting per client address.** Use the proxy's own (Caddy needs a plugin for this; nginx has `limit_req`), or a CDN or WAF in front. The server limits each signed-in user (`MCP_REQUESTS_PER_MINUTE`), not anonymous traffic.
- **An allowlist where you can:** the egress ranges of your hosted clients, plus your offices or VPN.
- **Expose only the paths clients need** (see [Every scenario](#every-scenario)). Everything else gets a 404 at the proxy.
- **A spending or billing alert** on the host's account. A flood costs bandwidth even when every request is refused.

## C. Replicated, behind a load balancer

Two or more replicas in different zones behind a load balancer: a managed container service (for example ECS on Fargate, Cloud Run or Azure Container Apps) or Kubernetes. The server is stateless, so replicas need no coordination. Four things change:

- **Divide the per-process limits by the replica count.** `MCP_REQUESTS_PER_MINUTE` and `MCP_OKTA_MAX_INFLIGHT` are counted per process, so N replicas allow N times as much. Set each to the total you want divided by N. (The audit log still names every caller.)
- **Give every replica the same cursor key.** A list's `next_cursor` is signed with `MCP_CURSOR_KEY`, and a resumed call can land on any replica. Rotate it on all of them together ([runbook §4.5](runbook.md#45-cursor-key-rotation)).
- **Give every replica the same policy file and config.** Roll out a policy change as a new deployment, after `okta-mcp --check` passes on it ([runbook §4.2](runbook.md#42-policy-change)). A replica set running two policies at once grants two sets of access.
- **Expect one service token per replica.** Each replica gets its own service token and its own DPoP key. That's fine, but each one draws on the service app's rate-limit share.

The load balancer does TLS and health checks: `/healthz` for liveness, `/readyz` to take a replica out of rotation. Put a WAF with per-address rate rules on a public load balancer, or use an internal load balancer if every client is on your network. The [every-scenario](#every-scenario) requirements still apply to the tasks. The secrets come from the platform's secrets manager as files, and the platform's own role reads them, not the containers'.

## Capacity

The bottleneck is Okta, not the host. One process serves many users at once: calls are async, and the work per call is token checks and reshaping JSON. Each tool call makes one or more Okta requests:

- a get makes one;
- a paged list makes one per page;
- `diagnostics login-failures` makes several.

All of them draw on your org's rate limits, which the service app shares with every other integration. Plan from those limits, and set the service app's rate-limit share in Okta so that okta-mcp gets 429s before your other integrations do. A small VM (1 vCPU, 1 GB) is a reasonable start for a team. Measure under your own load before sizing up: run a load test against a mocked Okta, which costs none of your org's quota.

## Not yet

- **No published image.** Until the first release, compose builds from a checkout ([`CHANGELOG.md`](../CHANGELOG.md)). On a platform, build the image in your own CI and pin it by digest.
- **Pre-release.** See the README's status, including what has and hasn't been checked against a live org, and [`SECURITY.md`](../SECURITY.md#review-status) for the review status.
