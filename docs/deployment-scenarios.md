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
  - `MCP_REQUESTS_PER_MINUTE` is a cap on Okta requests **per signed-in user, per replica**. A user whose calls the load balancer spreads over N replicas gets up to N times it; it never was a total across users. Set it to the per-user budget you want divided by N, or accept the multiple. The org-wide ceiling is the service app's rate-limit share in Okta, not this setting. [Runbook §4.9](runbook.md#49-rate-limit-sizing) derives both settings from your org's limits.
  - `MCP_OKTA_MAX_INFLIGHT` (default 10) is the replica's concurrent Okta requests; one user may hold at most half of them, rounded up. Keep it at 4 or more per replica, so one slow list doesn't take every slot. Scaling out adds slots; that is usually what you want.
- **Give every replica the same cursor key.** A list's `next_cursor` is signed with `MCP_CURSOR_KEY`, and a resumed call can land on any replica. The audit log's `hash` mode is keyed from it too, so replicas with different keys hash the same argument differently. Rotate it on all of them together ([runbook §4.5](runbook.md#45-cursor-key-rotation)).
- **Give every replica the same policy file and config.** Roll out a policy change as a new deployment, after `okta-mcp --check` passes on it ([runbook §4.2](runbook.md#42-policy-change)). While a rolling update runs, old and new replicas serve two policies at once: see [Policy rollout](#policy-rollout-across-replicas).
- **Expect one service token per replica.** Each replica gets its own service token and its own DPoP key. That's fine, but each one draws on the service app's rate-limit share.

The load balancer does TLS and health checks. **Health-check on `/healthz`, alert on `/readyz`.** `/readyz` fails when the service token or the issuer's keys can't be had, and every replica shares the service app and the issuer: an Okta-side failure fails them all at once, and a load balancer checking `/readyz` would then drain every replica and answer clients with its own 502s instead of the server's errors. Put a WAF with per-address rate rules on a public load balancer, or use an internal load balancer if every client is on your network. The [every-scenario](#every-scenario) requirements still apply to the tasks. The secrets come from the platform's secrets manager as files, and the platform's own role reads them, not the containers'.

### Policy rollout across replicas

Each replica reads the policy once, at startup, and never again: there is no hot reload. So a replica serves the policy it started with until it is replaced, and a rolling update runs old and new replicas side by side until it finishes, usually for minutes. **For that window the deployment grants two sets of access.** Which one a call gets depends on the replica the load balancer picks, and a client's cached tool list (kept up to 5 minutes) may come from the other one. The same holds for a config change (`OKTA_SCOPES`, say) and for an upgrade whose registry renames or removes a command.

- **A change that only adds access** (a new role, a command added to a role): roll as usual. Until the rollout finishes, some calls are refused that soon won't be.
- **A change that removes access** (a group taken off a role, a command removed, a `deny` added): **replace every replica at once instead of rolling.** Either blue/green (bring up the new set, check `/readyz` on it, move the load balancer to it, then stop the old set), or scale the old set to zero before the new one takes traffic (a short outage instead of a window of old access; in Kubernetes, `strategy: Recreate`). The old access then ends when the switch does, not when the last old replica drains.
- **Removing one person** needs no rollout: take them out of the role groups in Okta ([runbook §4.3](runbook.md#43-adding-a-user-removing-a-user)). To end all access at once, use the [kill switch](runbook.md#5-kill-switch).

Check the new policy first with `okta-mcp --check`, run once as a one-off task or Job with the same image, variables and mounts as the replicas, the way [runbook §4.2](runbook.md#42-policy-change) does with `docker compose run`.

#### Kubernetes

> **Unverified:** not run against a cluster. Checked only against the [`Dockerfile`](../Dockerfile) (user and group 10001) and the mounts in [`docker/compose.example.yaml`](../docker/compose.example.yaml).

- **Mount the policy from a ConfigMap whose name carries a hash of its content**, so a policy edit is a new pod template, and so a new rollout. Kustomize's `configMapGenerator` does this: it appends a hash of the content to the name and rewrites the Deployment's reference. Without Kustomize, put the hash in the name yourself (`okta-mcp-policy-<first 10 hex of sha256>`). Old pods keep reading the old ConfigMap until they are gone, and keeping it makes a rollback another rollout. A Secret works the same way; for the service key and cursor key, which come from a secrets manager, follow the key rotation steps instead ([runbook §4.4](runbook.md#44-service-key-rotation), [§4.5](runbook.md#45-cursor-key-rotation)), since they end in a restart too.
- **Don't edit a mounted ConfigMap in place.** The kubelet updates the files in running pods eventually (not at all for a `subPath` mount), but the server read its policy at startup, so nothing changes until pods restart. Then the pods that happen to restart (a crash, an eviction, a scale-up) read the new file while the rest serve the old one: two policies, with no rollout to show it or to finish it.
- **Make the mounted files readable by uid 10001.** ConfigMap and Secret files are owned by root with the volume's `defaultMode` (`0644` if unset). Run the pod as user and group 10001 with `fsGroup: 10001`, which gives the files group 10001, and set `defaultMode: 0440`. With a root-only mode such as `0400` and no `fsGroup`, startup fails with exit 2, the config error naming the unreadable file.
- **Keep the secrets out of `/run/secrets`** (the compose example's path): on Debian-based images `/var/run` is `/run`, where Kubernetes mounts the service account token under `/var/run/secrets/kubernetes.io/`. The server never calls the Kubernetes API, so turn that token off too.

```yaml
# kustomization.yaml. Unverified: not run against a cluster.
resources: [deployment.yaml]
configMapGenerator:
  - name: okta-mcp-policy          # becomes okta-mcp-policy-<hash>
    files: [policy.yaml]
```

```yaml
# deployment.yaml (excerpt). Unverified: not run against a cluster.
apiVersion: apps/v1
kind: Deployment
metadata:
  name: okta-mcp
spec:
  replicas: 2
  strategy:
    type: RollingUpdate            # Recreate (or blue/green) for a change that removes access
  template:
    spec:
      automountServiceAccountToken: false
      securityContext:
        runAsNonRoot: true
        runAsUser: 10001
        runAsGroup: 10001
        fsGroup: 10001
        seccompProfile: { type: RuntimeDefault }   # Docker applies its default; Kubernetes doesn't
      containers:
        - name: okta-mcp
          image: <registry>/okta-mcp:<tag>@sha256:<digest>
          securityContext:
            readOnlyRootFilesystem: true
            allowPrivilegeEscalation: false
            capabilities: { drop: [ALL] }
          # Kubernetes ignores the image's HEALTHCHECK. Probe /healthz, not /readyz: an Okta
          # outage fails /readyz on every pod at once (see above).
          livenessProbe: { httpGet: { path: /healthz, port: 8080 } }
          readinessProbe: { httpGet: { path: /healthz, port: 8080 } }
          env:
            - { name: MCP_POLICY_FILE, value: /etc/okta-mcp/policy.yaml }
            - { name: MCP_CURSOR_KEY_FILE, value: /etc/okta-mcp-secrets/cursor_key }
            - { name: OKTA_PRIVATE_KEY_FILE, value: /etc/okta-mcp-secrets/okta_private_key }
            # ... the rest as in docker/compose.example.yaml
          volumeMounts:
            - { name: policy, mountPath: /etc/okta-mcp, readOnly: true }
            - { name: secrets, mountPath: /etc/okta-mcp-secrets, readOnly: true }
      volumes:
        - name: policy
          configMap:
            name: okta-mcp-policy  # Kustomize rewrites this to the hashed name
            defaultMode: 0440
        - name: secrets
          secret:
            secretName: okta-mcp-secrets   # keys: cursor_key, okta_private_key
            defaultMode: 0440
```

## Capacity

The bottleneck is Okta, not the host. One process serves many users at once: calls are async, and the work per call is token checks and reshaping JSON. Each tool call makes one or more Okta requests:

- a get makes one;
- a paged list makes one per page;
- `diagnostics login-failures` makes several.

All of them draw on your org's rate limits, which the service app shares with every other integration. Plan from those limits, and set the service app's rate-limit share in Okta so that independent-okta-mcp gets 429s before your other integrations do. A small VM (1 vCPU, 1 GB) is a reasonable start for a team. Measure under your own load before sizing up: run a load test against a mocked Okta, which costs none of your org's quota.
