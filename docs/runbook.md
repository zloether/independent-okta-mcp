# Runbook

How to stand up, run and shut down an okta-mcp deployment. The Okta details are in [`okta-setup.md`](okta-setup.md), and the reasons behind each control are in the [design](design/mcp-server.md) (§ numbers below). This page gives the order of steps and the checks between them.

Steps marked **unverified** haven't been tried against a real org yet. They are tracked in the [plan](implementation-plan.md).

## 1. Before you start

Decide these first. Each is hard to change later. Where to host it (one host or replicated, internal or internet-facing) is in [`deployment-scenarios.md`](deployment-scenarios.md).

| Decision | Options | Where it's set |
|---|---|---|
| **Exposure** | Internal only (VPN or private network) or internet-facing. Either way TLS ends at a reverse proxy, and nothing but that proxy reaches the container's port (§3.3). Write the choice down with your deployment's notes | Your network, `ports:` in compose |
| **Refresh tokens** | A: none (sign in again every access-token lifetime, the default) or B: rotating | `refresh_tokens` in the setup config ([A or B](okta-setup.md#refresh-tokens-option-a-or-b)) |
| **Scopes and admin role** | Each `okta.*.read` scope you grant exposes its commands and may need a broader admin role than Read-only Administrator ([table](okta-setup.md#service-app-scopes-and-admin-roles)). Leave a scope out to stay narrow | `service_app.scopes` → `OKTA_SCOPES` |
| **DPoP or sessions** | DPoP on (default), or off so `sessions get` works: Okta rejects that call from a DPoP-bound token ([details](okta-setup.md#service-app-scopes-and-admin-roles)) | Require DPoP on the service app, `OKTA_DPOP` |
| **Roles** | Which Okta groups get which commands. Sensitive commands need a name or `include_sensitive`. Two things a role sees that the classes don't flag ([below](#what-redaction-doesnt-cover)): every profile attribute on a user, and whatever the System Log recorded | `policy.yaml` (start from [`docker/policy.example.yaml`](../docker/policy.example.yaml)) |
| **Audit args** | `full` (args in clear, which are PII) or `hash` (keyed hashes) | `MCP_AUDIT_ARGS` |

### What redaction doesn't cover

The server redacts known secret fields in every result (`scrub.yaml`), by key name. It can't know what your org put where:

- **Custom profile attributes.** User commands are normal, not sensitive, so `users: ["*"]` returns each user's whole profile. If your org keeps national ID numbers, salary bands, or anything secret in profile attributes, a role with user commands reads them, unless the attribute's name is one the rules redact (`secret`, `apiKey`, `token`, …). Check your user schema before granting user commands widely. There is no per-role field redaction yet (§12.4).
- **System Log values.** `logs list` returns events as Okta recorded them. Redaction sees key names, not the inside of a string, so a secret in a value, such as a token in a request URL under `debugContext.debugData`, is returned. Grant `logs` only to roles you would let read the System Log in the admin console. `diagnostics login-failures` returns derived attributes, never the events.

You need:

- An Okta org with API Access Management ([prerequisites](okta-setup.md#prerequisites)) and a Super Administrator to run setup.
- A Linux host with Docker Engine ≥ 25 and Compose v2, and a reverse proxy with a certificate for the public hostname.
- The repository checkout on that host. Until an image is published, compose builds from it.

## 2. Okta setup

Follow [`okta-setup.md`](okta-setup.md) with either `scripts/okta-setup.py` or `terraform/okta/`, not both. In short:

1. Generate the service app's key pair on a trusted machine. The private key goes only to the server's secrets directory.
2. Fill the setup config, including `mcp_public_url` (what clients will connect to, ending in `/mcp`) and each MCP client's exact redirect URI.
3. `check`, then `apply` (or `terraform plan` / `apply`).
4. If the scopes need Org or Super Administrator, assign it by hand ([why](okta-setup.md#what-apply-will-and-wont-change)).
5. Re-run `check` until it exits `0`. Save the values it prints: `MCP_ISSUER`, `MCP_ALLOWED_CLIENT_IDS`, `OKTA_CLIENT_ID`, `OKTA_KEY_ID`, `OKTA_SCOPES` and the group IDs.
6. Revoke the setup API token.

Then make the Okta-side controls the server can't check (§8.2, §10, R7). Neither setup tool does these:

- **Role-group membership.** Adding a user to an `mcp-okta-*` group grants that role. Keep the groups out of every delegated admin's resource set (Security → Administrators → Resources), don't target them with group rules, and list who can still change membership (Super Admins, plus any Org Admin, Group Admin or Group Membership Admin whose scope includes them).
- **Membership alert.** Alert on System Log `eventType eq "group.user_membership.add"` where `target.id` is one of the role-group IDs. Use your SIEM, or an Okta event hook if you have no SIEM. Also alert on `group.user_membership.remove` if you want a full trail.
- **MFA on the client apps.** Assign each public client app an authentication policy that requires MFA, phishing-resistant if you can (Applications → the client → Sign On). A new app otherwise gets the org default.
- **Service app rate-limit share** (unverified, V16). Under Applications → the service app → Application Rate Limits, set the share well below the default, so a looping MCP client gets 429s before other integrations do. Record the value you choose here: `____ %`.

## 3. Deploy

### 3.1 Files

From the checkout's `docker/` directory:

```sh
cp policy.example.yaml policy.yaml               # then edit: your group IDs, your roles
umask 077                                        # new secret files are owner-only from the start
mkdir -p secrets
head -c 32 /dev/urandom | base64 > secrets/cursor_key
cp /path/to/okta-mcp-service.pem secrets/okta_private_key.pem
sudo chown 10001:10001 secrets/* policy.yaml
sudo chmod 0400 secrets/* policy.yaml
```

`policy.yaml` and `secrets/` are git-ignored there. The container runs as uid 10001 and Compose mounts these files with their host owner and mode, so they must be readable by 10001 (§11.4).

**Replacing a mounted file later** (policy, key, cursor key): Docker bind-mounts a single file by inode, and editors and `install` write a new one, so a running container keeps reading the old file until it restarts. Replace with `install`, which sets owner 10001 and mode 0400 in one step, then recreate the container, which also applies any change to the compose file:

```sh
sudo install -o 10001 -g 10001 -m 0400 policy.new.yaml policy.yaml
docker compose -f compose.example.yaml up -d --force-recreate --wait
```

Edit the `CHANGE` values in [`compose.example.yaml`](../docker/compose.example.yaml) with what `check` printed. `OKTA_SCOPES` must be exactly the scopes the service app was granted. Leave `MCP_TRUST_PROXY` at `"false"` for now. If browser-based clients will connect, set `MCP_ALLOWED_ORIGINS`; other clients send no `Origin` and don't need it. The full variable list is design §11.3.

### 3.2 Start

Check first, so a configuration, key or policy error shows as one `check failed` report rather than a container that won't stay up (§4.2 has the details):

```sh
docker compose -f compose.example.yaml build
docker compose -f compose.example.yaml run --rm okta-mcp --check
```

Then:

```sh
docker compose -f compose.example.yaml up -d --wait
curl -s http://127.0.0.1:8080/healthz          # {"status":"ok"}
curl -s http://127.0.0.1:8080/readyz           # {"status":"ready"}; 503 for a few seconds while keys and token load
```

These use the loopback port. With the shared-network option (§3.3), which publishes no port, run them from the proxy's container instead, against `http://okta-mcp:8080`. `docker compose ps` also shows the image's own health check (`healthy`) either way.

A configuration, key or policy error stops the server with exit status `2` and the reasons on stderr (`docker compose logs okta-mcp`). Values are never echoed. `/readyz` answers `503` until the server has loaded the issuer's JWKS and obtained a service token (§11.4). If it stays at 503, check the server logs for `jwks_fetch_failed` or `service_token_failed`. The common causes:

- **`service_token_failed`:** the wrong `OKTA_KEY_ID` or key file, "Require DPoP" off on the service app (the server refuses the `Bearer` downgrade and says so), or scopes not granted.
- **`jwks_fetch_failed`:** an `MCP_ISSUER` typo, or no egress to the Okta org.

### 3.3 Proxy and exposure

Point the proxy at `127.0.0.1:8080`, or at `okta-mcp:8080` with the shared-network option in the compose file, and serve it at `MCP_PUBLIC_URL`. Then confirm that only the proxy can reach the port. Docker's published ports bypass host firewalls such as ufw (§11.4).

The proxy should cap what it accepts. A minimal Caddyfile (run in front of this server on 2026-11-16, as part of a fuller one: a body over 1 MB is refused with 413, sign-in and tool calls pass through):

```
mcp.example.com {
	request_body {
		max_size 1MB
	}
	reverse_proxy 127.0.0.1:8080
}
```

Whatever the proxy, set a request body limit (tool calls are a few KB; the server itself refuses bodies over 4 MiB), connection and header timeouts, and a per-address request rate if the endpoint is internet-facing: the server limits each signed-in user, not unauthenticated senders. Don't cache responses; tool lists differ per user.

```sh
# from ANOTHER host on the same network: both must fail to connect
curl -m 5 http://<server-host-ip>:8080/healthz
nc -vz -w 5 <server-host-ip> 8080
# through the proxy: must succeed
curl -s https://mcp.example.com/healthz
```

Turn on `MCP_TRUST_PROXY` only after both direct attempts fail, and only if you want client addresses in the logs. It honors `X-Forwarded-*` from any peer. It changes log lines only: identity, limits and audit key on the token's `uid`.

### 3.4 Smoke test

```sh
curl -si https://mcp.example.com/mcp | head -5
# 401, with WWW-Authenticate: Bearer ... resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource/mcp"
curl -s https://mcp.example.com/.well-known/oauth-protected-resource/mcp
curl -s https://mcp.example.com/.well-known/oauth-protected-resource
# both: resource = MCP_PUBLIC_URL, authorization_servers = [MCP_ISSUER]
```

Then sign in from an MCP client as one test user per role. Check that `okta_status` shows the expected roles and that each tool list holds only that role's commands. Also check a user who is in a role group from the setup config that `policy.yaml` doesn't map (add one to the setup config for the test if needed): they get a token but see only `okta_status`, which says their groups map to no role. A user in none of the setup config's role groups can't get a token at all, because the authorization server's rule and the client app assignments list exactly those groups. That includes a hand-made `mcp-okta-*` group. How each client connects, and which have been tried, is in [`compatibility-matrix.md`](compatibility-matrix.md).

### 3.5 Tell your users

Results are Okta data, and some of it is controlled by outsiders. For example, failed sign-ins put an attacker-chosen username into the System Log, and users write their own profile fields. A model can read instructions planted there as if they came from the user (§12.1, prompt injection). Ask users to connect okta-mcp in a session that has no tools able to send data out (web fetch, email, write access to other systems), or to keep human approval on for those tools.

## 4. Operate

### 4.1 Upgrade

The server is stateless. Pull the new checkout (or change the pinned image tag and digest). Before restarting, check the live policy against the new version: a release can rename or remove a command, or tighten what the loader accepts, and then the policy that loads today stops the new server from starting. Build first, so the check runs the image that will serve:

```sh
docker compose -f compose.example.yaml build    # with a published image: docker compose pull
docker compose -f compose.example.yaml run --rm okta-mcp --check
docker compose -f compose.example.yaml up -d --wait
```

If the check fails, the running server is untouched: fix the policy (§4.2) or go back to the old checkout. `pull_policy: build` rebuilds from the checkout on `up`. Outstanding cursors survive a restart if the cursor key is unchanged. Okta-side objects don't change on upgrade. Read the release notes for new scopes, since a new domain needs a grant, an `OKTA_SCOPES` change and possibly a broader role.

### 4.2 Policy change

1. Edit `policy.yaml` in version control, and get it reviewed. The policy decides who reads what, so treat a change like an access grant.
2. Check it before it goes live. From the `docker/` directory, put the new file beside the live one as `policy.new.yaml`, readable by uid 10001, and run `okta-mcp --check` in a one-off container of the same service, so it sees the same variables, secrets and user as the server:

   ```sh
   sudo install -o 10001 -g 10001 -m 0400 /path/to/reviewed/policy.yaml policy.new.yaml
   docker compose -f compose.example.yaml build    # if the checkout changed since the last up
   docker compose -f compose.example.yaml run --rm \
     -v ./policy.new.yaml:/etc/okta-mcp/policy.new.yaml:ro \
     -e MCP_POLICY_FILE=/etc/okta-mcp/policy.new.yaml \
     okta-mcp --check
   ```

   `--check` runs startup's loading code for the configuration, the service key, the registry, the scrub rules, the guides and the policy, then exits without serving, binding a port or sending a request. It doesn't create or write the audit file; it checks that the server could open it. Exit `0` prints `okta-mcp: check passed` and the warnings startup would log on stdout; exit `2` prints `okta-mcp: check failed` and the reasons startup would give on stderr. It can't check what needs the network or the port: the issuer's keys, the service token (both show on `/readyz`, §3.2) and the port bind. The running server is untouched either way. Fix the file until it passes, and read every warning. `run` publishes no port, so it doesn't clash with the running server.
3. Keep a copy of the old file. Install the checked one as `policy.yaml` and recreate the container (the commands under §3.1, "Replacing a mounted file"), then check `/readyz`.
4. If the container still exits with status `2` (for example, a variable changed between the check and the restart), the reasons are in the logs (`docker compose logs okta-mcp`). Put the old file back the same way. The server never starts with a partly valid policy (fail closed), so a bad file is an outage, not a widening.

There is no hot reload, and no `tools/list` change notification. Clients pick up the new tool lists when their cached list expires (§11.4). Warnings (for example, a role that grants nothing because its deny covers its allow, or `search_attributes` no allowed command can use) don't stop the server or fail the check; `--check` prints them, and the server logs them at startup.

A group ID that no role names grants nothing. Adding a user to a new Okta group does nothing until the policy names that group's ID.

### 4.3 Adding a user, removing a user

- **Add:** put the user in the right `mcp-okta-*` group. The role applies on their next token.
- **Remove:** take the user out of every `mcp-okta-*` group. Under A, access ends within one access-token lifetime (≤ 30 minutes as set up; on an authorization server set up by hand with longer tokens, the server still refuses a token older than `MCP_MAX_TOKEN_AGE`, 1 hour by default). Under B, also revoke their tokens: Clear User Sessions with token revocation, or `DELETE /api/v1/users/{id}/sessions?oauthTokens=true`. Without that, an Okta refresh token that was refused while they had no group starts working again if a group is ever restored ([table](okta-setup.md#refresh-tokens-option-a-or-b)).
- **Under B, failed refreshes** (a removed user's client still trying) appear in the System Log with no `User` target. Search by the client app's ID (`client.id`), not the user.
- **Under B, `lifetime_minutes` is the re-sign-in and MFA interval.** Refreshes don't re-run the Global Session Policy or the authentication policy.

### 4.4 Service key rotation

Rotate on a schedule (at least yearly), whenever someone who could read the key leaves, and on any suspicion of compromise (then also see §5). The service app accepts several active public keys, and the server sends `OKTA_KEY_ID` with each assertion, so rotation can avoid downtime.

**With `scripts/okta-setup.py` (or a hand-made app):**

1. Generate the new pair:

   ```sh
   openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out okta-mcp-service-2.pem
   openssl pkey -in okta-mcp-service-2.pem -pubout -out okta-mcp-service-2.pub.pem
   ```

2. Print its public JWK and `kid`. This is the RFC 7638 thumbprint, the same value the setup tools compute:

   ```sh
   uv run python -c 'import sys,json,hashlib,base64; from jwt.algorithms import RSAAlgorithm as R; j=R.to_jwk(R.prepare_key(R(R.SHA256),open(sys.argv[1]).read()),as_dict=True); m=json.dumps({"e":j["e"],"kty":"RSA","n":j["n"]},separators=(",",":"),sort_keys=True); k=base64.urlsafe_b64encode(hashlib.sha256(m.encode()).digest()).rstrip(b"=").decode(); print(json.dumps({"kty":"RSA","kid":k,"use":"sig","alg":"RS256","n":j["n"],"e":j["e"]}))' okta-mcp-service-2.pub.pem
   ```

3. Add it to the service app (Applications → the service app → General → Public Keys → Add key, then paste the JWK) and leave the old key active. Unverified: whether the console keeps the pasted `kid` or assigns its own. Use the `kid` the console shows.
4. On the server, install the new private key as `secrets/okta_private_key.pem` (owner 10001, mode 0400, as in §3.1), set `OKTA_KEY_ID` to the new `kid`, and run `docker compose -f compose.example.yaml up -d --force-recreate --wait`. `/readyz` turning `ready` proves Okta accepted the new key. The service token is fetched again at startup.
5. Deactivate, then delete, the old key in the console. `okta-setup.py check` reports `manual` while both keys are present. Update `public_key_file` in the setup config to the new public key, then `check` exits `0` again.
6. Destroy every copy of the old private key.

**With Terraform:** the module holds one key, so replacing `okta-mcp-service.jwk.json` and applying swaps the key at once. Run the apply and the server restart back to back. Between the two, the running server keeps using its cached service token (up to its lifetime, 1 hour) but can't get a new one. Unverified: adding the new key by hand first (steps 1–4), then updating the file and applying, should avoid the gap, since the hand-added key's `kid` is the same thumbprint the module computes.

### 4.5 Cursor key rotation

Install a new key and recreate the container:

```sh
umask 077
head -c 32 /dev/urandom | base64 > cursor_key.new
sudo install -o 10001 -g 10001 -m 0400 cursor_key.new secrets/cursor_key && rm cursor_key.new
docker compose -f compose.example.yaml up -d --force-recreate --wait
```

Cursors issued in the last 15 minutes stop working, and clients re-run the command. In `MCP_AUDIT_ARGS=hash` mode the audit hashes change too, because they use a key derived from the cursor key. Lines from before and after the rotation won't match on the same value. Rotate when the key may have leaked: a holder can forge cursors that carry query args the policy didn't check (plan 2.9).

### 4.6 Audit log

The server writes one JSON line per tool call and per denial (§12.3), never result bodies. Args are PII in `full` mode.

- **Sink.** The default is `MCP_AUDIT_LOG=stdout`, so lines go to the container runtime's log driver. Ship them to your SIEM from there, and set the driver's rotation (`max-size`, `max-file`) or use a forwarding driver. Don't use `docker compose logs` as your only copy.
- **File sink.** A file needs an absolute path on a writable mount, since the root filesystem is read-only. The server creates it mode 0600, warns at startup if an existing file is readable by others, and opens it once. Rotate it with `copytruncate` (logrotate) and never move-and-signal, since the server doesn't reopen the file.
- **Access.** Restrict who can read it to the people who investigate MCP use. It records which admin looked up which user.
- **Retention.** 90–365 days, by your policy. If you can't keep PII that long, use `MCP_AUDIT_ARGS=hash`.
- **Fail closed.** If a line can't be written, the call returns `internal_error` instead of an unaudited result. A full disk under a file sink therefore stops all calls.
- **Attribution.** Okta's System Log credits every call to the service app. The audit log is the only per-person record, and it joins to operational logs on `request_id`.

### 4.7 Operational logs and alerts

JSON lines on stderr (§13). Worth alerting on:

| Event | Meaning |
|---|---|
| `service_token_failed` | The server couldn't get a service token: a key, scope or DPoP problem, or Okta is down. A too-narrow admin role doesn't show here; it shows as the 401/403 warning below. The server asks for a new token only in the old one's last minute, so calls keep working for at most about a minute after the first line, then fail and `/readyz` turns 503 until this clears. Alert on repeats; one line followed by a successful token is a blip |
| `jwks_fetch_failed` | A JWKS fetch failed. Keys already loaded keep serving for up to an hour after the last good fetch, then `/mcp` answers 503 and `/readyz` turns 503. At startup, `/mcp` answers 503 until the first fetch succeeds (`/healthz` and the PRM URLs still answer). Alert on repeats |
| `okta_rate_limited` with `reason: over_max_wait` or `retry_failed`, often | The org's shared bucket is exhausted. Lower `MCP_REQUESTS_PER_MINUTE` or the service app's share |
| `limiter_rejected` | One user hit `MCP_REQUESTS_PER_MINUTE` |
| `okta_refused` (warning: `Okta refused the service app's request: HTTP 401/403 <errorCode>`) | `E0000006`: the service app's admin role is too narrow for a command's scope; see the [scope table](okta-setup.md#service-app-scopes-and-admin-roles). `E0000015`: the org may lack the feature the command needs. Without an `errorCode`, `error_code` holds the OAuth error if Okta sent one: `invalid_dpop_proof` means Okta rejected the DPoP proof (check the server's clock; on `sessions get` only, it's [expected](okta-setup.md#service-app-scopes-and-admin-roles)), `insufficient_scope` a scope the service app lacks. A 401 with `E0000011` or `invalid_token` (invalid token) or no code: a token or DPoP problem; the server drops the token and gets a new one on the next call, so repeats mean the key, clock or DPoP setup is wrong. Alert on `error_code` counts, not on single lines |

The default `MCP_REQUESTS_PER_MINUTE` (600) is above some Okta buckets (the users list was 300/min on a trial org, plan 2.4). On a small org, set it below your smallest bucket.

### 4.8 Drift

Run `uv run python scripts/okta-setup.py check --config okta-setup.yaml` on a schedule. `check` reads the service app's admin-role assignments, and the setup guide calls for a Super Administrator token for that. Whether a narrower token can read them is unverified. A scheduled job that holds a Super Administrator token is a bigger risk than the drift it catches, so either run `check` by hand on a calendar, or keep that token in a secret store with the same care as the service key. It exits `1` on any `todo` or `manual` item, for example a grant or admin role someone added to the service app, an access policy widened to all clients, or a second key. Under Terraform, a scheduled `terraform plan -detailed-exitcode` catches changes to the objects it manages, but not an extra access policy or rule someone adds on the authorization server; `check` reports those, so run it too, or alert on policy and rule changes for that server in the System Log.

## 5. Kill switch

In order of speed. Do as many as the incident needs (§11.4). Only step 1 takes effect at once. Steps 2–4 stop new tokens, not ones already issued, because the server checks user tokens locally and never learns that Okta revoked one.

1. **Stop the server:** `docker compose -f compose.example.yaml down`, or remove the route at the proxy. This takes seconds and ends all MCP access.
2. **Deactivate the service app** (Applications → the service app → Deactivate). This is the step for a leaked service key. Unverified (plan 7.3): whether Okta also refuses service tokens issued before the deactivation, or lets them run out (up to an hour). Until that is known, assume a stolen token works for an hour after this step.
3. **Rotate the service key** (§4.4) if the key may have leaked: delete its public key from the app. This stops new service tokens only. A token the thief already holds is bound to the thief's own DPoP key and stays valid for its lifetime, so do step 2 as well.
4. **Cut user sign-in:** deactivate the `okta-mcp` authorization server, or remove the client apps from its access policy. Users' access tokens already issued keep passing the server's checks until they expire (≤ 30 minutes as set up). If that window matters, also do step 1. Under B, also revoke the affected users' tokens (§4.3).
5. **Rotate the cursor key** (`secrets/cursor_key`, §4.5) if it may have leaked. Outstanding cursors stop working when the container is recreated.

Afterward, review the audit log for the window, and Okta's System Log for the service app's client ID, for calls that didn't come through the server.

## 6. Decommission

Stop and remove the container. Delete `secrets/`. In Okta, delete the service app, the client apps, the authorization server and the `mcp-okta-*` groups, or run `terraform destroy`. The setup script never deletes anything. Keep the audit log for its retention period.
