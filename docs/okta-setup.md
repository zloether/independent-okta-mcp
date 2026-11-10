# Okta setup

`scripts/okta-setup.py` checks, and optionally creates, everything okta-mcp needs on the Okta side (design Appendix C). Run `check` at any time; it only reads. `apply` creates what is missing after showing you the list and asking.

If you manage Okta with Terraform, use [`terraform/okta/`](../terraform/okta/) instead; see [Terraform](#terraform). It creates the same objects. Pick one tool per org.

## What it manages

| Object | Settings |
|---|---|
| Groups | One Okta group per role, named `mcp-okta-*` |
| Public clients | One native OIDC app per approved MCP client: authorization code (plus refresh token with rotation under [option B](#refresh-tokens-option-a-or-b)), PKCE required, no client secret, exact redirect URIs, role groups assigned |
| Custom authorization server | Audience = `mcp_public_url` |
| Scope | `okta-mcp`, implicit consent, published in metadata |
| `groups` claim | On the access token, always included; emits the **IDs** of Okta groups named `mcp-okta-*` |
| Access policy `okta-mcp clients` | Applies only to the configured clients |
| Policy rule `okta-mcp groups` | Authorization code only, role groups only, scopes `openid profile email offline_access okta-mcp`, access token ≤30 min; refresh tokens no longer than an access token under option A, or as set in `refresh_tokens` under option B |
| Service app | API Services app, `private_key_jwt` with your public key, **Require DPoP on**, the configured `okta.*.read` grants, Read-only Administrator role |

## Before you start

1. **An admin API token.** `apply` creates an authorization server and assigns an admin role, which needs a **Super Administrator** token. `check` only reads, but those reads include admin-role assignments, so use the same token. The token is used only by this tool. Never give it to the server, and revoke it when you are done.

   ```sh
   export OKTA_ORG_URL=https://example.okta.com
   export OKTA_SETUP_API_TOKEN=…   # Security > API > Tokens
   ```

2. **The service app key pair.** The tool reads only the public half. The private key goes to the server as a secret (`OKTA_PRIVATE_KEY_FILE`).

   ```sh
   openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out okta-mcp-service.pem
   openssl pkey -in okta-mcp-service.pem -pubout -out okta-mcp-service.pub.pem
   ```

3. **A config file.** Copy [`scripts/okta-setup.example.yaml`](../scripts/okta-setup.example.yaml) and edit it, including the [refresh-token choice](#refresh-tokens-option-a-or-b). Invalid configs are rejected before anything is sent to Okta: unknown keys, group names without the `mcp-okta-` prefix, scopes other than `okta.*.read`, access-token lifetimes over 30 minutes, and refresh-token lifetimes over 24 hours.

## Refresh tokens: option A or B

The server works the same either way. It never sees a refresh token and checks every access token in full on every call, so this is an Okta setting you choose per deployment.

| | **A: no refresh tokens** (default) | **B: rotating refresh tokens** |
|---|---|---|
| Config | omit `refresh_tokens` | `refresh_tokens: {idle_minutes: 60, lifetime_minutes: 480}` (example values) |
| Client apps | Authorization code grant | Authorization code and refresh token grants, rotation on (30 s leeway) |
| Users sign in | Every `access_token_minutes` | When the session has been idle for `idle_minutes`, or `lifetime_minutes` after the first sign-in |
| A stolen token works for | One access-token lifetime | Until the refresh token goes idle or expires. Rotation narrows this: each refresh token works once (plus the leeway), so the thief and the user can't both keep using the same one. How Okta handles the reuse wasn't tested here |
| Group removed or changed | Takes effect within one access-token lifetime | The same: Okta rebuilds the `groups` claim on every refresh, and refuses the refresh once the user is in no MCP group |
| Cutting someone off for good | Remove them from the `mcp-okta-*` groups | Also revoke their tokens: Clear User Sessions in the admin console, or `DELETE /api/v1/users/{id}/sessions?oauthTokens=true` (or deactivate the user). Clearing sessions without `oauthTokens=true` leaves refresh tokens working. Okta keeps a refused refresh token, so it works again if any MCP group is restored before it expires |

Pick A when sign-in every 30 minutes is acceptable, or when the clients run on shared or unmanaged machines. Pick B for day-long interactive use on managed devices. Either way, the rule must allow `offline_access`: Claude Code always requests it, and a rule without it fails sign-in with `no_matching_policy`. Under A, Okta grants the scope but issues no refresh token. As a backstop, the rule's refresh-token lifetime and idle window are set to the access-token lifetime under A, so a client app that gets the refresh token grant by mistake gains nothing beyond one access-token lifetime.

Under B, keep `access_token_minutes` well above 5: Claude Code refreshes tokens that are close to expiry, and with 5-minute tokens it refreshed on almost every call in testing. `idle_minutes` must be at least `access_token_minutes`, or the refresh token goes idle before the access token expires. Both bounds are checked before anything is sent to Okta (and at `terraform plan`).

Under B, `lifetime_minutes` is how often users must sign in again, whatever the Global Session Policy says. Refreshes don't need an Okta session and don't re-run the session or authentication policies, so an MFA requirement every 2 hours doesn't shorten an 8-hour refresh chain. If you want MFA at a set interval, set `lifetime_minutes` no longer than that interval.

`apply` doesn't switch an existing deployment between A and B: it never changes a client's grant types or the rule's token lifetimes. After changing the config, `check` reports what differs as `manual`. Change it in the admin console (Applications > the client > General: Refresh Token grant and rotation; Security > API > the authorization server > Access Policies > the rule), then run `check` again.

## Run

```sh
uv run python scripts/okta-setup.py check --config okta-setup.yaml
uv run python scripts/okta-setup.py apply --config okta-setup.yaml   # add --yes to skip the prompt
```

Each line has a status:

| Status | Meaning |
|---|---|
| `ok` | Matches the config |
| `todo` | Missing; `apply` will create or add it |
| `done` | `apply` just created or added it |
| `manual` | Exists but differs in a way the tool will not change; fix it in the admin console |

When nothing is missing, the tool prints the values to give the server (`MCP_ISSUER`, `MCP_ALLOWED_CLIENT_IDS`, `OKTA_CLIENT_ID`, `OKTA_KEY_ID`, `OKTA_SCOPES`, …) and the group IDs to put in `policy.yaml`. Exit status is `0` when everything matches, `1` when `todo` or `manual` items remain, and `2` on errors, so `check` can run in CI or on a schedule to catch drift.

## What `apply` will and won't change

`apply` finds objects by name: the group name, the app label, the authorization server name, and the fixed policy and rule names. It then:

- **creates** missing objects;
- **adds** missing links: app group assignments, configured clients in the access policy, and configured groups in the policy rule, plus the grants and the Read-only Administrator role on a service app it creates in the same run;
- **turns on** Require DPoP on the service app. Okta leaves it off for apps created through the API.

It never deletes anything, never removes grants, roles, clients or groups, and never changes audiences, claim expressions, app types, redirect URIs or token lifetimes. Those differences are reported as `manual`. So are settings that widen access: extra grants or admin roles on the service app (never use Super Admin), policies that apply to `ALL_CLIENTS` or `EVERYONE`, individual users in the rule, and imported groups with an `mcp-okta-` name.

An existing object that fails any check is not trusted, and nothing that depends on it is changed:

- a group: not assigned to clients, added to the rule or listed for `policy.yaml`;
- a client app: not assigned groups, added to the access policy or listed in `MCP_ALLOWED_CLIENT_IDS`;
- the authorization server: no scope, claim, policy or rule is added and `MCP_ISSUER` is not printed;
- the access policy or rule: no clients or groups are added;
- the service app, or one with grants or admin roles beyond the configured ones: no grants, role or Require DPoP, and its client ID is not printed.

An existing service app that passes every check still gets no new grants or admin role. Its public key is public, so anyone who can create apps could have set one up in advance for a Super Admin to empower. Missing grants or a missing role are reported as `manual`, with the app's ID and creation date. Confirm the app is yours, then grant them in the admin console.

The rule must allow the authorization code grant only, so a rule that also lists the refresh token grant is reported; refresh tokens are turned on per client app. A client app's grants must match the config exactly: a refresh token grant under option A, or one without rotation (leeway ≤30 s) under option B, makes the app untrusted. Untrusted only means the tool adds nothing more to it; an app already in the access policy stays there, so remove it from the policy by hand if it shouldn't get tokens. A rule whose refresh tokens last longer, or stay valid while idle longer, than allowed (the access-token lifetime under A, `refresh_tokens` under B) is reported and gets no new groups. A rule without `offline_access` is reported, but still trusted, since it only blocks sign-in. The service app must hold exactly the configured public key, so during a key rotation `check` reports the second key as `manual` until the old one is removed. If two groups, apps or authorization servers share a configured name, the tool stops with an error instead of picking one.

## After setup

- Add users to the `mcp-okta-*` groups. The tool creates the groups but never manages membership.
- To remove a user, take them out of the groups. Under option B, also clear their sessions with token revocation (see [the table above](#refresh-tokens-option-a-or-b)).
- **Protect membership of the `mcp-okta-*` groups.** Anyone who can add a user to one grants that role (design §8.2): Org Admins, Group Admins and Group Membership Admins whose scope includes the group, custom roles with `okta.groups.members.manage`, and group rules that target it. Keep these groups out of delegated admins' resource sets, don't target them with group rules, and alert on `group.user_membership.add` for their IDs. A new or renamed `mcp-okta-*` group grants nothing by itself: the server's policy matches group IDs.
- **Require MFA for the client apps.** Assign the public client apps an authentication policy that requires MFA (Applications > the client > Sign On); a new app gets the org's default policy. Neither tool sets this.
- **Cap the service app's rate-limit share** (Applications > the service app > Application Rate Limits), so MCP traffic can't use up limits other integrations depend on (design §10, not yet verified in the dev org).
- Re-run `check` after any change in the admin console.

## Terraform

`terraform/okta/` is a root module for the [okta/okta provider](https://registry.terraform.io/providers/okta/okta/latest) (`~> 7.1`) with the same objects, names and checks as the script: inputs that would widen access (group names without the prefix, scopes other than `okta.*.read`, access-token lifetimes over 30 minutes, refresh-token lifetimes over 24 hours, a private or short key) fail at `plan`. Set `refresh_tokens` for option B; leave it unset for A. Unlike the script, changing it later updates the apps and rule in place.

1. Create the key pair as above, then convert the public half to a JWK. Terraform cannot parse PEM, and needs only the public JWK:

   ```sh
   uv run python -c 'import sys; from jwt.algorithms import RSAAlgorithm as R; print(R.to_jwk(R(R.SHA256).prepare_key(open(sys.argv[1]).read())))' \
     okta-mcp-service.pub.pem > terraform/okta/okta-mcp-service.jwk.json
   ```

2. Copy `terraform/okta/terraform.tfvars.example` to `terraform.tfvars` and edit it. Add a backend to `versions.tf`. State holds IDs and settings but no secrets: the clients have none and the service app holds only the public key.

3. Run with a Super Administrator token, as for the script:

   ```sh
   export OKTA_API_TOKEN=…   # the org comes from okta_org_url in terraform.tfvars
   cd terraform/okta && terraform init && terraform plan
   ```

4. After `apply`, `terraform output server_env` gives the server's environment and `terraform output group_ids` the IDs for `policy.yaml`. `OKTA_KEY_ID` is the RFC 7638 thumbprint, the same value the script computes.

Unlike the script, Terraform owns what it creates: `apply` reverts console changes and `destroy` deletes the objects. `okta_app_group_assignments` owns *all* group assignments of each client app, so assign other groups through `groups`, not the console. Group membership stays outside Terraform. Neither the script nor this module manages the other's objects; to move from the script to Terraform, add `import` blocks for the existing objects (each resource's provider docs give the import ID) and check that `plan` shows no changes.

## Limits

- Only native (loopback or custom-scheme redirect) public clients are created. Register other client types by hand, then add their client IDs to the access policy.
- Only the Read-only Administrator role is managed. You can assign a narrower custom admin role by hand instead; the tool then accepts it and does not add Read-only Administrator, but it does not check the custom role's permissions. In Terraform, replace `okta_app_oauth_role_assignment.service` with a `CUSTOM` assignment.