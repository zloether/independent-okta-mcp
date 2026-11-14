# Okta setup

`scripts/okta-setup.py` checks, and optionally creates, everything okta-mcp needs on the Okta side (design Appendix C). Run `check` at any time; it only reads. `apply` creates what is missing after showing you the list and asking.

If you manage Okta with Terraform, use [`terraform/okta/`](../terraform/okta/) instead; see [Terraform](#terraform). It creates the same objects. Pick one tool per org.

## Prerequisites

**A custom authorization server, which needs Okta's API Access Management add-on.** Users sign in to okta-mcp through a custom authorization server, because the org authorization server can't issue access tokens with your own audience or the `groups` claim. Both setup tools create a new one (`okta-mcp` by default). Okta says:

- Custom authorization servers are part of API Access Management, an optional add-on in production orgs.
- Since March 2023, an Enterprise or One-App subscription without the add-on includes only the built-in `default` custom authorization server and can't create new ones. Servers created before then keep working.
- Developer and Integrator Free Plan orgs include it.

To check your org: in the Admin Console, go to **Security → API**. No **Authorization Servers** tab means no custom authorization servers at all. A tab listing only `default`, with **Add Authorization Server** refused, means you can't create one. Okta's code for a missing feature is `E0000015`; when `okta-setup.py` gets it (HTTP 401 or 403) from the authorization-server endpoints, it stops with a note naming the add-on. The exact response on such an org hasn't been seen, so another error is possible. Terraform fails at `apply` with the provider's error. To add it, ask your Okta account team for the API Access Management SKU.

Without the add-on there is no supported path today. Pointing the tools at the built-in `default` server (`authorization_server: default`) would mean changing its audience to `mcp_public_url`, which breaks anything else that validates `api://default` tokens; the script never changes an audience and reports it as `manual`. This hasn't been tried. The alternative the design names (the org authorization server plus a server-side group lookup, design §9.5) isn't built.

## What it manages

| Object | Settings |
|---|---|
| Groups | One Okta group per role, named `mcp-okta-*` (the prefix is `group_prefix`; see [Group names](#group-names)) |
| Public clients | One native OIDC app per approved MCP client: authorization code (plus refresh token with rotation under [option B](#refresh-tokens-option-a-or-b)), PKCE required, no client secret, exact redirect URIs, role groups assigned |
| Custom authorization server | Audience = `mcp_public_url` |
| Scope | `okta-mcp`, implicit consent, published in metadata |
| `groups` claim | On the access token, always included; emits the **IDs** of Okta groups whose name starts with the prefix |
| Access policy `okta-mcp clients` | Applies only to the configured clients |
| Policy rule `okta-mcp groups` | Authorization code only, role groups only, scopes `openid profile email offline_access okta-mcp`, access token ≤30 min; refresh tokens no longer than an access token under option A, or as set in `refresh_tokens` under option B |
| Service app | API Services app, `private_key_jwt` with your public key, **Require DPoP on**, the configured `okta.*.read` grants, and the admin role those scopes need (see [the next section](#service-app-scopes-and-admin-roles)) |

### Group names

The role groups' names start with a prefix, `mcp-okta-` unless you set `group_prefix` (script config or Terraform variable). The `groups` claim emits the IDs of the user's Okta-mastered groups whose names start with it, and the setup tools refuse group names that don't start with it, compared case-sensitively (whether Okta's match ignores case is unchecked; matching the prefix's case exactly is safe either way). Pick a prefix only your MCP role groups use: a broader one puts more of each user's group IDs in every token, toward Okta's cap on the claim (about 100). It doesn't grant anything by itself; the policy matches IDs. Allowed: 4 to 64 characters, a letter or digit first, then letters, digits, space, `_`, `.`, `:` and `-` (the prefix goes inside a quoted Okta expression, so quotes, backslashes and braces are refused). Okta matches it as a prefix only, so a convention that marks groups by a suffix or a middle part (`Helpdesk-OktaMCP`) needs a hand-written claim expression, which the script then reports as `manual`.

Changing the prefix after setup: Terraform updates the claim in place; the script never changes a claim expression, so it reports the old one as `manual` and you edit it in the admin console (Security → API → the authorization server → Claims). Rename or recreate the groups to match first, or users lose their roles until you do.

## Service app scopes and admin roles

Okta answers a service-app request only when the token's scope **and** the app's admin role both allow it. The scopes you grant (`service_app.scopes`, which become the server's `OKTA_SCOPES`) set which commands the server can offer. The server hides any command whose scope isn't configured. Each scope also needs an admin role broad enough for its endpoints:

| Scope | Narrowest standard role | Commands that need it |
|---|---|---|
| `okta.users.read` | `READ_ONLY_ADMIN` | Resolving a login to a user ID (any command with a `user` argument); `org-settings list-yubikey-tokens`, `get-yubikey-token` (role unverified for these); `diagnostics login-failures` |
| `okta.groups.read` | `READ_ONLY_ADMIN` | `groups` |
| `okta.networkZones.read` | `READ_ONLY_ADMIN` | `network-zones` |
| `okta.apps.read` | `READ_ONLY_ADMIN` | `apps`, except the grant and interclient commands |
| `okta.apps.interclientTrust.read` | `READ_ONLY_ADMIN` | `apps list-interclient-allowed`, `list-interclient-targets` |
| `okta.policies.read` | `READ_ONLY_ADMIN` | `policies` |
| `okta.authenticators.read` | `READ_ONLY_ADMIN` | `authenticators` |
| `okta.behaviors.read` | `READ_ONLY_ADMIN` | `behaviors` |
| `okta.logs.read` | `READ_ONLY_ADMIN` | `logs`; `diagnostics login-failures` |
| `okta.threatInsights.read` | `READ_ONLY_ADMIN` | `security get-threat-insight-config` |
| `okta.apiTokens.read` | `READ_ONLY_ADMIN` | `api-tokens` |
| `okta.authorizationServers.read` | `READ_ONLY_ADMIN` | `authorization-servers` |
| `okta.idps.read` | `READ_ONLY_ADMIN` | `identity-providers` (role shown for `list` only) |
| `okta.captchas.read` | `READ_ONLY_ADMIN` | `org-settings get-captcha-settings` |
| `okta.profileMappings.read` | `READ_ONLY_ADMIN` | `schemas list-mappings`, `get-mapping` |
| `okta.userTypes.read` | `READ_ONLY_ADMIN` | `schemas list-user-types`, `get-user-type` |
| `okta.uischemas.read` | `READ_ONLY_ADMIN` | `schemas list-ui-schemas`, `get-ui-schema` |
| `okta.devices.read` | `READ_ONLY_ADMIN` | `devices` |
| `okta.deviceAssurance.read` | `READ_ONLY_ADMIN` | `device-assurance` |
| `okta.devicePostureChecks.read` | `READ_ONLY_ADMIN` | `device-posture` |
| `okta.sessions.read` | `READ_ONLY_ADMIN` | `sessions`, only with DPoP off (see below) |
| `okta.schemas.read` | `ORG_ADMIN` | `schemas get-user-schema`, `get-group-schema` (`get-app-user-schema` needs only `READ_ONLY_ADMIN`) |
| `okta.linkedObjects.read` | `ORG_ADMIN` | `schemas list-linked-objects`, `get-linked-object` |
| `okta.orgs.read` | `SUPER_ADMIN` | `org-settings get-third-party-admin-setting`, `get-support-settings`, `get-admin-app-setting`, `get-client-privileges`; the rest of `org-settings` and `attack-protection` need only `READ_ONLY_ADMIN` |
| `okta.logStreams.read` | `SUPER_ADMIN` | `schemas list-log-stream-schemas`, `get-log-stream-schema` |
| `okta.appGrants.read` | `SUPER_ADMIN` | `apps list-grants`, `get-grant` |
| `okta.securityEventsProviders.read` | `SUPER_ADMIN` | `security list-event-providers`, `get-event-provider` |
| `okta.roles.read` | `SUPER_ADMIN` | `groups list-roles`, `get-role`, `list-role-app-targets`, `list-role-group-targets`; `iam`; `oauth-client-roles` |

`diagnostics` commands read several domains. They need only the scopes in the table rows that name them; the other scopes they can use are optional. Without one, the command still runs and lists the check it skipped (and the scope it would need) in its result. `diagnostics login-failures` also uses `okta.apps.read` (whether the user is assigned to the app that refused them), so grant it unless you want that check off.

The table was found in a dev org (2026-11-13) by running each command under Read-only Administrator, then Org Administrator, then Super Administrator. A role is the one every command under the scope needs; where only some of a scope's commands need it, the last column says which.

The service app needs the highest role in the table among its scopes, so each deployment picks its role by picking scopes. Okta allows a call only when the token's scopes and the app's role both do, and every scope here is `.read`, so even a Super Administrator service app can't write. A broader role still lets a stolen service key read more of what its scopes cover, and would let it write if someone later granted the app a `.manage` scope. To stay at Read-only Administrator, leave out the scopes that need more: their commands disappear from every user's tool list. Granting such a scope while keeping the narrower role isn't supported: `check` reports the missing role, Terraform fails the plan, and the commands the last column names get HTTP 403 from Okta.

Some endpoints also need an Okta feature that not every org has, whatever the role: `groups get-owners`, `apps list-cwo-connections` and `devices get-os-accounts` return HTTP 401 (`E0000015`) on orgs without it. `org-settings list-support-cases` returned 403 even under Super Administrator in the dev org, which has no Okta support contract (the likely cause; untested on an org with one).

**`sessions get` needs DPoP off.** Okta rejects `GET /api/v1/sessions/{id}` from a DPoP-bound token with HTTP 400 `invalid_dpop_proof` ("'htu' claim in the DPoP proof JWT is invalid"), though the proof is built as for every other endpoint. The same call works with a bearer token (dev org, 2026-11-14). This is Okta's bug and may be fixed later, so the command stays. Choose one:

- **DPoP (default, recommended):** leave `okta.sessions.read` out. Every other command works, and a stolen service token is useless without the server's in-memory DPoP key.
- **Sessions:** grant `okta.sessions.read`, turn off Require DPoP on the service app, and set `OKTA_DPOP=false`. The token then works for anyone holding it until it expires. The setup tools always turn Require DPoP on, so turn it off by hand afterwards: `check` then reports it as `todo`. The next script or Terraform `apply` turns it back on, and then every command fails (`service_token_failed`) until you turn it off again.

`check` needs the role the table names for the configured scopes, or a custom role in its place; narrower standard roles held alongside it are allowed. `apply` assigns Read-only Administrator and nothing broader: when the scopes need Org or Super Administrator, `apply` still assigns Read-only Administrator to an app it created, reports the broader role as `manual`, and you assign it in the admin console (Applications > the service app > Admin roles). Until then the commands that need it get 403. A scope not in the table is refused, and so is a role broader than the scopes need.

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

3. **A config file.** Copy [`scripts/okta-setup.example.yaml`](../scripts/okta-setup.example.yaml) and edit it, including the [refresh-token choice](#refresh-tokens-option-a-or-b). Invalid configs are rejected before anything is sent to Okta: unknown keys, a `group_prefix` outside its character set, group names without the prefix, scopes other than `okta.*.read`, access-token lifetimes over 30 minutes, and refresh-token lifetimes over 24 hours.

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
- **adds** missing links: app group assignments, configured clients in the access policy, and configured groups in the policy rule, plus the grants and the Read-only Administrator role (when the scopes need no more) on a service app it creates in the same run;
- **turns on** Require DPoP on the service app. Okta leaves it off for apps created through the API.

It never deletes anything, never removes grants, roles, clients or groups, and never changes audiences, claim expressions, app types, redirect URIs or token lifetimes. Those differences are reported as `manual`. So are settings that widen access: extra grants on the service app or admin roles broader than its scopes need, policies that apply to `ALL_CLIENTS` or `EVERYONE`, individual users in the rule, and imported groups with a role group's name.

An existing object that fails any check is not trusted, and nothing that depends on it is changed:

- a group: not assigned to clients, added to the rule or listed for `policy.yaml`;
- a client app: not assigned groups, added to the access policy or listed in `MCP_ALLOWED_CLIENT_IDS`;
- the authorization server: no scope, claim, policy or rule is added and `MCP_ISSUER` is not printed;
- the access policy or rule: no clients or groups are added;
- the service app, or one with grants or admin roles beyond the configured ones: no grants, role or Require DPoP, and its client ID is not printed.

An existing service app that passes every check still gets no new grants or admin role. Its public key is public, so anyone who can create apps could have set one up in advance for a Super Admin to empower. Missing grants or a missing role are reported as `manual`, with the app's ID and creation date. Confirm the app is yours, then grant them in the admin console.

The rule must allow the authorization code grant only, so a rule that also lists the refresh token grant is reported; refresh tokens are turned on per client app. A client app's grants must match the config exactly: a refresh token grant under option A, or one without rotation (leeway ≤30 s) under option B, makes the app untrusted. Untrusted only means the tool adds nothing more to it; an app already in the access policy stays there, so remove it from the policy by hand if it shouldn't get tokens. A rule whose refresh tokens last longer, or stay valid while idle longer, than allowed (the access-token lifetime under A, `refresh_tokens` under B) is reported and gets no new groups. A rule without `offline_access` is reported, but still trusted, since it only blocks sign-in. A rule that runs a token inline hook is reported and gets no new groups: a hook can rewrite the `groups` claim after the claim expression has run. Any other ACTIVE access policy on the authorization server, or other ACTIVE rule in the policy, is reported: Okta applies the first match by priority, so it could issue tokens the managed rule doesn't bound. Terraform manages only its own objects and doesn't see these; run `check` after a Terraform apply too, or watch the System Log for policy and rule changes on the authorization server. A service app with a `jwks_uri` is reported. The service app must hold exactly the configured public key, so during a key rotation `check` reports the second key as `manual` until the old one is removed. If two groups, apps or authorization servers share a configured name, the tool stops with an error instead of picking one.

## After setup

- Add users to the `mcp-okta-*` groups. The tool creates the groups but never manages membership.
- To remove a user, take them out of the groups. Under option B, also clear their sessions with token revocation (see [the table above](#refresh-tokens-option-a-or-b)).
- **Protect membership of the `mcp-okta-*` groups.** Anyone who can add a user to one grants that role (design §8.2): Org Admins, Group Admins and Group Membership Admins whose scope includes the group, custom roles with `okta.groups.members.manage`, and group rules that target it. Keep these groups out of delegated admins' resource sets, don't target them with group rules, and alert on `group.user_membership.add` for their IDs. A new or renamed `mcp-okta-*` group grants nothing by itself: the server's policy matches group IDs.
- **Require MFA for the client apps.** Assign the public client apps an authentication policy that requires MFA (Applications > the client > Sign On); a new app gets the org's default policy. Neither tool sets this.
- **Cap the service app's rate-limit share** (Applications > the service app > Application Rate Limits), so MCP traffic can't use up limits other integrations depend on (design §10, not yet verified in the dev org).
- Re-run `check` after any change in the admin console.

## Terraform

`terraform/okta/` is a root module for the [okta/okta provider](https://registry.terraform.io/providers/okta/okta/latest) (`~> 7.1`) with the same objects, names and checks as the script: inputs that would widen access (group names without the prefix, scopes other than `okta.*.read`, access-token lifetimes over 30 minutes, refresh-token lifetimes over 24 hours, a private or short key) fail at `plan`. The service app gets the role [the table](#service-app-scopes-and-admin-roles) names for `service_scopes`; when that is Org or Super Administrator, `plan` fails unless you set `allow_org_admin = true` or `allow_super_admin = true`. Set `refresh_tokens` for option B; leave it unset for A. Unlike the script, changing it or `group_prefix` later updates the apps, rule and claim in place.

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
- The script assigns only Read-only Administrator; Org and Super Administrator are assigned by hand (or by Terraform with `allow_org_admin` or `allow_super_admin`). You can assign a narrower custom admin role by hand instead; the tool then accepts it and adds no standard role, but it does not check the custom role's permissions. In Terraform, replace `okta_app_oauth_role_assignment.service` with a `CUSTOM` assignment.