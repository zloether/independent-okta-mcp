# Okta setup

`scripts/okta-setup.py` checks, and optionally creates, everything okta-mcp needs on the Okta side (design Appendix C). Run `check` at any time; it only reads. `apply` creates what is missing after showing you the list and asking.

If you manage Okta with Terraform, use [`terraform/okta/`](../terraform/okta/) instead; see [Terraform](#terraform). It creates the same objects. Pick one tool per org.

## What it manages

| Object | Settings |
|---|---|
| Groups | One Okta group per role, named `mcp-okta-*` |
| Public clients | One native OIDC app per approved MCP client: authorization code, PKCE required, no client secret, exact redirect URIs, role groups assigned |
| Custom authorization server | Audience = `mcp_public_url` |
| Scope | `okta-mcp`, implicit consent, published in metadata |
| `groups` claim | On the access token, always included; emits the **IDs** of Okta groups named `mcp-okta-*` |
| Access policy `okta-mcp clients` | Applies only to the configured clients |
| Policy rule `okta-mcp groups` | Authorization code only, role groups only, access token ≤30 min, no refresh tokens |
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

3. **A config file.** Copy [`scripts/okta-setup.example.yaml`](../scripts/okta-setup.example.yaml) and edit it. Invalid configs are rejected before anything is sent to Okta: unknown keys, group names without the `mcp-okta-` prefix, scopes other than `okta.*.read`, and token lifetimes over 30 minutes.

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
- **adds** missing links: app group assignments, service-app grants, the Read-only Administrator role, configured clients in the access policy, and configured groups in the policy rule;
- **turns on** Require DPoP on the service app. Okta leaves it off for apps created through the API.

It never deletes anything, never removes grants, roles, clients or groups, and never changes audiences, claim expressions, app types, redirect URIs or token lifetimes. Those differences are reported as `manual`. So are settings that widen access: extra grants or admin roles on the service app (never use Super Admin), policies that apply to `ALL_CLIENTS` or `EVERYONE`, individual users in the rule, and imported groups with an `mcp-okta-` name.

An existing object that fails any check is not trusted, and nothing that depends on it is changed:

- a group: not assigned to clients, added to the rule or listed for `policy.yaml`;
- a client app: not assigned groups, added to the access policy or listed in `MCP_ALLOWED_CLIENT_IDS`;
- the authorization server: no scope, claim, policy or rule is added and `MCP_ISSUER` is not printed;
- the access policy or rule: no clients or groups are added;
- the service app: no grants, role or Require DPoP, and its client ID is not printed.

The rule must allow the authorization code grant only, so a rule that also allows refresh tokens is reported. The service app must hold exactly the configured public key, so during a key rotation `check` reports the second key as `manual` until the old one is removed. If two groups, apps or authorization servers share a configured name, the tool stops with an error instead of picking one.

## After setup

- Add users to the `mcp-okta-*` groups. The tool creates the groups but never manages membership.
- Restrict who can create or rename `mcp-okta-*` groups, and alert on it: anyone who can create such a group can get it into the `groups` claim.
- Re-run `check` after any change in the admin console.

## Terraform

`terraform/okta/` is a root module for the [okta/okta provider](https://registry.terraform.io/providers/okta/okta/latest) (`~> 7.1`) with the same objects, names and checks as the script: inputs that would widen access (group names without the prefix, scopes other than `okta.*.read`, token lifetimes over 30 minutes, a private or short key) fail at `plan`.

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