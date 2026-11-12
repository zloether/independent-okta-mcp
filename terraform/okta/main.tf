locals {
  description = "Managed by okta-mcp terraform/okta"

  # Emits IDs of Okta-mastered groups whose name starts with mcp-okta- (design §8.2, V13).
  # Keep in sync with GROUPS_EXPRESSION in scripts/okta-setup.py.
  groups_expression = "user.getGroups({'group.type': {'OKTA_GROUP'}}, {'group.profile.name': {'mcp-okta-'}}).![id]"

  jwk = jsondecode(file(var.service_public_jwk_file))
  # RFC 7638 thumbprint, the same kid scripts/okta-setup.py computes.
  kid = replace(replace(trimsuffix(base64sha256(jsonencode({ e = local.jwk.e, kty = "RSA", n = local.jwk.n })), "="), "+", "-"), "/", "_")

  # The narrowest standard admin role each scope needs (docs/okta-setup.md#service-app-scopes-and-admin-roles).
  # Keep in sync with SCOPE_ROLES in scripts/okta-setup.py (tested).
  scope_roles = {
    "okta.users.read"        = "READ_ONLY_ADMIN"
    "okta.groups.read"       = "READ_ONLY_ADMIN"
    "okta.networkZones.read" = "READ_ONLY_ADMIN"
    "okta.roles.read"        = "SUPER_ADMIN"
  }
  service_role = contains([for s in var.service_scopes : lookup(local.scope_roles, s, "")], "SUPER_ADMIN") ? "SUPER_ADMIN" : "READ_ONLY_ADMIN"
}

# --- Role groups ---------------------------------------------------------------

resource "okta_group" "role" {
  for_each = var.groups

  name        = each.value
  description = local.description
}

# --- Public clients --------------------------------------------------------------

resource "okta_app_oauth" "client" {
  for_each = var.clients

  label                      = each.key
  type                       = "native"
  grant_types                = var.refresh_tokens == null ? ["authorization_code"] : ["authorization_code", "refresh_token"]
  response_types             = ["code"]
  redirect_uris              = each.value
  token_endpoint_auth_method = "none"
  pkce_required              = true
  refresh_token_rotation     = var.refresh_tokens == null ? null : "ROTATE"
  refresh_token_leeway       = var.refresh_tokens == null ? null : 30
}

# Owns all group assignments of each client app.
resource "okta_app_group_assignments" "client" {
  for_each = okta_app_oauth.client

  app_id = each.value.id

  dynamic "group" {
    for_each = okta_group.role
    content {
      id = group.value.id
    }
  }
}

# --- Authorization server ------------------------------------------------------

resource "okta_auth_server" "mcp" {
  name        = var.authorization_server
  description = local.description
  audiences   = [var.mcp_public_url]
}

resource "okta_auth_server_scope" "mcp" {
  auth_server_id   = okta_auth_server.mcp.id
  name             = var.scope
  description      = "Use the okta-mcp server"
  consent          = "IMPLICIT"
  metadata_publish = "ALL_CLIENTS"
}

resource "okta_auth_server_claim" "groups" {
  auth_server_id          = okta_auth_server.mcp.id
  name                    = "groups"
  claim_type              = "RESOURCE"
  value_type              = "EXPRESSION"
  value                   = local.groups_expression
  always_include_in_token = true
}

resource "okta_auth_server_policy" "clients" {
  auth_server_id   = okta_auth_server.mcp.id
  name             = "okta-mcp clients"
  description      = local.description
  priority         = 1
  client_whitelist = [for app in okta_app_oauth.client : app.client_id]
}

# Refresh grants match an authorization_code rule; refresh is turned on per client app (option B).
# Under option A, a client given the refresh_token grant anyway gets refresh tokens that last no
# longer than an access token. Claude Code requests offline_access; without it, sign-in fails
# with no_matching_policy.
resource "okta_auth_server_policy_rule" "groups" {
  auth_server_id                 = okta_auth_server.mcp.id
  policy_id                      = okta_auth_server_policy.clients.id
  name                           = "okta-mcp groups"
  priority                       = 1
  grant_type_whitelist           = ["authorization_code"]
  scope_whitelist                = ["openid", "profile", "email", "offline_access", okta_auth_server_scope.mcp.name]
  group_whitelist                = [for g in okta_group.role : g.id]
  access_token_lifetime_minutes  = var.access_token_minutes
  refresh_token_lifetime_minutes = var.refresh_tokens == null ? var.access_token_minutes : var.refresh_tokens.lifetime_minutes
  refresh_token_window_minutes   = var.refresh_tokens == null ? var.access_token_minutes : var.refresh_tokens.idle_minutes

  lifecycle {
    precondition {
      condition     = var.refresh_tokens == null || try(var.refresh_tokens.idle_minutes >= var.access_token_minutes, false)
      error_message = "refresh_tokens.idle_minutes must be at least access_token_minutes."
    }
  }
}

# --- Service app (the server's own Okta credential) ----------------------------

resource "okta_app_oauth" "service" {
  label                      = var.service_app_name
  type                       = "service"
  grant_types                = ["client_credentials"]
  response_types             = ["token"]
  token_endpoint_auth_method = "private_key_jwt"
  # Okta leaves this off for apps created through the API (spike V15).
  dpop_bound_access_tokens = true

  jwks {
    kty = "RSA"
    kid = local.kid
    e   = local.jwk.e
    n   = local.jwk.n
  }
}

resource "okta_app_oauth_api_scope" "service" {
  app_id = okta_app_oauth.service.id
  issuer = var.okta_org_url
  scopes = var.service_scopes
}

resource "okta_app_oauth_role_assignment" "service" {
  client_id = okta_app_oauth.service.client_id
  type      = local.service_role

  lifecycle {
    # A scope change replaces the role; keep the app's old role until the new one exists.
    create_before_destroy = true
    precondition {
      condition     = alltrue([for s in var.service_scopes : contains(keys(local.scope_roles), s)])
      error_message = "No admin role is recorded for some service_scopes; add them to local.scope_roles."
    }
    precondition {
      condition     = local.service_role != "SUPER_ADMIN" || var.allow_super_admin
      error_message = "service_scopes include okta.roles.read, which needs SUPER_ADMIN; set allow_super_admin = true to assign it."
    }
  }
}
