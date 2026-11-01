variable "okta_org_url" {
  description = "Okta org URL, e.g. https://example.okta.com (OKTA_ORG_URL), not a custom domain; the org Terraform manages and the issuer for the service app's grants."
  type        = string

  validation {
    condition     = can(regex("^https://[A-Za-z0-9-]+\\.[A-Za-z0-9.-]+$", var.okta_org_url))
    error_message = "Must be https://<org>.<domain> with no path or trailing slash."
  }
}

variable "mcp_public_url" {
  description = "Canonical external URL of the MCP endpoint (MCP_PUBLIC_URL); becomes the authorization server audience."
  type        = string

  validation {
    condition     = can(regex("^(https://[^/]+|http://(127\\.0\\.0\\.1|localhost)(:[0-9]+)?)(/.*)?$", var.mcp_public_url))
    error_message = "Must be an https URL (http only for 127.0.0.1/localhost)."
  }
}

variable "authorization_server" {
  description = "Name of the dedicated custom authorization server."
  type        = string
  default     = "okta-mcp"
}

variable "scope" {
  description = "Custom scope MCP clients request."
  type        = string
  default     = "okta-mcp"
}

variable "access_token_minutes" {
  description = "Access token lifetime for MCP clients."
  type        = number
  default     = 30

  validation {
    condition     = var.access_token_minutes >= 5 && var.access_token_minutes <= 30
    error_message = "Must be between 5 and 30 minutes."
  }
}

variable "groups" {
  description = "Role groups; their IDs go into policy.yaml."
  type        = set(string)

  validation {
    condition     = length(var.groups) > 0 && alltrue([for g in var.groups : startswith(g, "mcp-okta-") && g != "mcp-okta-"])
    error_message = "At least one group; names must start with \"mcp-okta-\"."
  }
}

variable "clients" {
  description = "One public (PKCE) OIDC app per approved MCP client, keyed by app label, with its exact redirect URIs."
  type        = map(list(string))

  validation {
    condition     = length(var.clients) > 0 && alltrue([for uris in values(var.clients) : length(uris) > 0])
    error_message = "At least one client, each with at least one redirect URI."
  }
}

variable "service_app_name" {
  description = "Label of the server's API Services app."
  type        = string
  default     = "okta-mcp service"
}

variable "service_public_jwk_file" {
  description = "Path to the service key's public JWK (JSON with kty, n, e); see docs/okta-setup.md."
  type        = string

  validation {
    condition = try(
      jsondecode(file(var.service_public_jwk_file)).kty == "RSA"
      && length(jsondecode(file(var.service_public_jwk_file)).n) >= 342
      && length(jsondecode(file(var.service_public_jwk_file)).e) > 0
      && !contains(keys(jsondecode(file(var.service_public_jwk_file))), "d"),
      false
    )
    error_message = "Must be a public RSA JWK of at least 2048 bits (no private part)."
  }
}

variable "service_scopes" {
  description = "Okta API scopes granted to the service app; the server's capability ceiling (OKTA_SCOPES)."
  type        = set(string)

  validation {
    condition     = length(var.service_scopes) > 0 && alltrue([for s in var.service_scopes : can(regex("^okta\\..+\\.read$", s))])
    error_message = "Only okta.*.read scopes are allowed."
  }
}
