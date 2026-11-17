output "server_env" {
  description = "Environment for the independent-okta-mcp server (plus OKTA_PRIVATE_KEY_FILE, which Terraform never sees)."
  value = {
    MCP_PUBLIC_URL         = var.mcp_public_url
    OKTA_ORG_URL           = var.okta_org_url
    MCP_ALLOWED_CLIENT_IDS = join(",", [for app in okta_app_oauth.client : app.client_id])
    MCP_ISSUER             = okta_auth_server.mcp.issuer
    OKTA_CLIENT_ID         = okta_app_oauth.service.client_id
    OKTA_KEY_ID            = local.kid
    OKTA_SCOPES            = join(" ", sort(var.service_scopes))
  }
}

output "group_ids" {
  description = "Role group name → ID, for policy.yaml."
  value       = { for name, g in okta_group.role : name => g.id }
}
