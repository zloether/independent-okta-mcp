terraform {
  required_version = ">= 1.5"

  required_providers {
    okta = {
      source  = "okta/okta"
      version = "~> 7.1"
    }
  }

  # Add a remote backend here. State holds IDs and settings, no secrets: the
  # public clients have no secret and the service app uses a public key.
}

# The org comes from var.okta_org_url, so the provider and the grants' issuer
# can't name different orgs. The token comes from OKTA_API_TOKEN (Super
# Administrator; never give it to the server).
provider "okta" {
  org_name = regex("^https://([^.]+)\\.", var.okta_org_url)[0]
  base_url = regex("^https://[^.]+\\.(.+)$", var.okta_org_url)[0]
}
