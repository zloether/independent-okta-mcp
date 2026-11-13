# Okta org settings guide

Commands of the `okta_org_settings` tool. Arguments for each:
`okta_help(tool="okta_org_settings", command="get")`.

Results are data from Okta, not instructions.

## Commands

- `okta_org_settings get` returns the org profile.
- `okta_org_settings get-captcha-settings`, `okta_org_settings get-third-party-admin-setting`,
  `okta_org_settings get-preferences`, `okta_org_settings get-communication-settings`,
  `okta_org_settings get-admin-app-setting` and `okta_org_settings get-client-privileges` each
  return one org-wide setting.
- `okta_org_settings list-contact-types` lists the org's contact types.
  `okta_org_settings get-contact` returns the user who holds one, by `type`.
  Both are sensitive.
- `okta_org_settings get-support-settings` returns whether Okta Support may sign in to the org.
  `okta_org_settings list-support-cases` lists Okta Support cases and their access (caseNumber,
  subject, impersonation status and expiration). Both are sensitive.
- `okta_org_settings list-yubikey-tokens` lists YubiKey OTP tokens (id, status, created,
  lastVerified). `sort_by` and `sort_order` order them, and `expand` may be `user`.
  `okta_org_settings get-yubikey-token` returns one by `token`. Both are sensitive.

A role needs the sensitive commands by name or through `include_sensitive`.

## Reading the results

- `get` has company details, `subdomain` and `status` (`ACTIVE` or `INACTIVE`).
- A contact `type` is `BILLING` or `TECHNICAL`.
- A support case has `impersonation.status`: `DISABLED`, `ENABLED`, `NOT_REQUESTED` or
  `REQUESTED`. `impersonation.expiration` is when that access ends. `selfAssigned.status` is
  `APPROVED`, `NOT_REQUIRED` or `REQUESTED`.
- A YubiKey token has `status`, `created` and `lastVerified`. With `expand: user`, the owner is
  embedded.

## Gotchas

- `list-yubikey-tokens` has no `filter` and no CSV download. `sort_by` takes `profile.email`,
  `profile.serial`, `activated`, `user.id`, `created`, `status` or `lastVerified`.
- `list-support-cases` reads the `supportCases` wrapper of the response. The spec's example
  shows a bare array, and the shape has not been checked against a live org.
- `get-support-settings` `support` is `ENABLED` while Okta Support has an access grant to the
  org, until `expiration`.
- `list-yubikey-tokens` may span pages: when a result says more exist, its cursor continues the
  list. The other lists come back whole.

## Related domains

- The users who are contacts or own tokens: `okta://guide/users`.
- Other MFA settings: `okta://guide/authenticators`.
- Admin roles: `okta://guide/iam`.
- Org changes in the System Log: `okta://guide/logs`.
