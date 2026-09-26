# Upgrading to 0.1.0

0.1.0 raises the minor version because one thing needs an operator's action to
keep working. Everything else is additive.

## Action needed: verify the domains you run active tests against

If **weak-auth** or the **active scan** is enabled under Settings, both now run
only against verified domains. Until you verify yours, scans report those two
checks as *not applicable* instead of running them.

For each domain you test actively:

1. **Admin → Verified domains** → enter the domain → **Start verification**.
2. Publish the TXT record (or the `/.well-known/` file) shown there.
3. **Check now**.

An admin can **attest** a domain instead, with a reason, where neither is
possible. See [ENTERPRISE.md](ENTERPRISE.md#verified-domains).

If neither check is enabled, nothing changes for you.

## No action needed

- **Roles.** Existing `user` accounts are Analysts and keep every right they
  had, except clearing the entire history, which is now admin-only. The new
  Viewer role is only assigned when you choose to.
- **Sessions** now re-read the account on each request, so disabling or
  demoting someone takes effect immediately.
- **Audit log, API tokens, notifications, metrics, accepted risks, discovered
  hostnames**: new, off or empty until used.
- **Retention** defaults to keeping everything.
- **Database**: new tables are created on start. No existing table changes.

## Rolling back

Pin `domainlens:0.0.7`. The new tables are ignored by 0.0.7; nothing it reads
was altered.
