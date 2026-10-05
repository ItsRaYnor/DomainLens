# Usage guide

## Ad-hoc scan

1. Open the web UI (`http://127.0.0.1:5000` or Docker port `5050`).
2. Enter a domain (e.g. `example.com`).
3. Select checks, or leave **All Checks** enabled.
4. Click **Scan**.
5. Review tabs: **Advies** (fix + retest steps), DNS, E-mail, SSL/TLS, Web, Network, OSINT.

### API scan

```bash
curl -s -X POST http://127.0.0.1:5000/api/scan \
  -H 'Content-Type: application/json' \
  -d '{"domain":"example.com","checks":["dns","tls_deep","ncsc_tls","http_headers"]}'
```

Available checks: `whois`, `dns`, `dnssec`, `spf`, `dmarc`, `dkim`, `mta_sts`, `tlsrpt`, `ssl`, `tls_deep`, `ncsc_tls`, `http_headers`, `https_redirect`, `http_deep`, `ipv6`, `blacklist`, `ports`, `osint`, `hubspot_cf`, `weak_auth`, `all`.

### Printable report

After a saved scan: **Report** button or `GET /report/<scan_id>`.

---

## Advies (remediation)

The **Advies** tab lists every finding with:

- **Probleem** — what is wrong
- **Advies (oplossen)** — how to fix it
- **Hertesten** — how to verify (re-scan in DomainLens, internet.nl, dig, curl, …)

Prioritized items (critical / high / medium) appear at the top.

### Web security & CSP

The **HTTP Headers** check now also analyses:

- **CSP quality** — `'unsafe-inline'` / `'unsafe-eval'`, wildcards, missing `frame-ancestors` / `base-uri` / `form-action`
- **Cookies** — missing `Secure` / `HttpOnly` / `SameSite` on session-like cookies
- **CORS** — `Access-Control-Allow-Origin: *` (especially with credentials)
- **Clickjacking** — no CSP `frame-ancestors` and no `X-Frame-Options`
- **Info disclosure** — versioned `Server` / `X-Powered-By`

When CSP is missing or weak, Advies includes **step-by-step build guidance**: start with Report-Only, baseline `default-src 'self'`, add hosts, prefer nonces/hashes, then enforce.

---

## DNS monitoring & scheduling

### Create a monitor (UI)

1. Open **Monitors** drawer.
2. Enter domain, target, record type, schedule (minutes), and checks.
3. Save — first scan runs when due (immediately if enabled).

### Create via API

```bash
curl -s -X POST http://127.0.0.1:5000/api/monitors \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "example.com",
    "domain": "example.com",
    "target": "example.com",
    "record_type": "A",
    "schedule_minutes": 1440,
    "checks": ["all"]
  }'
```

### Scheduler

- Background thread polls every `scheduler.poll_seconds` (default 60s).
- Due monitors run with configurable **concurrency** (default 2).
- Manual batch: **Run due** in UI or `POST /api/monitors/run-due`.
- Status: `GET /health` or `GET /api/reporting/scheduler`.

### Zone / OVH import

Import many targets from a zone file or OVHcloud DNS API (see README).

### Rapid7 InsightVM / Nexpose

**Do not import a full ~1GB vulnerability dump.** Prefer API sync or a Critical/Severe-only export.

See **[INTEGRATIONS_RAPID7_SERVICENOW.md](INTEGRATIONS_RAPID7_SERVICENOW.md)** for Console/Cloud API setup and ServiceNow CMDB CI ↔ Vulnerable Item linking.

1. Settings → Rapid7 → `source_mode` = `console_api` or `cloud_api` (or upload a lean CSV).
2. Set API min severity to **high** (Critical + Severe).
3. Monitoring drawer → **Sync via InsightVM API**, or upload a filtered file.
4. Optional: enable ServiceNow CMDB bridge to match `cmdb_ci` and create `sn_vul_vulnerable_item`.
5. Set `DOMAINLENS_PUBLIC_URL` so each VI includes a link back to DomainLens Advies / retest (`/remediate/vuln/<id>`). Ownership stays in ServiceNow.
5. Scan a domain — matching hosts appear under **Rapid7** and in **Advies**.

```bash
# Lean API sync
curl -s -X POST http://127.0.0.1:5000/api/vuln-imports/sync \
  -H 'Content-Type: application/json' -d '{"push_cmdb":true}'

curl -s 'http://127.0.0.1:5000/api/vuln-findings?domain=example.com'
```

### Events & ServiceNow

Monitor scans create events: `baseline_created`, `scan_changed`, `scan_unchanged`, `scan_failed`.

Configure ServiceNow env vars to auto-create incidents for high/critical events.

---

## WHOIS and registration data

**Tools &rarr; WHOIS** looks up one domain without a scan; a subdomain is looked up at
its registered domain. The data comes from RDAP (the registry's structured record, found
through IANA) with port-43 WHOIS as a fallback. For `.nl` that shows status, registrar,
reseller, DNSSEC, name servers and dates. Holder and contacts are withheld by most
registries; the page says so and links to the registry's own lookup (SIDN for `.nl`).

Some country registries offer no RDAP at all &mdash; `.be`, `.eu`, `.de`, `.at` among them. For
those the registry's own port-43 WHOIS is asked and read into the same overview (source
"WHOIS (port 43)"): registered or free, quarantine, registrar where the registry publishes one
(DENIC and nic.at do not), name servers, DNSSEC and the registration date. The domain
portfolio and the batch lookup use the same fallback, so domains there are measured instead
of staying "not measured". `.be`, `.de`, `.eu` and `.at` publish no expiry date; that shows
as "Not published", as for `.nl`.

**Batch lookup** on the same page takes a pasted list or a CSV/text file (every cell that
is a domain name, at most 500) and runs in the background. It is paced so no registry
blocks this server: one request per two seconds per registry, a `429` honoured for as long
as the registry asks, and no port-43 retry against a registry that is throttling. Each
domain ends as *registered*, *not registered* or *not measured* (with the reason); the
result downloads as CSV. Starting a batch needs the Analyst role and is audited.

API: `GET /api/whois?domain=`, `POST /api/whois/batch` with `{"text": "..."}`, then
`GET /api/whois/batch/{job_id}` and `/api/whois/batch/{job_id}/csv`.

The registry status is shown in words. A `.nl` domain in SIDN's quarantine (*pending
delete*) shows when it is released: at a random moment within the hour after the published
time. SIDN shows holder and contacts only on its own website, behind bot protection; this
tool links there rather than scraping it.

### Wanted domains

Domains you want rather than hold are **portfolio domains with the decision "Request or
claim"** (see Domain portfolio below): one list, with units, contacts and the import for them
too. Add them with the import (choose "Request or claim" as the decision for new domains, or a
Decision column), from Tools &rarr; WHOIS ("Add as wanted domain"), or by setting the decision
on domains already listed. The tile and filter "Wanted" show them; the old address
`/monitoring/wanted` opens the portfolio filtered on them.

A wanted domain is looked up every six hours, hourly while it is being deleted, and every
minute from just before until an hour after a `.nl` domain's published release from
quarantine. Coming free is reported once ("can be requested now"); registered again on or
after the release day is a new holder ("if that was not you, it is taken"); registered again
before it, the old holder restored it. A failed lookup never counts as free. DomainLens is not
a registrar: register the domain yourself, or use a backorder service.

The former watchlist's entries move into the portfolio once, when this version first starts,
with their last answer, note and history; a domain already in the portfolio keeps its own
decision. The old rows stay in the database, marked as moved. `GET/POST /api/watchlist`,
`DELETE /api/watchlist/{id}` and `POST /api/watchlist/{id}/check` keep working on the wanted
domains; the ids are now portfolio ids.

## Domain portfolio

**Monitoring &rarr; Domain portfolio** keeps the domains you hold, grouped per company or
department. Paste a list (`example.nl;Sales`), or upload a CSV, text or Excel (.xlsx) file.
With a header row naming the columns (`Domain`/`Domein` and `Company`/`Bedrijf`/`Group`/
`Afdeling`), only those columns are read. A subdomain or URL is added as its registered
domain (`https://shop.example.nl/x` becomes `example.nl`; common second-level suffixes such
as `co.uk` are kept), and the import lists what it converted. A domain imported again moves
to the group named for it. Each group can name the
registrar its domains belong at (matched against the registrar and the reseller, several
names separated by commas); a domain registered elsewhere is marked **to move**.

Every domain is looked up over RDAP, paced per registry like the batch lookup: daily, every
six hours in the month before it expires, hourly while it is being deleted or when the last
lookup failed. A change of phase (quarantine, deleted, no longer registered), registrar,
reseller or name servers is recorded and sent through the notification channels, as is an
expiry within 30 and within 7 days. The first lookup of a domain is its baseline, not a
change. SIDN publishes no expiry date for `.nl` (the registrar renews until the holder
cancels), so those show "Not published"; for them quarantine is the signal that matters. A
failed lookup keeps the previous answer and says so. Lookups run with the scheduler; with
the scheduler off use "Check now".

### Decision, threat intelligence and contact

Every domain carries a **decision**, set for selected domains in the portfolio:

| Decision | Meaning | Warnings |
|---|---|---|
| Keep and renew (default) | The domain is held until someone decides otherwise | All: expiry, quarantine, registrar and name server changes, to move |
| To decide | A domain whose future is still open | As for keep: it is still yours |
| Cancel (let it lapse) | The domain is to be cancelled at the registrar | Expiry and quarantine are the plan: recorded at low severity, no expiry warnings, nothing to move. A registrar or name server change is still high: until it lapses it is yours |
| Request or claim | Not (yet) the organisation's: to request when it is free, or to claim from its holder | Coming free is the news: "can be requested now" (high) and the filter "free now". No expiry warnings, nothing to move |

With each lookup DomainLens measures whether a registered domain is **in use**: mail
(an MX other than the null MX `0 .`, or an SPF record that lets someone send; `v=spf1 -all`
means no mail) and web (an A or AAAA record on the domain or `www.`, which a parking page has
too). A domain without DNS (not registered, quarantine, not in DNS) is measurably unused; a
DNS question that got no answer leaves the use "not measured", never "no". When not one
question gets an answer, the name servers the registry delegates the domain to are asked
directly: if none of them answers, the domain is flagged **Name servers do not answer** (a red
tile and filter, and a line under its status). It resolves nowhere, and if those name servers'
own domain lapses, someone else could take over its DNS. Going silent and answering again
are each reported once for a domain you hold. If the name servers do answer, the failure was
on our side and the use simply stays "not measured". The CSV column `dns` says `ok`,
`no_answer` or nothing (not measured). The **Threat
intel** column records whether the domain is enrolled with your threat intelligence service:
a domain in use and not enrolled is flagged ("In use, no threat intel"); one that is unused,
or being cancelled or claimed, does not need it.

A **contact** belongs with a company or business unit: give a unit its contact under
**Organisation** (when adding the unit, or in "Edit, move or merge units"), and every unit and
domain below it has that contact unless it names its own, the way the expected registrar is
inherited. A domain gets its own contact with "Link contact" in its row ("From the unit" says
it has its unit's); choosing "The unit's contact" there removes the domain's own again.
Contacts are kept under "Contacts" on the Organisation page, one card per person showing the
units they are the contact for: link one more from the card, or unlink one with its &times;.
"+ Add contact" takes a name, e-mail and phone, or an account, and optionally the unit the
person is the contact for. A contact is entered by hand or made from an account (local or single sign-on): its name and e-mail address then
follow the account, as SCIM or each sign-in keeps it current. Wherever a contact is chosen,
"New contact…" adds one on the spot. When the account is removed the contact keeps the last
known name and says "Account removed". Deleting a contact leaves its units and domains
without one of their own.

Threat intelligence is switched on or off per domain with the switch in its row, or for many
at once with the buttons above the table.

The import reads these columns too when a header row names them: **Decision**/`Besluit`
(keep, to decide, cancel, request or claim, in English or Dutch, e.g. `Opzeggen`, `Behouden`),
**Contact**/`Contactpersoon`/`Owner`/`Eigenaar` (a name, an address, or `Name <address>`),
**E-mail**, and **Threat intel** (`yes`/`no`, `ja`/`nee`). A contact is found by its address,
then by its name; an address of an account makes a contact of that account; otherwise a
contact is added. An empty cell changes nothing, and a value that is not understood is listed
in the result and left as it was.

The CSV export has the columns `decision`, `threat_intel`, `mail`, `web` (`yes`, `no`, or
empty for not measured), `contact`, `contact_email` and `contact_from` (`domain` or `unit`).

Changing the portfolio needs the Analyst role and is audited. API: `GET /api/portfolio`,
`GET /api/portfolio/csv`, `POST /api/portfolio/import` (JSON `text`, or a multipart `file` .xlsx), `POST /api/portfolio/groups`,
`PUT/DELETE /api/portfolio/groups/{id}`, `POST /api/portfolio/domains` (`action`: `move`,
`remove`, `lifecycle` with `value` keep/review/cancel/claim, `threat_intel` with `value`
true/false, or `contact` with `value` a contact id or null),
`POST /api/portfolio/domains/{id}/check`, `GET/POST /api/contacts` (`{name, email, phone}` or
`{user_id}`), `PUT/DELETE /api/contacts/{id}`; a unit's contact is `contact_id` on
`POST /api/organisation/units` and `PUT /api/organisation/units/{id}` (null clears it).

## DNS propagation check

**Tools &rarr; DNS record** asks one resolver a question; the propagation panel below it
asks several the same question and compares the answers.

Tick the resolvers to compare and press **Check propagation**. The verdict is
one of three, and they are kept apart on purpose:

| Verdict | Meaning |
|---|---|
| propagated | Every resolver that answered returned the same records |
| inconsistent | They answered and the records differ &mdash; still rolling out |
| unknown | Fewer than two answered, so nothing was compared |

A resolver that times out is listed as **unreachable**, never as
disagreeing. That is our reach failing, not evidence about the zone, and
counting it as "not propagated yet" would send someone chasing a rollout that
already finished.

Record order is normalised before comparing: round-robin resolvers rotate an
RRset deliberately, and comparing raw order would report a difference on every
second lookup of a settled record.

Each row expands into **Query detail** &mdash; the answer, authority and
additional sections with TTLs, the response flags, and which address replied.
That is what tells you *why* two resolvers disagree rather than just *that*
they do.

### Custom resolvers

To compare your own recursors, add them in **Settings &rarr; Scan &rarr;
Custom resolvers**, one per line:

```
Office = 10.0.0.1, 10.0.0.2
DMZ = 192.0.2.53
```

They then appear as checkboxes alongside the built-in ones.

Addresses are configured there rather than typed on the lookup page for a
reason: DomainLens commonly runs without authentication on a LAN, and an
endpoint that accepted a resolver address would be a way to aim UDP/53 at any
host the server can reach. Only literal IP addresses are accepted, a label
cannot shadow a built-in resolver name, and a malformed line is skipped rather
than breaking the page.

## Responsible disclosure: your own security.txt and PGP key

DomainLens checks other people's `security.txt`. It can publish one of its own
too, with a contact key it generates for you.

Configure it under **Settings &rarr; Responsible disclosure**. `Contact` is the
only required field; with it set and the section enabled, the file appears at
`/.well-known/security.txt`. Both that file and the key below are reachable
without signing in, as RFC 9116 requires &mdash; a researcher who has to log in
to find out how to report a bug does not report it.

`Expires` is mandatory in RFC 9116 and is computed at request time from the
configured number of days, so the file cannot quietly go stale the way a
hand-written date does. Anything over a year is clamped to a year.

The domain check reads the key it fetches, so its fingerprint, algorithm,
identities and expiry appear straight away -- no copying into the
validator to learn the same things. That matters because "armoured"
only says the wrapper is right: an expired key passes that check and
still leaves a researcher unable to encrypt anything.

Checking any domain's published contact and key &mdash; including your own,
once you have published one &mdash; is **Tools &rarr; Responsible disclosure**.
The lookups live there too: they are tools, and the scan page no longer
carries its own copy of the DNS lookup.

**Tools &rarr; Responsible disclosure** carries four things, all of which work
on a domain that is not this one:

| Tool | What it does |
|---|---|
| Check a domain | Fetches its `security.txt` and follows `Encryption:` to the key |
| Validate a security.txt | Checks a **pasted** file against RFC 9116, before you publish it |
| Validate a PGP key | Reads a pasted armoured key: algorithm, fingerprint, identities, expiry |
| Generate a keypair | Makes a keypair and keeps **neither** half |

The validators fetch nothing and store nothing, which is what makes them
usable on a draft. A pasted key is read in a throwaway keyring with
`--import-options show-only`, so it is never imported or trusted anywhere. A
private key pasted into the validator is reported rather than refused:
someone checking "does my key work" with the wrong half needs to be told
which half they have.

The generator under Tools is for someone else's domain and keeps nothing. The
one in Settings, below, is for **this** installation and keeps the public half
so it can be published.

### Generating the key

**Settings &rarr; Responsible disclosure key &rarr; Generate keypair** creates an
OpenPGP keypair (ed25519 by default) and:

- keeps the **public** half, serving it at `/.well-known/pgp-key.asc` and
  referencing it from `security.txt` with an `Encryption:` field;
- shows you the **private** half exactly once, to download or copy.

**The private key is never stored.** It is generated in a throwaway keyring
that is deleted before the request returns, handed back in that one response,
and written to nothing &mdash; not the database, not the logs, not `/data`. It
cannot be shown again; generate a new key if you lose it.

That is a deliberate limit rather than an oversight. DomainLens commonly runs
without authentication on a LAN, and a copy of its database plus
`DOMAINLENS_SECRET_KEY` would otherwise hand someone the key that decrypts
every vulnerability report its owner ever received. Keep the private key in
your password manager or your own GnuPG keyring, and decrypt there.

Settings refuse a PGP **private** key block in any field, whichever route it
arrives by, and the key endpoint fails loudly rather than serving one.

### Passphrase on the private key

Both generators take an optional passphrase. It encrypts the private key
file, so the downloaded `.asc` is useless to anyone who cannot supply it.

It is used for that one generation and kept nowhere: not in the response
beyond a yes/no, not in settings, not in the database. Lose it and the key is
gone, because nothing here could recover it. The result says which kind of
key you got, since an unprotected private key file is usable by anyone
holding it.

### Requirements

Key generation shells out to `gpg`, which ships in the Docker image. On a
native install without GnuPG the button is disabled and says so; everything
else on the page keeps working, and you can still paste a public key you
generated elsewhere.

## Comparing two periods

**Reports &rarr; Compare** answers "what changed" for one domain between two
moments, field by field: SPF dropping from `-all` to `~all`, DMARC from
reject to none, a TLS grade slipping, a security header disappearing.

Monitoring already tells you *that* something changed. Unless the change is
one of the few it names outright, the event reads "Observed changes for
example.com" &mdash; and an SPF weakening lands exactly there, because the
record still exists and still parses. This names it instead.

Each period is represented by its **most recent** scan: "how did it look in
May" means how it was left, so a change made mid-period shows in the period
it happened. Both scans are named under the result, with their dates and ids,
so the comparison can be checked rather than taken on trust.

Two filters narrow a long result: **only what got worse**, and a single area
(SPF, DMARC, TLS, headers, and so on). They re-render what is already loaded
rather than re-running the comparison.

### From a trend line to the change behind it

The **issues** tile on Trends drills into the move rather than the standing.
A count on its own cannot tell a domain that sat at 20 issues all month from
one that went from 2 to 20, and the second is why anyone opens a rising line:

| Domain | Issues at start | Issues now | Change |
|---|---|---|---|
| spiked.example | 2 | 20 | +18 |
| steady.example | 20 | 20 | 0 |
| fixed.example | 15 | 3 | -12 |
| once.example | &mdash; | 8 | not measured |

A domain scanned once in the window is **not measured**, never `0`: one scan
has nothing to compare against, and a zero would read as "we looked and it
held steady".

Each row links to **what changed**, which opens the comparison above on
exactly those two scans and runs it &mdash; so a rising line leads to "SPF
went from -all to ~all" in two clicks.

### What counts as a change

Only fields an operator can act on. A raw diff of two scans reports something
every single time &mdash; TTLs count down, certificates lose a day of
validity, timings never repeat &mdash; and a report full of that is one
nobody opens. A certificate's expiry *date* changing is a renewal and is
reported; its days-remaining ticking down is not.

A direction is only claimed where one value is genuinely better: DMARC
policies, TLS grades and SPF qualifiers are ordered, so those moves are
labelled better or worse. Anything else is reported as changed, without a
verdict invented for it.

A check that ran in only one of the two scans is listed under **could not be
compared**, never folded into "nothing changed" &mdash; and a period with no
scan at all is refused outright, because reporting it as steady would be a
claim nobody measured.

## DANE on the mail hosts

DomainLens looked up TLSA at `_443._tcp` on the domain. That is the
deployment almost nobody has; the record that carries weight lives at
`_25._tcp` on each **mail exchanger**, which is what internet.nl scores and
what the Dutch government requires.

Each MX host is now checked separately, because partial coverage is its own
problem: a sender that reaches the one host without TLSA gets no
verification, which is the same as having none. With no explicit MX, SMTP
falls back to the domain's A/AAAA address (the RFC 5321 implicit MX), so
DomainLens checks `_25._tcp.<domain>`. Only an explicit null MX (`0 .`) is
**not applicable**, because it states that the domain receives no mail.

Mail exchangers outside the scanned domain's DNS zone (for example hosted
mail from Zoho, Microsoft or Google) are only **informational** when TLSA is
missing. The provider controls the zone where that record must be published;
the domain owner cannot add it. MX names under the scanned domain remain an
actionable finding.

## Unexpected certificates

CAA says which authorities *may* issue. It is consulted only at issuance, so
it can look perfectly correct while a certificate exists that nobody asked
for: a CA that ignored it, a record added after the fact, or a certificate
obtained through a compromised DNS account.

The scan now compares the Certificate Transparency logs (already fetched for
subdomain enumeration) against the domain's own CAA record, and reports
certificates issued in the last 30 days by an authority CAA does not permit.
Because CAA is evaluated at issuance time while DomainLens sees the current
record, this is a **medium** manual-verification finding rather than proof
that the CA issued improperly. Issuers DomainLens cannot map remain a
coverage note and are not counted as domain findings.

## Measurement status and duplicate findings

DNS absence is only reported when the resolver authoritatively measured
NXDOMAIN or NODATA. Timeouts, SERVFAIL and unavailable resolvers are
**unmeasured** and do not become missing SPF, DMARC, DKIM, CAA or TLSA
findings.

Overlapping checks are normalized before advice is shown. TLS/NCSC, CDN/CSP,
HubSpot/CSP and security-audit findings may contribute remediation context,
but the same condition is counted only once.

An issuer that cannot be mapped to a CAA identifier is reported as **not
checked**, never as a violation. The mapping is a lookup table, not a rule,
and a false alarm here is the kind that gets a check ignored. A domain with
no CAA `issue` property has made no restriction, so nothing can be
unexpected; a crt.sh outage is **unmeasured**, never a clean bill of health.

## Own infrastructure tests (open relay, open resolver)

These ask a mail server to relay and a nameserver to recurse. Against a
stranger's host that is a probe, so they are gated twice and **both** gates
must pass:

1. **Off by default.** Enabling is a settings change.
2. **An allowlist.** Only domains named under **Settings &rarr; Own
   infrastructure tests** are ever contacted. A single on/off switch would
   turn "test my infrastructure" into "test everything I happen to scan".

They are deliberately gentle: one connection, one probe, a short timeout, no
retries. The relay test disconnects **before DATA** &mdash; it never sends a
message, so a server that would have relayed is identified without anything
being relayed. The probe recipient is under `.invalid`, which RFC 2606
reserves so it can never resolve or belong to anyone.

A server that refuses to talk is not a finding: refusing is usually the
correct behaviour, and a timeout is recorded as unknown rather than clean.

## Weak authentication testing

**Legal / ethical use only** — test domains you own or have written permission to assess.

1. Enable in `config/domainlens.json`:

```json
"weak_auth": { "enabled": true }
```

2. **Verify the domain** under **Admin → Verified domains** (DNS TXT record,
   a `/.well-known/` file, or an admin attestation). Unverified domains get no
   login attempts; the check reports *not applicable*. The same applies to the
   active scan. See [ENTERPRISE.md](ENTERPRISE.md#verified-domains).
3. Customize paths and credential lists (see [CONFIGURATION.md](CONFIGURATION.md)).
4. Run check `weak_auth` (alone or with other web checks).
5. If weak credentials are found, **Advies** shows critical remediation steps.
6. After fixing passwords, re-run the scan to confirm `weak_credentials_found: false`.

---

## Organisation

**Monitoring &rarr; Organisation** arranges domains in companies and the units under them
(`Org X › Retail › Webshop`), with both kinds of monitoring per unit: security (rating of
the domains scanned in the last 90 days, open critical and high findings, monitors and their
high or critical events in the last week) and registration (domains at risk, expiring, to
move, not yet looked up). Every figure of a unit includes the units below it; scans and
monitors whose domain is in no unit are counted separately underneath.

A domain belongs to one unit, and every scan and monitor of its hostnames counts there:
`www.example.nl`, `shop.example.nl` and `example.nl` all follow the unit of `example.nl`. Put
a domain in a unit:

- in the domain portfolio, with a unit path in the import (`example.nl;Org X > Retail`, or
  `/` as separator; missing levels are created) or by moving selected domains;
- when adding a monitor (choose the unit), or later from the unit picker on the monitor;
- from a scan result ("Add to unit" under the result header).

Choosing a unit for a monitor or scan adds the registered domain to the portfolio, so it is
then also watched for quarantine and expiry. A unit may name the registrar its domains belong
at; units below inherit it unless they name their own.

**Delete** (in a unit's row, in "Edit, move or merge units", or "Delete unit…" on its page)
removes an empty unit after a confirmation. A unit that holds domains or units asks what
should happen to them: **merge** them into another unit, **move them one level up**, or
**delete the unit and everything in it** &mdash; its domains leave the portfolio and the units
below it are deleted; monitors and scans are kept and count as not in a unit. The last needs
the unit's name typed to confirm. API: `DELETE /api/organisation/units/{id}` with
`?contents=lift` (the default) or `?contents=delete`; merging is `POST .../merge`.

To move a unit with everything below it — to another company, say — choose its new place
under **Under** and save. A move onto a name that already exists at that level is refused;
use **Merge two units** instead: every domain and unit of the first goes to the second,
units of the same name on both sides are merged as well, the second keeps its expected
registrar (taking the first's only when it had none), and the first is removed. API:
`POST /api/portfolio/groups/{id}/merge` with `{"into": id}`. The Monitors page, the domain portfolio (`?group=`) and the dashboard
(`?group=`) can each be narrowed to a unit and the units below it. API: `GET /api/organisation`,
`POST /api/portfolio/assign`, `GET /api/portfolio/unit?domain=`, `POST /api/portfolio/groups`
(with `parent_id`), `PUT /api/portfolio/groups/{id}` (`name`, `parent_id`,
`expected_registrar`), and `org_unit_id` on `POST`/`PATCH /api/monitors`.

### Alerts per unit

A unit can have its own alert addresses (**Notify**, under Units and their registrar).
Alerts about its domains &mdash; registration and security &mdash; go to them by e-mail, besides
the general channels, and also to the addresses of the units above it, so a company contact
hears about its business units. Every alert names the unit, in e-mail, Slack, Teams and the
webhook payload (`unit`). Unit e-mail uses the SMTP settings and minimum severity under
Settings &rarr; Notifications; an address already on the general list is not mailed twice.

### Collapsing the tree

The Organisation table folds per unit (▸/▾) and has Expand all / Collapse all; the choice is
remembered in the browser.

### Names in the API

Units are called units everywhere now. The API takes `unit_id` (and `unit` for a path in
the import) and returns `unit` and `unit_id` per domain; the CSV column is `unit`. Units are
managed at `/api/organisation/units`. The earlier names (`group_id`, `group`,
`/api/portfolio/groups`) keep working.

### A unit's own page

Click a unit on the Organisation page for everything of that unit and the units below it:
the figures (in order, open critical and high findings, monitors, registrations at risk or
expiring), its units, its domains with both their security rating and registration status,
its monitors, the most common risks and the recent changes of both kinds. **Monitor security
of all domains** creates a security monitor (a scheduled full scan) for every domain of the
unit that has none on any of its hosts; the first scans are spread over the chosen interval
so they do not all run at once. The same action is in the domain portfolio for selected
domains (**Monitor security**), and the portfolio marks domains that are already monitored.

### Wanted domains

Domains you want rather than hold &mdash; taken, expiring or in quarantine &mdash; are portfolio
domains with the decision "Request or claim" (filter "Wanted" in the domain portfolio); the
"Add as wanted domain" button under Tools &rarr; WHOIS adds one.

### One rating

Every list uses the same A&ndash;F rating as the dashboard, worked out from the open findings:
the scan result shows it beside the title, the scan history and the start page show it per
scan, and the Monitors table per host, with the open critical and high findings and the last
change. The TLS grade is named as such in the history line and in the TLS tab.

### When nothing runs on its own

With the scheduler off, the monitoring and report pages say so under the menu, with the
reason: switched off in Settings (with a link to it), or disabled for the server by
`DOMAINLENS_DISABLE_SCHEDULER`.

### Language

The interface is complete in English and in Dutch (Settings &rarr; General &rarr; Language).
Everything the browser shows follows the choice, findings and advice included. Data that comes
from outside stays as it arrives (registry answers, response headers, cipher suite names),
and exports, e-mails and notifications are in English.

How it works: templates and scripts are written in English, and `static/js/translate.js`
applies a Dutch catalogue, keyed by the English text, to the page and to everything scripts
add to it later. The catalogue lives in `i18n/nl_ui/`: `*.tsv` sheets ("English<TAB>Dutch",
`{}` for a part filled in at run time, `{n}` for a number) built into `*.json` with
`python -m i18n.build_catalogue`, plus `*.json` files with sentences that carry markup.
`tests/test_dutch_ui.py` fails when a fixed text in a template has no Dutch, when a
translated sentence loses a link, or when a pattern would rewrite text that is already Dutch.
To find gaps on a page, open it in Dutch and run `DomainLensUntranslated()` in the browser
console.

## Management dashboard

**Reports &rarr; Dashboard** shows how all domains stand, for people who do not read scan
reports: how many are in order, the open critical and high findings, which baseline
controls are in place (DMARC enforcing, strict SPF, DNSSEC, TLS rated A or B, HSTS, HTTPS
redirect, no blocklist listing), the risks that affect the most domains, which domains need
attention first, what got better or worse, and, with a domain portfolio, registrations at
risk or expiring. Choose 30 days, 90 days or a year, and narrow it to one portfolio group;
the address keeps the choice, so a link opens the same view. **Print / PDF** prints it as a
light, two-column report.

Each domain is judged on its latest scan in the period and rated on its open findings:
A no finding of medium severity or worse, B only medium, C one or two high, D three or more
high, F any critical. This is not the stored TLS grade, which only describes TLS. Accepted
risks are not counted as open. A control that could not be measured is shown apart and
counts neither as in place nor as missing. A domain not scanned in the period is left out
and listed by name. API: `GET /api/reporting/dashboard?days=90&group={id}`.

## Trends & reporting

- **Trends** page: `/trends` — scan activity and scores from `scan_metrics`, for whoever runs the scans.
- `GET /api/reporting/overview?days=30`
- `GET /api/reporting/trends?days=30&domain=example.com`

---

## Authentication (Azure App Registration)

For Microsoft Entra ID / Azure AD:

1. Create an **App Registration** (redirect URI `https://host/auth/callback`).
2. Set `OAUTH_PROVIDER=azure`, `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`.
3. Users sign in via `/login` → **Continue with Microsoft Entra ID** (preferred OAuth).
4. Enable **SCIM** for directory provisioning (`SCIM_ENABLED=1`, OAuth token at `/oauth/token`).
5. Keep **local backup** accounts (`AUTH_LOCAL_ENABLED=1`) for Entra outages.
6. Optional legacy SAML: `SAML_ENABLED=1` + IdP SSO URL.

Details: [AZURE_APP_REGISTRATION.md](AZURE_APP_REGISTRATION.md), [SCIM_AND_SSO.md](SCIM_AND_SSO.md).

---

## Geo-blocked sites (NL/DE/BE)

Some CDN setups (e.g. BunnyCDN) return `403` outside Benelux. DomainLens marks HSTS / headers / redirects as **inconclusive**, not failed. TLS and NCSC checks still work. Re-verify HTTP findings from NL/DE/BE or [internet.nl](https://internet.nl/).

---

## internet.nl alignment

For Dutch HTTPS/TLS compliance:

- Run **NCSC TLS** + **TLS Scan** checks.
- Compare cipher suites and cipher order with internet.nl HTTPS results.
- DomainLens also probes **TLS 1.2 signature hashes** (NCSC §3.3.5 / RFC 9155): if the edge still accepts SHA-1 for key-exchange signatures, you get a `signature-hash-insufficient` finding — the same failure as internet.nl “Hashfuncties voor sleuteluitwisseling”. This is **not** the cipher-suite name ending in `-SHA`; it is OpenSSL `SignatureAlgorithms`.
- Use **Advies → Hertesten** links to re-test after changes.

### Reports & exports

- HTML report: `/report/<scan_id>` (print / Save as PDF)
- API exports: `/api/reports/<id>/export?format=json|markdown|csv`
- Scanner UI: **Export** menu (JSON / Markdown / CSV Advies)

### CDN hardening (Bunny / Cloudflare / OVHcloud)

When DomainLens detects BunnyCDN, Cloudflare, or OVHcloud, Advies includes edge-specific remediations:

| Finding | What to change |
|--------|----------------|
| SHA-1 signature hashes | Disable SHA-1/SHA-224 on the **CDN SSL profile** (and origin). Bunny: modern TLS preset + support ticket if SignatureAlgorithms is not exposed. Cloudflare: Minimum TLS 1.2+, modern cipher suites / support for sigalg profiles. OVH: Intermediate SSL Gateway profile or origin `SSLSignatureAlgorithms` / `ssl_conf_command SignatureAlgorithms`. Fix **both A and AAAA**. |
| Cipher order | Prefer AEAD (GCM/CCM/ChaCha) before CBC phase-out suites; enable server preference. |
| Geo-block + headers | Inject HSTS/CSP on **all** responses including CDN 403 pages (Bunny Edge Rules / Cloudflare Transform Rules / OVH gateway). |

Example (site behind BunnyCDN): TLS 1.2+1.3 work from any region, but HTTP may be geo-blocked (`cdn-requestcountrycode: US` → 403). internet.nl still fails SHA-1 on IPv4/IPv6 until the Bunny edge stops offering `ECDSA+SHA1` / `RSA+SHA1`.

---

## Configuration reference

See [CONFIGURATION.md](CONFIGURATION.md) for the full `domainlens.json` schema, env overrides, and bootstrap monitors.
