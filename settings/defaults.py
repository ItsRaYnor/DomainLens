"""Default configuration values — single source of truth (no hardcoded scan lists in app.py)."""

DEFAULT_DKIM_SELECTORS = [
    "default", "google", "selector1", "selector2", "k1", "k2",
    "mail", "dkim", "s1", "s2", "sig1", "sm1", "sm2",
    "mandrill", "everlytickey1", "everlytickey2", "mxvault",
    # Additional ESP/provider selectors — DKIM selector names are chosen
    # per-domain and can never be fully enumerable, but these cover common
    # transactional-mail and email-hosting providers seen in the wild.
    "zmail", "resend", "brevo1", "brevo2", "whs1", "whs2", "whs3",
    "pm", "pmta", "smtpapi", "scph0223", "scph0224",
]

DEFAULT_SCAN_PORTS = {
    "21": "FTP",
    "22": "SSH",
    "25": "SMTP",
    "53": "DNS",
    "80": "HTTP",
    "110": "POP3",
    "143": "IMAP",
    "443": "HTTPS",
    "465": "SMTPS",
    "587": "Submission",
    "993": "IMAPS",
    "995": "POP3S",
    "3306": "MySQL",
    "3389": "RDP",
    "5432": "PostgreSQL",
    "8080": "HTTP-Alt",
    "8443": "HTTPS-Alt",
}

DEFAULT_SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "X-XSS-Protection",
    "Referrer-Policy",
    "Permissions-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Resource-Policy",
    "Cross-Origin-Embedder-Policy",
]

DEFAULT_MONITOR_IMPORT_TYPES = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SRV", "CAA", "PTR"]

DEFAULT_WEAK_AUTH_PATHS = ["/", "/admin", "/login", "/wp-login.php", "/manager/html", "/api/login"]

DEFAULTS = {
    "general": {
        "locale": "en",
        "app_title": "DomainLens",
        "app_subtitle": "Domain Intelligence Toolkit",
        # Absolute URL used in ServiceNow → DomainLens deep links
        "public_url": "",
    },
    "appearance": {
        # What a visitor sees before they have chosen anything themselves.
        # "auto" follows the operating system, which is the right default:
        # picking for someone is a worse guess than asking their OS.
        "theme": "auto",
        # Hue and saturation of this value drive every accent shade. Its
        # lightness is ignored — that belongs to the theme, so one colour
        # works in both.
        "accent": "#5b8def",
        # Whether a user may override the two above for themselves.
        "allow_user_override": True,
    },
    "server": {
        # Bind to localhost by default. The app ships with authentication OFF,
        # so exposing it on 0.0.0.0 would serve the admin UI and all APIs to the
        # whole network with no login. Set host explicitly (or DOMAINLENS_HOST) to
        # 0.0.0.0 ONLY after enabling authentication (see docs/CONFIGURATION.md).
        "host": "127.0.0.1",
        "port": 5000,
        "log_level": "INFO",
    },
    "database": {
        "path": "domainlens.db",
    },
    "scheduler": {
        "enabled": True,
        "poll_seconds": 60,
        "max_monitors_per_run": 200,
        "concurrency": 2,
        "failure_backoff_minutes": 15,
        "max_consecutive_failures": 8,
        "defaults": {
            "schedule_minutes": 1440,
            "checks": ["all"],
            "enabled": True,
        },
    },
    "scan": {
        "rate_limit": {"requests": 10, "window_seconds": 60},
        # A lookup is one UDP round trip, a scan is tens of seconds against
        # dozens of third parties. One shared budget made a few lookups eat
        # the scan allowance.
        "dns_lookup_rate_limit": {"requests": 60, "window_seconds": 60},
        "thread_pool_workers": 14,
        "dkim_selectors": DEFAULT_DKIM_SELECTORS,
        "ports": DEFAULT_SCAN_PORTS,
        "security_headers": DEFAULT_SECURITY_HEADERS,
        "monitor_import_types": DEFAULT_MONITOR_IMPORT_TYPES,
        "benelux_geo_allow": ["NL", "DE", "BE"],
        # "Label = 1.2.3.4, 5.6.7.8" per line. Configured here and referred
        # to by label afterwards: the DNS API runs unauthenticated on a LAN,
        # so an address must never arrive on a request.
        "custom_resolvers": [],
        # Reuse today's answer from third-party services (crt.sh, OSINT feeds)
        # instead of asking them again on every scan of the same domain.
        "external_cache": {"enabled": True, "ttl_hours": 24, "max_stale_hours": 168},
    },
    # Responsible disclosure: what /.well-known/security.txt publishes, and
    # the public half of the contact key. The private half is never stored --
    # it is handed to the operator once at generation and forgotten.
    "disclosure": {
        "enabled": False,
        "contact": "",
        "policy_url": "",
        "acknowledgments_url": "",
        "preferred_languages": "en, nl",
        "expires_days": 365,
        "canonical_url": "",
        "pgp_public_key": "",
        "pgp_fingerprint": "",
        "pgp_uid": "",
        "pgp_generated_at": "",
    },
    "reporting": {
        "retention_days": 365,
        "digest_enabled": False,
        "digest_interval_hours": 24,
    },
    "updates": {
        "check_enabled": True,
        "github_repo": "ItsRaYnor/DomainLens",
        "include_prereleases": False,
        "docker_image": "domainlens",
        "compose_file": "docker-compose.yml",
    },
    "weak_auth": {
        "enabled": False,
        "max_attempts_per_scan": 25,
        "delay_seconds": 0.35,
        "timeout_seconds": 8,
        "include_http": True,
        "paths": DEFAULT_WEAK_AUTH_PATHS,
        "usernames": ["admin", "administrator", "root", "user", "test", "guest"],
        "passwords": [
            "admin", "password", "123456", "12345678", "root", "test",
            "guest", "changeme", "welcome", "letmein", "P@ssw0rd", "qwerty",
        ],
        "credentials_file": "weak_auth_credentials.json",
        "wordlist_file": None,
        "usernames_file": None,
    },
    "active_scan": {
        # Sends live XSS/open-redirect/SQL-injection probes to the target.
        # Only enable this for domains you own or are explicitly authorized
        # to test. Off by default.
        "enabled": False,
        "max_requests_per_scan": 40,
        "max_pages_crawled": 5,
        "delay_seconds": 0.25,
        "timeout_seconds": 8,
        "include_http": True,
        "extra_params": [],
    },
    "own_infra": {
        # Open relay and open resolver tests. These ask a mail server to relay
        # and a nameserver to recurse, which against a stranger's host is a
        # probe. Off by default, and even when enabled they only run against
        # domains named in `domains` -- a global switch would turn "test my
        # infrastructure" into "test everything I happen to scan".
        "enabled": False,
        "domains": [],
    },
    "js_scan": {
        # Passive — always safe to run: fetches the homepage's JS/CSS and
        # checks for known-vulnerable library versions and leaked secrets.
        "enabled": True,
    },
    "auth_local": {
        "enabled": False,
        "require_login": True,
        "mfa_enabled": True,
        "mfa_required": False,
        "max_failed_attempts": 5,
        "lockout_minutes": 15,
        "password_min_length": 12,
        "password_require_upper": True,
        "password_require_lower": True,
        "password_require_digit": True,
        "password_require_special": True,
    },
    "auth_oauth": {
        "enabled": False,
        "require_login": True,
        "provider": "oidc",
        "tenant_id": "",
        "azure_cloud": "public",
        "scopes": "",
        "prompt": "select_account",
        "allowed_emails": [],
        "allowed_domains": [],
        "session_hours": 12,
        # True: allowlisted SSO users may sign in without a pre-provisioned DB
        # row (documented allowlist-based OAuth). Set False to require every
        # user to be provisioned first (e.g. via SCIM) — now actually enforced.
        "jit_provision": True,
    },
    "auth_saml": {
        "enabled": False,
        "entity_id": "",
        "acs_url": "",
        "idp_entity_id": "",
        "idp_sso_url": "",
        "idp_cert": "",
        # SAML assertions MUST be signed and verified against idp_cert. Unsigned
        # assertions are forgeable (anyone could log in as anyone), so this is
        # off by default and ignored when idp_cert is set.
        "allow_unsigned": False,
        "display_name": "Microsoft Entra ID (SAML legacy)",
    },
    "scim": {
        "enabled": False,
        "auth_mode": "oauth",  # oauth (preferred) | bearer (legacy) | both
        "default_role": "user",
    },
    "servicenow": {
        "enabled": False,
        "instance": "",
        "min_severity": "high",
        "category": "Network",
        "subcategory": "DNS",
        "assignment_group": "",
        "caller_id": "",
        "cmdb_enabled": False,
        "create_vulnerable_items": False,
        "update_existing_vi": True,
        "ci_table": "cmdb_ci",
        "vuln_item_table": "sn_vul_vulnerable_item",
        "vuln_table": "sn_vul_vulnerability",
        "ci_match_fields": ["name", "fqdn", "host_name", "ip_address"],
        "vi_source": "DomainLens InsightVM",
        "vi_state_open": "open",
        "domainlens_url_field": "",  # optional custom SN field e.g. u_domainlens_url
    },
    "rapid7": {
        "enabled": True,
        "include_in_scan": True,
        "min_severity_for_advies": "medium",
        "max_rows": 50000,
        "max_advies_items": 40,
        # Prefer API over 1GB full exports
        "source_mode": "file",  # file | console_api | cloud_api
        "api_base_url": "",
        "cloud_api_base_url": "https://us.api.insight.rapid7.com",
        "api_verify_ssl": True,
        "api_min_severity": "high",
        "file_min_severity": "medium",
        "site_ids": [],
        "asset_hostname_contains": "",
        "max_assets": 500,
        "max_findings_per_asset": 100,
        "page_size": 100,
        "include_solution": True,
        "include_description": False,
        "include_proof": False,
        "sync_to_servicenow_cmdb": False,
    },
    "integrations": {
        "spamhaus_dqs_configured": False,
        "abusech_configured": False,
        "otx_configured": False,
        "ovh_configured": False,
    },
    "monitors": [],
}

# Env var → (section, key path as tuple, type)
ENV_OVERRIDES = {
    "DOMAINLENS_HOST": ("server", "host", "str"),
    "DOMAINLENS_PORT": ("server", "port", "int"),
    "PORT": ("server", "port", "int"),
    "DOMAINLENS_LOG_LEVEL": ("server", "log_level", "str"),
    "DOMAINLENS_DB": ("database", "path", "str"),
    "DOMAINLENS_MONITOR_AUTORUN": ("scheduler", "enabled", "bool"),
    "DOMAINLENS_MONITOR_POLL_SECONDS": ("scheduler", "poll_seconds", "int"),
    "DOMAINLENS_RATE_LIMIT": ("scan", "rate_limit.requests", "int"),
    "DOMAINLENS_RATE_WINDOW": ("scan", "rate_limit.window_seconds", "int"),
    "DOMAINLENS_WEAK_AUTH_ENABLED": ("weak_auth", "enabled", "bool"),
    "DOMAINLENS_ACTIVE_SCAN_ENABLED": ("active_scan", "enabled", "bool"),
    "DOMAINLENS_JS_SCAN_ENABLED": ("js_scan", "enabled", "bool"),
    "AUTH_LOCAL_ENABLED": ("auth_local", "enabled", "bool"),
    "AUTH_REQUIRE_LOGIN": ("auth_local", "require_login", "bool"),
    "AUTH_MFA_ENABLED": ("auth_local", "mfa_enabled", "bool"),
    "AUTH_MFA_REQUIRED": ("auth_local", "mfa_required", "bool"),
    "AUTH_MAX_FAILED_ATTEMPTS": ("auth_local", "max_failed_attempts", "int"),
    "AUTH_LOCKOUT_MINUTES": ("auth_local", "lockout_minutes", "int"),
    "AUTH_PASSWORD_MIN_LENGTH": ("auth_local", "password_min_length", "int"),
    "OAUTH_ENABLED": ("auth_oauth", "enabled", "bool"),
    "OAUTH_REQUIRE_LOGIN": ("auth_oauth", "require_login", "bool"),
    "OAUTH_PROVIDER": ("auth_oauth", "provider", "str"),
    "AZURE_TENANT_ID": ("auth_oauth", "tenant_id", "str"),
    "OAUTH_TENANT_ID": ("auth_oauth", "tenant_id", "str"),
    "AZURE_CLOUD": ("auth_oauth", "azure_cloud", "str"),
    "AZURE_SCOPES": ("auth_oauth", "scopes", "str"),
    "AZURE_PROMPT": ("auth_oauth", "prompt", "str"),
    "SCIM_ENABLED": ("scim", "enabled", "bool"),
    "SCIM_AUTH_MODE": ("scim", "auth_mode", "str"),
    "SCIM_DEFAULT_ROLE": ("scim", "default_role", "str"),
    "SAML_ENABLED": ("auth_saml", "enabled", "bool"),
    "SAML_ENTITY_ID": ("auth_saml", "entity_id", "str"),
    "SAML_IDP_ENTITY_ID": ("auth_saml", "idp_entity_id", "str"),
    "SAML_IDP_SSO_URL": ("auth_saml", "idp_sso_url", "str"),
    "SERVICENOW_ENABLED": ("servicenow", "enabled", "bool"),
    "SERVICENOW_MIN_SEVERITY": ("servicenow", "min_severity", "str"),
    "SERVICENOW_INSTANCE": ("servicenow", "instance", "str"),
    "SERVICENOW_CMDB_ENABLED": ("servicenow", "cmdb_enabled", "bool"),
    "RAPID7_SOURCE_MODE": ("rapid7", "source_mode", "str"),
    "RAPID7_CONSOLE_URL": ("rapid7", "api_base_url", "str"),
    "RAPID7_API_MIN_SEVERITY": ("rapid7", "api_min_severity", "str"),
    "DOMAINLENS_LOCALE": ("general", "locale", "str"),
    "DOMAINLENS_PUBLIC_URL": ("general", "public_url", "str"),
    "DOMAINLENS_BASE_URL": ("general", "public_url", "str"),
}

# Secrets stay env-only; UI shows configured/masked status
SECRET_ENV_KEYS = [
    "DOMAINLENS_SECRET_KEY",
    "FLASK_SECRET_KEY",
    "OAUTH_CLIENT_SECRET",
    "AZURE_CLIENT_SECRET",
    "SCIM_BEARER_TOKEN",
    "SCIM_CLIENT_SECRET",
    "SERVICENOW_PASSWORD",
    "SERVICENOW_USER",
    "LOCAL_ADMIN_PASSWORD",
    "SPAMHAUS_DQS_KEY",
    "ABUSECH_AUTH_KEY",
    "OTX_API_KEY",
    "VIRUSTOTAL_API_KEY",
    "OVH_APP_KEY",
    "OVH_APP_SECRET",
    "OVH_CONSUMER_KEY",
    "RAPID7_USERNAME",
    "RAPID7_PASSWORD",
    "RAPID7_API_KEY",
]


# Optional API keys that unlock extra data sources. These are deliberately
# environment-only (never stored in the settings DB/JSON), but the admin UI
# previously gave no indication that they existed, whether they were set, or
# where to set them — the only clue was a bare "Set ABUSECH_AUTH_KEY" string
# in a scan result. This catalogue drives a read-only status panel.
OPTIONAL_INTEGRATIONS = [
    {
        "env": "SPAMHAUS_DQS_KEY",
        "name": "Spamhaus DQS",
        "enables": "Spamhaus blocklist zones in the Blacklist check",
        "without": "Spamhaus zones are skipped; the other DNSBLs still run",
        "signup": "https://portal.spamhaus.com/dqs/",
    },
    {
        "env": "ABUSECH_AUTH_KEY",
        "name": "abuse.ch (ThreatFox + URLhaus)",
        "enables": "Malware/C2 threat-feed lookups in the OSINT tab",
        "without": "ThreatFox and URLhaus are reported as not configured",
        "signup": "https://auth.abuse.ch/",
    },
    {
        "env": "OTX_API_KEY",
        "name": "AlienVault OTX",
        "enables": "OTX threat-intelligence pulses in the OSINT tab",
        "without": "OTX is reported as not configured",
        "signup": "https://otx.alienvault.com/api",
    },
    {
        "env": "VIRUSTOTAL_API_KEY",
        "name": "VirusTotal",
        "enables": "Multi-vendor domain reputation (detections + community score) in the OSINT tab",
        "without": "VirusTotal is reported as not configured and no reputation verdict is claimed",
        "signup": "https://www.virustotal.com/gui/my-apikey",
    },
]


# Higher-privilege credentials for the outbound integrations. Unlike the
# OSINT keys these grant access to other systems, so they were deliberately
# environment-only. That is not actually the safer default: a value in
# docker-compose.yml sits in plaintext in a file that tends to reach git, is
# readable to anyone with Portainer stack access, and is visible through
# `docker inspect` and /proc/<pid>/environ to every process in the container.
# Encrypted in the database with the key held in DOMAINLENS_SECRET_KEY, an
# attacker needs both the database and the environment instead of either one.
#
# An environment variable still wins and locks the field, so nothing changes
# for deployments that already set these.
MANAGED_CREDENTIALS = [
    {"env": "SERVICENOW_USER", "name": "ServiceNow user", "group": "ServiceNow",
     "note": "Account used to create and update incidents."},
    {"env": "SERVICENOW_PASSWORD", "name": "ServiceNow password", "group": "ServiceNow",
     "note": "Password for the ServiceNow account."},

    {"env": "RAPID7_USERNAME", "name": "InsightVM console user", "group": "Rapid7",
     "note": "Console (on-prem) API account."},
    {"env": "RAPID7_PASSWORD", "name": "InsightVM console password", "group": "Rapid7",
     "note": "Password for the console API account."},
    {"env": "RAPID7_API_KEY", "name": "Insight Platform API key", "group": "Rapid7",
     "note": "Cloud API key; used instead of console credentials."},

    {"env": "OAUTH_CLIENT_SECRET", "name": "OAuth client secret", "group": "OAuth / Entra ID",
     "note": "Client secret for the OAuth login application."},
    {"env": "AZURE_CLIENT_SECRET", "name": "Azure client secret", "group": "OAuth / Entra ID",
     "note": "Entra ID client secret; takes precedence over the generic OAuth one."},

    {"env": "SCIM_BEARER_TOKEN", "name": "SCIM bearer token", "group": "SCIM provisioning",
     "note": "Static bearer token for the SCIM endpoint (legacy auth mode)."},
    {"env": "SCIM_CLIENT_SECRET", "name": "SCIM client secret", "group": "SCIM provisioning",
     "note": "Client secret when SCIM uses OAuth instead of a bearer token."},
]
