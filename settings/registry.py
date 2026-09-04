"""Settings registry metadata for admin UI."""

from settings.defaults import DEFAULTS

# field: type, label key (i18n), optional min/max/options
FIELD_META = {
    "appearance": {
        "theme": {"type": "select", "options": ["auto", "light", "dark"],
                  "label": "settings.appearance.theme"},
        "accent": {"type": "color", "label": "settings.appearance.accent"},
        "allow_user_override": {"type": "bool", "label": "settings.appearance.allow_user_override"},
    },
    "general": {
        "locale": {"type": "select", "options": ["en", "nl"], "label": "settings.general.locale"},
        "app_title": {"type": "text", "label": "settings.general.app_title"},
        "app_subtitle": {"type": "text", "label": "settings.general.app_subtitle"},
        "public_url": {"type": "text", "label": "settings.general.public_url"},
    },
    "scheduler": {
        "enabled": {"type": "bool", "label": "settings.scheduler.enabled"},
        "poll_seconds": {"type": "int", "min": 5, "max": 86400, "label": "settings.scheduler.poll_seconds"},
        "max_monitors_per_run": {"type": "int", "min": 1, "max": 1000, "label": "settings.scheduler.max_monitors_per_run"},
        "concurrency": {"type": "int", "min": 1, "max": 16, "label": "settings.scheduler.concurrency"},
        "failure_backoff_minutes": {"type": "int", "min": 1, "max": 1440, "label": "settings.scheduler.failure_backoff_minutes"},
        "max_consecutive_failures": {"type": "int", "min": 1, "max": 50, "label": "settings.scheduler.max_consecutive_failures"},
    },
    "scan": {
        "rate_limit.requests": {"type": "int", "min": 1, "max": 1000, "label": "settings.scan.rate_limit_requests"},
        "rate_limit.window_seconds": {"type": "int", "min": 1, "max": 3600, "label": "settings.scan.rate_limit_window"},
        "dns_lookup_rate_limit.requests": {"type": "int", "min": 1, "max": 10000, "label": "settings.scan.dns_lookup_rate_limit_requests"},
        "dns_lookup_rate_limit.window_seconds": {"type": "int", "min": 1, "max": 3600, "label": "settings.scan.dns_lookup_rate_limit_window"},
        "thread_pool_workers": {"type": "int", "min": 1, "max": 32, "label": "settings.scan.thread_pool_workers"},
        "dkim_selectors": {"type": "lines", "label": "settings.scan.dkim_selectors"},
        "ports": {"type": "json", "label": "settings.scan.ports"},
        "security_headers": {"type": "lines", "label": "settings.scan.security_headers"},
        "monitor_import_types": {"type": "lines", "label": "settings.scan.monitor_import_types"},
        "benelux_geo_allow": {"type": "lines", "label": "settings.scan.benelux_geo_allow"},
        "custom_resolvers": {"type": "lines", "label": "settings.scan.custom_resolvers"},
        "external_cache.enabled": {"type": "bool", "label": "settings.scan.external_cache_enabled"},
        "external_cache.ttl_hours": {"type": "int", "min": 1, "max": 168, "label": "settings.scan.external_cache_ttl_hours"},
        "external_cache.max_stale_hours": {"type": "int", "min": 0, "max": 2160, "label": "settings.scan.external_cache_max_stale_hours"},
    },
    # The key fields are absent on purpose: a public key is produced by
    # generation or by an explicit paste, never by free-text editing, and
    # pgp_fingerprint must keep matching the key it describes.
    "disclosure": {
        # Ordered the way the file is filled in: switch it on, give the one
        # mandatory field, then the optional extras.
        "enabled": {"type": "bool", "label": "settings.disclosure.enabled"},
        "contact": {"type": "text", "label": "settings.disclosure.contact"},
        "expires_days": {"type": "int", "min": 1, "max": 365,
                         "label": "settings.disclosure.expires_days"},
        "policy_url": {"type": "text", "label": "settings.disclosure.policy_url"},
        "acknowledgments_url": {"type": "text", "label": "settings.disclosure.acknowledgments_url"},
        "preferred_languages": {"type": "text", "label": "settings.disclosure.preferred_languages"},
        "canonical_url": {"type": "text", "label": "settings.disclosure.canonical_url"},
    },
    "own_infra": {
        "enabled": {"type": "bool", "label": "settings.own_infra.enabled"},
        "domains": {"type": "lines", "label": "settings.own_infra.domains"},
    },
    "reporting": {
        "retention_days": {"type": "int", "min": 7, "max": 3650, "label": "settings.reporting.retention_days"},
        "digest_enabled": {"type": "bool", "label": "settings.reporting.digest_enabled"},
        "digest_interval_hours": {"type": "int", "min": 1, "max": 168, "label": "settings.reporting.digest_interval_hours"},
    },
    "updates": {
        "check_enabled": {"type": "bool", "label": "settings.updates.check_enabled"},
        "github_repo": {"type": "text", "label": "settings.updates.github_repo"},
        "include_prereleases": {"type": "bool", "label": "settings.updates.include_prereleases"},
        "docker_image": {"type": "text", "label": "settings.updates.docker_image"},
        "compose_file": {"type": "text", "label": "settings.updates.compose_file"},
    },
    "weak_auth": {
        "enabled": {"type": "bool", "label": "settings.weak_auth.enabled", "warning": "settings.weak_auth.warning"},
        "max_attempts_per_scan": {"type": "int", "min": 1, "max": 200, "label": "settings.weak_auth.max_attempts"},
        "delay_seconds": {"type": "float", "min": 0, "max": 10, "label": "settings.weak_auth.delay_seconds"},
        "timeout_seconds": {"type": "int", "min": 1, "max": 60, "label": "settings.weak_auth.timeout_seconds"},
        "include_http": {"type": "bool", "label": "settings.weak_auth.include_http"},
        "paths": {"type": "lines", "label": "settings.weak_auth.paths"},
        "usernames": {"type": "lines", "label": "settings.weak_auth.usernames"},
        "passwords": {"type": "lines", "label": "settings.weak_auth.passwords"},
        "credentials_file": {"type": "text", "label": "settings.weak_auth.credentials_file"},
    },
    "active_scan": {
        "enabled": {"type": "bool", "label": "settings.active_scan.enabled", "warning": "settings.active_scan.warning"},
        "max_requests_per_scan": {"type": "int", "min": 1, "max": 500, "label": "settings.active_scan.max_requests"},
        "max_pages_crawled": {"type": "int", "min": 0, "max": 50, "label": "settings.active_scan.max_pages"},
        "delay_seconds": {"type": "float", "min": 0, "max": 10, "label": "settings.active_scan.delay_seconds"},
        "timeout_seconds": {"type": "int", "min": 1, "max": 60, "label": "settings.active_scan.timeout_seconds"},
        "include_http": {"type": "bool", "label": "settings.active_scan.include_http"},
        "extra_params": {"type": "lines", "label": "settings.active_scan.extra_params"},
    },
    "js_scan": {
        "enabled": {"type": "bool", "label": "settings.js_scan.enabled"},
    },
    "auth_local": {
        "enabled": {"type": "bool", "label": "settings.auth_local.enabled"},
        "require_login": {"type": "bool", "label": "settings.auth_local.require_login"},
        "mfa_enabled": {"type": "bool", "label": "settings.auth_local.mfa_enabled"},
        "mfa_required": {"type": "bool", "label": "settings.auth_local.mfa_required"},
        "max_failed_attempts": {"type": "int", "min": 1, "max": 50, "label": "settings.auth_local.max_failed_attempts"},
        "lockout_minutes": {"type": "int", "min": 1, "max": 1440, "label": "settings.auth_local.lockout_minutes"},
        "password_min_length": {"type": "int", "min": 8, "max": 128, "label": "settings.auth_local.password_min_length"},
        "password_require_upper": {"type": "bool", "label": "settings.auth_local.password_require_upper"},
        "password_require_lower": {"type": "bool", "label": "settings.auth_local.password_require_lower"},
        "password_require_digit": {"type": "bool", "label": "settings.auth_local.password_require_digit"},
        "password_require_special": {"type": "bool", "label": "settings.auth_local.password_require_special"},
    },
    "auth_oauth": {
        "enabled": {"type": "bool", "label": "settings.auth_oauth.enabled"},
        "require_login": {"type": "bool", "label": "settings.auth_oauth.require_login"},
        "provider": {
            "type": "select",
            "options": ["oidc", "google", "github", "microsoft", "azure"],
            "label": "settings.auth_oauth.provider",
        },
        "tenant_id": {"type": "str", "label": "settings.auth_oauth.tenant_id"},
        "azure_cloud": {
            "type": "select",
            "options": ["public", "usgov", "china", "germany"],
            "label": "settings.auth_oauth.azure_cloud",
        },
        "scopes": {"type": "str", "label": "settings.auth_oauth.scopes"},
        "prompt": {"type": "str", "label": "settings.auth_oauth.prompt"},
        "allowed_emails": {"type": "lines", "label": "settings.auth_oauth.allowed_emails"},
        "allowed_domains": {"type": "lines", "label": "settings.auth_oauth.allowed_domains"},
        "session_hours": {"type": "int", "min": 1, "max": 720, "label": "settings.auth_oauth.session_hours"},
        "jit_provision": {"type": "bool", "label": "settings.auth_oauth.jit_provision"},
    },
    "auth_saml": {
        "enabled": {"type": "bool", "label": "settings.auth_saml.enabled"},
        "entity_id": {"type": "str", "label": "settings.auth_saml.entity_id"},
        "acs_url": {"type": "str", "label": "settings.auth_saml.acs_url"},
        "idp_entity_id": {"type": "str", "label": "settings.auth_saml.idp_entity_id"},
        "idp_sso_url": {"type": "str", "label": "settings.auth_saml.idp_sso_url"},
        "allow_unsigned": {"type": "bool", "label": "settings.auth_saml.allow_unsigned"},
        "display_name": {"type": "str", "label": "settings.auth_saml.display_name"},
    },
    "scim": {
        "enabled": {"type": "bool", "label": "settings.scim.enabled"},
        "auth_mode": {
            "type": "select",
            "options": ["oauth", "bearer", "both"],
            "label": "settings.scim.auth_mode",
        },
        "default_role": {
            "type": "select",
            "options": ["user", "admin"],
            "label": "settings.scim.default_role",
        },
    },
    "servicenow": {
        "enabled": {"type": "bool", "label": "settings.servicenow.enabled"},
        "instance": {"type": "text", "label": "settings.servicenow.instance"},
        "min_severity": {"type": "select", "options": ["critical", "high", "medium", "low", "info"], "label": "settings.servicenow.min_severity"},
        "category": {"type": "text", "label": "settings.servicenow.category"},
        "subcategory": {"type": "text", "label": "settings.servicenow.subcategory"},
        "assignment_group": {"type": "text", "label": "settings.servicenow.assignment_group"},
        "caller_id": {"type": "text", "label": "settings.servicenow.caller_id"},
        "cmdb_enabled": {"type": "bool", "label": "settings.servicenow.cmdb_enabled"},
        "create_vulnerable_items": {"type": "bool", "label": "settings.servicenow.create_vulnerable_items"},
        "update_existing_vi": {"type": "bool", "label": "settings.servicenow.update_existing_vi"},
        "ci_table": {"type": "text", "label": "settings.servicenow.ci_table"},
        "vuln_item_table": {"type": "text", "label": "settings.servicenow.vuln_item_table"},
        "vuln_table": {"type": "text", "label": "settings.servicenow.vuln_table"},
        "ci_match_fields": {"type": "lines", "label": "settings.servicenow.ci_match_fields"},
        "vi_source": {"type": "text", "label": "settings.servicenow.vi_source"},
        "domainlens_url_field": {"type": "text", "label": "settings.servicenow.domainlens_url_field"},
    },
    "rapid7": {
        "enabled": {"type": "bool", "label": "settings.rapid7.enabled"},
        "include_in_scan": {"type": "bool", "label": "settings.rapid7.include_in_scan"},
        "source_mode": {
            "type": "select",
            "options": ["file", "console_api", "cloud_api"],
            "label": "settings.rapid7.source_mode",
        },
        "api_base_url": {"type": "text", "label": "settings.rapid7.api_base_url"},
        "cloud_api_base_url": {"type": "text", "label": "settings.rapid7.cloud_api_base_url"},
        "api_verify_ssl": {"type": "bool", "label": "settings.rapid7.api_verify_ssl"},
        "api_min_severity": {
            "type": "select",
            "options": ["critical", "high", "medium", "low"],
            "label": "settings.rapid7.api_min_severity",
        },
        "file_min_severity": {
            "type": "select",
            "options": ["critical", "high", "medium", "low", "info"],
            "label": "settings.rapid7.file_min_severity",
        },
        "site_ids": {"type": "lines", "label": "settings.rapid7.site_ids"},
        "asset_hostname_contains": {"type": "text", "label": "settings.rapid7.asset_hostname_contains"},
        "max_assets": {"type": "int", "min": 1, "max": 20000, "label": "settings.rapid7.max_assets"},
        "max_findings_per_asset": {"type": "int", "min": 1, "max": 5000, "label": "settings.rapid7.max_findings_per_asset"},
        "page_size": {"type": "int", "min": 10, "max": 500, "label": "settings.rapid7.page_size"},
        "include_solution": {"type": "bool", "label": "settings.rapid7.include_solution"},
        "include_description": {"type": "bool", "label": "settings.rapid7.include_description"},
        "include_proof": {"type": "bool", "label": "settings.rapid7.include_proof"},
        "sync_to_servicenow_cmdb": {"type": "bool", "label": "settings.rapid7.sync_to_servicenow_cmdb"},
        "min_severity_for_advies": {
            "type": "select",
            "options": ["critical", "high", "medium", "low", "info"],
            "label": "settings.rapid7.min_severity_for_advies",
        },
        "max_rows": {"type": "int", "min": 100, "max": 500000, "label": "settings.rapid7.max_rows"},
        "max_advies_items": {"type": "int", "min": 1, "max": 200, "label": "settings.rapid7.max_advies_items"},
    },
}

# Fourteen sections in one flat row put "Scheduler" beside "SCIM" beside
# "Rapid7" with nothing to say they are different kinds of thing. The
# categories below are ordered by how often someone opens them on purpose:
# appearance and scanning are daily, integrations are set once.
#
# ADMIN_SECTIONS stays the flat list — it is what the schema iterates and what
# the save endpoint validates against — and a test asserts the two agree, so a
# section added to one and forgotten in the other fails rather than vanishing
# from the page.
SETTING_CATEGORIES = [
    {"key": "settings.categories.appearance", "sections": ["appearance", "general"]},
    {"key": "settings.categories.scanning",
     "sections": ["scan", "weak_auth", "active_scan", "js_scan", "own_infra"]},
    {"key": "settings.categories.automation",
     "sections": ["scheduler", "reporting", "updates"]},
    {"key": "settings.categories.access",
     "sections": ["auth_local", "auth_oauth", "auth_saml", "scim"]},
    {"key": "settings.categories.integrations", "sections": ["servicenow", "rapid7"]},
    {"key": "settings.categories.disclosure", "sections": ["disclosure"]},
]

ADMIN_SECTIONS = [
    "disclosure",
    "own_infra",
    "appearance",
    "general",
    "scheduler",
    "scan",
    "reporting",
    "updates",
    "weak_auth",
    "active_scan",
    "js_scan",
    "auth_local",
    "auth_oauth",
    "auth_saml",
    "scim",
    "servicenow",
    "rapid7",
]

def section_defaults(section: str) -> dict:
    return dict(DEFAULTS.get(section) or {})
