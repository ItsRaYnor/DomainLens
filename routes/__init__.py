"""Flask route modules — register without bloating app.py."""

from __future__ import annotations


def register_routes(app, *, db, auth, recommendations, servicenow, domainlens_config, scheduler_config_fn,
                    normalize_domain, is_valid_domain):
    """Attach modular blueprints / route handlers to the Flask app."""
    from routes import audit, ownership, reports, risks, system, tokens

    system.register(
        app,
        db=db,
        auth=auth,
        servicenow=servicenow,
        domainlens_config=domainlens_config,
        scheduler_config_fn=scheduler_config_fn,
    )
    reports.register(app, db=db, recommendations=recommendations)
    audit.register(app, auth=auth)
    tokens.register(app, auth=auth, db=db)
    ownership.register(app, auth=auth, normalize_domain=normalize_domain,
                       is_valid_domain=is_valid_domain)
    risks.register(app, auth=auth, db=db, normalize_domain=normalize_domain,
                   is_valid_domain=is_valid_domain)
