"""Flask route modules — register without bloating app.py."""

from __future__ import annotations


def register_routes(app, *, db, auth, recommendations, servicenow, domainlens_config, scheduler_config_fn):
    """Attach modular blueprints / route handlers to the Flask app."""
    from routes import reports, system

    system.register(
        app,
        db=db,
        auth=auth,
        servicenow=servicenow,
        domainlens_config=domainlens_config,
        scheduler_config_fn=scheduler_config_fn,
    )
    reports.register(app, db=db, recommendations=recommendations)
