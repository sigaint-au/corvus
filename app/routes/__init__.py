"""Register all HTTP route modules on the Flask app."""


def register_all(app):
    """Register every route blueprint/module on the given Flask application.

    Imports route modules and calls each module's ``register(app)`` in a fixed
    order (auth, teams, projects, secrets, import_export, project_tokens, admin,
    api, eso).

    Args:
        app: The Flask application instance that will own all registered routes.

    Returns:
        None. Side effect is registering handlers and blueprints on ``app``.

    Example:
        >>> from flask import Flask
        >>> from routes import register_all
        >>> app = Flask(__name__)
        >>> register_all(app)
    """
    from routes import (
        admin,
        api,
        auth,
        eso,
        import_export,
        mgmt_api,
        project_tokens,
        projects,
        rbac,
        secrets,
        teams,
        webhooks_ui,
    )

    auth.register(app)
    teams.register(app)
    projects.register(app)
    secrets.register(app)
    import_export.register(app)
    project_tokens.register(app)
    webhooks_ui.register(app)
    rbac.register(app)
    admin.register(app)
    api.register(app)
    eso.register(app)
    mgmt_api.register(app)
