"""Register all HTTP route modules on the Flask app."""


def register_all(app):
    from routes import admin, api, auth, eso, project_io, project_tokens, projects, secrets, teams

    auth.register(app)
    teams.register(app)
    projects.register(app)
    secrets.register(app)
    project_io.register(app)
    project_tokens.register(app)
    admin.register(app)
    api.register(app)
    eso.register(app)
