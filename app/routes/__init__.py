"""Register all HTTP route modules on the Flask app."""


def register_all(app):
    from routes import admin, api, auth, eso, projects, teams

    auth.register(app)
    teams.register(app)
    projects.register(app)
    admin.register(app)
    api.register(app)
    eso.register(app)
