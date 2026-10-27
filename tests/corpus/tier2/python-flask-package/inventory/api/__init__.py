from .items import bp as items_bp
from .reports import bp as reports_bp


def register_blueprints(app):
    app.register_blueprint(items_bp, url_prefix="/items")
    app.register_blueprint(reports_bp, url_prefix="/reports")
