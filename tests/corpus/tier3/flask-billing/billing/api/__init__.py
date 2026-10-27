from .invoices import bp as invoices_bp


def register_blueprints(app):
    app.register_blueprint(invoices_bp, url_prefix="/invoices")
