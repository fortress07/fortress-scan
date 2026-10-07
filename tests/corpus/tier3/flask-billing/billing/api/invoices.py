from flask import Blueprint, jsonify, render_template, request

from ..services import InvoiceService
from ..tasks import export_invoice

bp = Blueprint("invoices", __name__)
service = InvoiceService()

COLUMNS = ("number", "total", "issued_at")


@bp.route("/search")
def search():
    return jsonify(service.search(request.args.get("q", "")))  # fsb-expect: FSB-SQL-001


@bp.route("/sorted")
def sorted_invoices():
    column = request.args.get("column", "number")
    if column not in COLUMNS:
        return "", 400
    return jsonify(service.sorted(column))


@bp.route("/view")
def view():
    return render_template("invoice.html", note=request.args.get("note", ""))  # fsb-expect: FSB-XSS-001


@bp.route("/view-safe")
def view_safe():
    return render_template("safe.html", note=request.args.get("note", ""))


@bp.route("/download")
def download():
    return service.read(request.args.get("name", ""))  # fsb-expect: FSB-PATH-001


@bp.route("/export", methods=["POST"])
def export():
    export_invoice.delay(request.form["number"])
    return "", 202


@bp.route("/<int:invoice_id>")
def get_invoice(invoice_id):
    return jsonify(service.by_id(invoice_id))
