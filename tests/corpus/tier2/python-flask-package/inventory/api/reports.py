import html

from flask import Blueprint, request

from ..services.reports import ReportService

bp = Blueprint("reports", __name__)
reports = ReportService("/var/reports")


@bp.route("/run", methods=["POST"])
def run():
    name = request.form["name"]
    reports.generate(name)  # fsb-expect: FSB-CMD-001
    return "", 202


@bp.route("/view")
def view():
    path = request.args.get("path", "")
    return reports.read(path)  # fsb-expect: FSB-PATH-001


@bp.route("/title")
def title():
    text = request.args.get("t", "")
    return "<h1>%s</h1>" % html.escape(text)
