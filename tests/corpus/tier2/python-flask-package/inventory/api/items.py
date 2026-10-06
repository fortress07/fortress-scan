from flask import Blueprint, jsonify, request

from ..services import ItemService
from ..util.auth import login_required

bp = Blueprint("items", __name__)
service = ItemService()


@bp.route("/search")
@login_required
def search():
    term = request.args.get("q", "")
    return jsonify(service.search(term))  # fsb-expect: FSB-SQL-001


@bp.route("/<int:item_id>")
def get_item(item_id):
    return jsonify(service.get(item_id))


@bp.route("/by-sku")
def by_sku():
    sku = request.args.get("sku", "")
    return jsonify(service.by_sku(sku))
