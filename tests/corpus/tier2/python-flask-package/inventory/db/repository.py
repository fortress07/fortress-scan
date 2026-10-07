from .base import BaseRepository


class ItemRepository(BaseRepository):
    table = "items"

    def find_like(self, term):
        return self._where("name LIKE '%" + term + "%'")

    def find_by_id(self, item_id):
        return self._fetch("SELECT * FROM items WHERE id = %s", (item_id,))

    def find_by_sku(self, sku):
        return self._fetch("SELECT * FROM items WHERE sku = %s", (sku,))
