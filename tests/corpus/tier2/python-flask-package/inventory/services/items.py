from ..db.repository import ItemRepository


class ItemService:
    def __init__(self, repository=None):
        self.repository = repository or ItemRepository()

    def search(self, term):
        return self.repository.find_like(term.strip())

    def get(self, item_id):
        return self.repository.find_by_id(int(item_id))

    def by_sku(self, sku):
        return self.repository.find_by_sku(sku)
