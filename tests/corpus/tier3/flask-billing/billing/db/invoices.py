from .base import BaseRepository


class InvoiceRepository(BaseRepository):
    def by_number(self, number):
        return self._where("number LIKE '%" + number + "%'")

    def sorted(self, column):
        return self._fetch("SELECT id, number FROM invoices ORDER BY " + column)

    def by_id(self, invoice_id):
        return self._fetch("SELECT * FROM invoices WHERE id = %s", (invoice_id,))
