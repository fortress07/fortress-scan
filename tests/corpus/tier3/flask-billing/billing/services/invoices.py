import os

from .. import config
from ..db.invoices import InvoiceRepository


class InvoiceService:
    def __init__(self, repository=None):
        self.repository = repository or InvoiceRepository()
        self.root = config.INVOICE_ROOT

    def search(self, term):
        return self.repository.by_number(term.strip())

    def sorted(self, column):
        return self.repository.sorted(column)

    def by_id(self, invoice_id):
        return self.repository.by_id(int(invoice_id))

    def read(self, name):
        with open(os.path.join(self.root, name)) as handle:
            return handle.read()
