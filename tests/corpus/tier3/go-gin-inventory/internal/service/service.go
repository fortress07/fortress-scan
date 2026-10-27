package service

import (
	"database/sql"

	"github.com/acme/inventory-api/internal/shell"
	"github.com/acme/inventory-api/internal/store"
)

type Catalog struct {
	items *store.Items
}

func New(items *store.Items) *Catalog {
	return &Catalog{items: items}
}

func (c *Catalog) Search(name string) (*sql.Rows, error) {
	return c.items.ByName(name)
}

func (c *Catalog) Sorted(column string) (*sql.Rows, error) {
	return c.items.Sorted(column)
}

func (c *Catalog) Page(limit int) (*sql.Rows, error) {
	return c.items.Page(limit)
}

func (c *Catalog) Export(name string) error {
	return shell.Run("inventory-export --name " + name)
}
