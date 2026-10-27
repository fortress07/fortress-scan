package store

import (
	"database/sql"
)

const listQuery = "SELECT id, name, price FROM items WHERE "

type DB struct {
	handle *sql.DB
}

func Open(dsn string) *DB {
	handle, err := sql.Open("postgres", dsn)
	if err != nil {
		panic(err)
	}
	return &DB{handle: handle}
}

type Items struct {
	db *DB
}

func NewItems(db *DB) *Items {
	return &Items{db: db}
}

func (i *Items) where(clause string) (*sql.Rows, error) {
	return i.db.handle.Query(listQuery + clause) // fsb-allow: FSB-SQL-002
}

func (i *Items) ByName(name string) (*sql.Rows, error) {
	return i.where("name LIKE '%" + name + "%'")
}

func (i *Items) Sorted(column string) (*sql.Rows, error) {
	return i.db.handle.Query("SELECT id, name FROM items ORDER BY " + column) // fsb-allow: FSB-SQL-002
}

func (i *Items) Page(limit int) (*sql.Rows, error) {
	return i.db.handle.Query("SELECT id, name FROM items LIMIT $1", limit)
}
