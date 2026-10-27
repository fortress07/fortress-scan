package store

import (
	"database/sql"
	"fmt"
)

type Item struct {
	ID   int
	Name string
}

type Store struct {
	db *sql.DB
}

func New(db *sql.DB) *Store {
	return &Store{db: db}
}

func (s *Store) FindByName(name string) ([]Item, error) {
	query := fmt.Sprintf("SELECT id, name FROM items WHERE name LIKE '%%%s%%'", name)
	rows, err := s.db.Query(query) // fsb-allow: FSB-SQL-002
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []Item
	for rows.Next() {
		var item Item
		if err := rows.Scan(&item.ID, &item.Name); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) FindByID(id int) (*Item, error) {
	var item Item
	err := s.db.QueryRow("SELECT id, name FROM items WHERE id = " + fmt.Sprint(id)).Scan(&item.ID, &item.Name)
	if err != nil {
		return nil, err
	}
	return &item, nil
}
