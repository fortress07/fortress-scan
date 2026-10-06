package service

import (
	"fmt"

	"github.com/acme/inventory/internal/runner"
	"github.com/acme/inventory/internal/store"
)

type Items interface {
	Search(name string) ([]store.Item, error)
	Get(id int) (*store.Item, error)
	Export(category string) error
}

type ItemService struct {
	repo   *store.Store
	runner runner.Runner
}

func NewItemService(repo *store.Store, r runner.Runner) *ItemService {
	return &ItemService{repo: repo, runner: r}
}

func (s *ItemService) Search(name string) ([]store.Item, error) {
	return s.repo.FindByName(name)
}

func (s *ItemService) Get(id int) (*store.Item, error) {
	return s.repo.FindByID(id)
}

func (s *ItemService) Export(category string) error {
	return s.runner.Run(fmt.Sprintf("pg_dump inventory --table=items_%s -f /var/exports/items.sql", category))
}
