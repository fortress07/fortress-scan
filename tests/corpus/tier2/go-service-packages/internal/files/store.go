package files

import (
	"os"
	"path/filepath"
)

type Store struct {
	root string
}

func NewStore(root string) *Store {
	return &Store{root: root}
}

func (s *Store) Read(name string) ([]byte, error) {
	return os.ReadFile(filepath.Join(s.root, name))
}
