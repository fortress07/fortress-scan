package main

import (
	"database/sql"
	"log"
	"net/http"

	_ "github.com/lib/pq"

	"github.com/acme/inventory/internal/api"
	"github.com/acme/inventory/internal/files"
	"github.com/acme/inventory/internal/runner"
	"github.com/acme/inventory/internal/service"
	"github.com/acme/inventory/internal/store"
)

func main() {
	db, err := sql.Open("postgres", "postgres://inventory@localhost/inventory?sslmode=disable")
	if err != nil {
		log.Fatal(err)
	}
	items := service.NewItemService(store.New(db), runner.Shell{})
	h := api.NewHandler(items, files.NewStore("/srv/attachments"))

	mux := http.NewServeMux()
	mux.HandleFunc("/items/search", h.Search)
	mux.HandleFunc("/items/get", h.Get)
	mux.HandleFunc("/items/export", h.Export)
	mux.HandleFunc("/items/attachment", h.Attachment)
	mux.HandleFunc("/items/greeting", h.Greeting)
	log.Fatal(http.ListenAndServe(":8080", api.WithRequestLog(mux)))
}
