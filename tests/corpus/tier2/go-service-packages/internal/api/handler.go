package api

import (
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"strconv"

	"github.com/acme/inventory/internal/files"
	"github.com/acme/inventory/internal/service"
)

type Handler struct {
	items service.Items
	files *files.Store
}

func NewHandler(items service.Items, store *files.Store) *Handler {
	return &Handler{items: items, files: store}
}

func (h *Handler) Search(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	rows, err := h.items.Search(name) // fsb-expect: FSB-SQL-001
	if err != nil {
		http.Error(w, "search failed", http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(rows)
}

func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.URL.Query().Get("id"))
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	item, err := h.items.Get(id)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	json.NewEncoder(w).Encode(item)
}

func (h *Handler) Export(w http.ResponseWriter, r *http.Request) {
	category := r.FormValue("category")
	if err := h.items.Export(category); err != nil { // fsb-expect: FSB-CMD-001
		http.Error(w, "export failed", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

func (h *Handler) Attachment(w http.ResponseWriter, r *http.Request) {
	data, err := h.files.Read(r.URL.Query().Get("file")) // fsb-expect: FSB-PATH-001
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(data)
}

func (h *Handler) Greeting(w http.ResponseWriter, r *http.Request) {
	who := r.URL.Query().Get("who")
	fmt.Fprintf(w, "<p>Hello, %s</p>", html.EscapeString(who))
}
