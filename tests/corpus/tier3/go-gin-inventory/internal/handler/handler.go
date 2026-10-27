package handler

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"github.com/acme/inventory-api/internal/service"
)

var columns = map[string]bool{"name": true, "price": true, "created_at": true}

type API struct {
	catalog *service.Catalog
}

func New(catalog *service.Catalog) *API {
	return &API{catalog: catalog}
}

func (a *API) Search(c *gin.Context) {
	rows, err := a.catalog.Search(c.Query("name")) // fsb-expect: FSB-SQL-001
	if err != nil {
		c.Status(http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	c.Status(http.StatusOK)
}

func (a *API) Sorted(c *gin.Context) {
	column := c.Query("column")
	if !columns[column] {
		c.Status(http.StatusBadRequest)
		return
	}
	rows, err := a.catalog.Sorted(column)
	if err != nil {
		c.Status(http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	c.Status(http.StatusOK)
}

func (a *API) Page(c *gin.Context) {
	limit, err := strconv.Atoi(c.Query("limit"))
	if err != nil {
		c.Status(http.StatusBadRequest)
		return
	}
	rows, err := a.catalog.Page(limit)
	if err != nil {
		c.Status(http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	c.Status(http.StatusOK)
}

func (a *API) Export(c *gin.Context) {
	if err := a.catalog.Export(c.PostForm("name")); err != nil { // fsb-expect: FSB-CMD-001
		c.Status(http.StatusInternalServerError)
		return
	}
	c.Status(http.StatusAccepted)
}
