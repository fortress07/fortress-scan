package main

import (
	"github.com/gin-gonic/gin"

	"github.com/acme/inventory-api/internal/handler"
	"github.com/acme/inventory-api/internal/service"
	"github.com/acme/inventory-api/internal/store"
)

func main() {
	db := store.Open("postgres://localhost/inventory")
	items := service.New(store.NewItems(db))
	api := handler.New(items)

	router := gin.Default()
	router.GET("/items", api.Search)
	router.GET("/items/sorted", api.Sorted)
	router.GET("/items/page", api.Page)
	router.POST("/items/export", api.Export)
	router.Run(":8080")
}
