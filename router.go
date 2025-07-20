package main

import (
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

func setupRouter(db *gorm.DB) *gin.Engine {
	r := gin.Default()

	r.POST("/register", registerHandler(db))
	r.POST("/login", loginHandler(db))

	auth := r.Group("/")
	auth.Use(authMiddleware())
	auth.GET("/protected", protectedHandler())

	return r
}
