package main

import (
	"log"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func main() {
	db, err := gorm.Open(sqlite.Open("database.db"), &gorm.Config{})
	if err != nil {
		log.Fatal("Failed to connect to database: ", err)
	}

	// AutoMigrate creates or updates tables based on the User struct
	if err := db.AutoMigrate(&User{}); err != nil {
		log.Fatal("Failed to migrate database: ", err)
	}

	r := setupRouter(db)
	log.Println("Server running at http://localhost:8080")
	r.Run(":8080")
}
