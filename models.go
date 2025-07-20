package main

type User struct {
	ID       uint   `gorm:"primaryKey" json:"-"`
	Username string `gorm:"unique" json:"username"`
	Password string `json:"password"`
}
