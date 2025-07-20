package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// Unit test: password hashing
func TestHashAndCheckPassword(t *testing.T) {
	password := "secret123"
	hash, err := hashPassword(password)
	if err != nil {
		t.Fatalf("Failed to hash password: %v", err)
	}

	if !checkPasswordHash(password, hash) {
		t.Fatalf("Password hash does not match original password")
	}

	if checkPasswordHash("wrongpassword", hash) {
		t.Fatalf("Password hash matched wrong password")
	}
}

// Integration test: register -> login -> protected
func TestRegisterAndLogin(t *testing.T) {
	gin.SetMode(gin.TestMode)

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("Failed to open in-memory DB: %v", err)
	}
	db.AutoMigrate(&User{})

	router := setupRouter(db)

	// Register user
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/register", strings.NewReader(`{"username":"testuser","password":"secret"}`))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("Expected 201, got %d", w.Code)
	}

	// Login user
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("POST", "/login", strings.NewReader(`{"username":"testuser","password":"secret"}`))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d", w.Code)
	}

	var resp map[string]string
	json.Unmarshal(w.Body.Bytes(), &resp)
	token := resp["token"]
	if token == "" {
		t.Fatalf("Expected token in login response")
	}

	// Access protected route
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d", w.Code)
	}
}
