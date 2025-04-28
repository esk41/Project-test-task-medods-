package main

import (
	"github.com/esk41/Project-test-task-medods-/backend/handlers"
	"github.com/joho/godotenv"
	"log"
	"net/http"
)

func init() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}
}

func main() {
	http.HandleFunc("/auth", handlers.GenerateTokensHandler)
	http.HandleFunc("/refresh", handlers.RefreshTokensHandler)

	log.Println("Server started on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
