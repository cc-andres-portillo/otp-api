package main

import (
	"log"
	"net/http"

	"github.com/cc-andres-portillo/otp-api/db"
	"github.com/cc-andres-portillo/otp-api/handlers"
)

func main() {
	db.ConnectMongo()

	http.HandleFunc("/2fa/setup", handlers.Setup2FAHandler)
	http.HandleFunc("/2fa/verify", handlers.Verify2FAHandler)

	log.Println("API corriendo en http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
