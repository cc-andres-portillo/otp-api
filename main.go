package main

import (
	"log"
	"net/http"

	"github.com/cc-andres-portillo/otp-api/db"
	"github.com/cc-andres-portillo/otp-api/handlers"
)

func main() {
	db.ConnectMongo("mongodb://root:12345abc@localhost:27017/?directConnection=true&authMechanism=SCRAM-SHA-1&authSource=admin", "futurapps")

	http.HandleFunc("POST /2fa/setup", handlers.Setup2FAHandler)
	http.HandleFunc("POST /2fa/verify", handlers.Verify2FAHandler)
	http.HandleFunc("POST /2fa/recovery-codes", handlers.GetRecoveryCodes)
	http.HandleFunc("POST /2fa/generate-recovery-codes", handlers.FA2GenerateRecoveryCodes)
	http.HandleFunc("POST /2fa/validate-recovery-code", handlers.ValidateRecoveryCodeHandler) // NUEVO

	log.Println("API corriendo en http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
