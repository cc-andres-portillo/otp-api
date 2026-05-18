package main

import (
	"log"
	"net/http"

	"github.com/cc-andres-portillo/otp-api/internal/db"

	account_security_handlers "github.com/cc-andres-portillo/otp-api/cmd/api/handlers/account_security"
	account_security_applications "github.com/cc-andres-portillo/otp-api/internal/core/account_security/application"
	account_security_mongocc "github.com/cc-andres-portillo/otp-api/internal/core/account_security/infrastructure/mongocc"

	user_applications "github.com/cc-andres-portillo/otp-api/internal/core/user/application"
	user_repositories "github.com/cc-andres-portillo/otp-api/internal/core/user/infrastructure/mongocc"

	auth_security_libs "github.com/cc-andres-portillo/otp-api/internal/core/account_security/infrastructure/lib"
)

func main() {
	db.ConnectMongo("mongodb://root:12345abc@localhost:27017/?directConnection=true&authMechanism=SCRAM-SHA-1&authSource=admin", "futurapps")

	otp_adapter := auth_security_libs.New(30)
	account_security_repository := &account_security_mongocc.Repository{DB: db.DB}
	user_repository := &user_repositories.Repository{DB: db.DB}

	account_security_application := &account_security_applications.Application{
		Repository: account_security_repository,
		OTPAdapter: otp_adapter,
	}
	user_application := &user_applications.Application{
		Repository: user_repository,
	}

	account_security_handler := account_security_handlers.NewAccountSecurityHandler(account_security_application, user_application, otp_adapter)

	http.HandleFunc("POST /login", account_security_handler.Login)
	http.HandleFunc("POST /2fa/setup", account_security_handler.Setup2FA)
	http.HandleFunc("POST /2fa/activate", account_security_handler.ActivateTwoFA)
	http.HandleFunc("POST /2fa/disable", account_security_handler.Disable2FA)
	http.HandleFunc("POST /recovery-codes/generate", account_security_handler.GenerateRecoveryCodes)
	http.HandleFunc("POST /recovery-codes/use", account_security_handler.ValidateRecoveryCode)

	log.Println("API corriendo en http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
