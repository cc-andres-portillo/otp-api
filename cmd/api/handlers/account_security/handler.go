package account_security_handlers

import (
	"encoding/json"
	"net/http"

	account_security_ports "github.com/cc-andres-portillo/otp-api/internal/core/account_security/ports"
	user_ports "github.com/cc-andres-portillo/otp-api/internal/core/user/ports"
)

type accountSecurityHandler struct {
	Application     account_security_ports.ApplicationPort
	UserApplication user_ports.ApplicationPort
	OTPAdapter      account_security_ports.OTPAdapterPort
}

func NewAccountSecurityHandler(application account_security_ports.ApplicationPort, userApplication user_ports.ApplicationPort, otpAdapter account_security_ports.OTPAdapterPort) *accountSecurityHandler {
	return &accountSecurityHandler{
		Application:     application,
		UserApplication: userApplication,
		OTPAdapter:      otpAdapter,
	}
}

type ErrorResponse struct {
	Message string `json:"message"`
}

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, ErrorResponse{Message: msg})
}
