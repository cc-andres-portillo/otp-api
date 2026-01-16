package account_security_handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
)

func (h *accountSecurityHandler) Setup2FA(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("tk-session")
	if err != nil {
		if err == http.ErrNoCookie {
			fmt.Fprintln(w, "No se encontró la cookie.")
		} else {
			writeError(w, http.StatusInternalServerError, err.Error())
		}
		return
	}

	var req struct {
		Issuer string `json:"issuer"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "JSON inválido")
		return
	}

	if req.Issuer == "" {
		writeError(w, http.StatusBadRequest, "JSON issuer field is required")
		return
	}

	user, err := h.UserApplication.GetByID(r.Context(), cookie.Value)
	if err != nil {
		writeError(w, http.StatusNotFound, "Usuario no encontrado")
		return
	}

	secret, _, qrImg, err := h.Application.CreateTwoFA(r.Context(), user.ID, user.Email, req.Issuer)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Error generando clave OTP")
		return
	}

	writeJSON(w, http.StatusOK, struct {
		Secret string `json:"secret"`
		// QR     string `json:"qr"`
		QRImg []byte `json:"qr"`
	}{
		Secret: secret,
		QRImg:  qrImg,
	})
}
