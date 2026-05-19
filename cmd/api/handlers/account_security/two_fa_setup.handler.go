package account_security_handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
)

type setup2FABody struct {
	Issuer string `json:"issuer"`
}

type Setup2FADTO struct {
	Secret string `json:"secret"`
	// Url     string `json:"qr"`
	QRImg []byte `json:"qr"`
}

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

	var body setup2FABody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "JSON inválido")
		return
	}

	if body.Issuer == "" {
		writeError(w, http.StatusBadRequest, "JSON issuer field is required")
		return
	}

	user, err := h.UserApplication.GetByID(r.Context(), cookie.Value)
	if err != nil {
		writeError(w, http.StatusNotFound, "Usuario no encontrado")
		return
	}

	secret, _, qrImg, err := h.Application.CreateTwoFA(r.Context(), user.ID, user.Email, body.Issuer)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Error generando clave OTP")
		return
	}

	writeJSON(w, http.StatusOK, Setup2FADTO{
		Secret: secret,
		QRImg:  qrImg,
		// Url:    url,
	})
}
