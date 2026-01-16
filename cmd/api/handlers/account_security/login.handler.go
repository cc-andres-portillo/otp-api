package account_security_handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

type LoginBody struct {
	Email string `json:"email"`
}

func (l *LoginBody) Validate() error {
	if l.Email == "" {
		return errors.New("EMAIL_IS_REQUIRED")
	}
	return nil
}

func (l *LoginBody) DecodeBody(body io.ReadCloser) error {
	if err := json.NewDecoder(body).Decode(l); err != nil {
		return errors.New("JSON inválido")
	}

	return nil
}

func (h *accountSecurityHandler) Login(w http.ResponseWriter, r *http.Request) {
	req := LoginBody{}

	req.DecodeBody(r.Body)

	fmt.Println(req)

	// var req LoginBody
	// if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
	// 	writeError(w, http.StatusBadRequest, "JSON inválido")
	// 	return
	// }
	if err := req.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	user, err := h.UserApplication.GetByEmail(r.Context(), req.Email)
	if err != nil {
		writeError(w, http.StatusNotFound, "Usuario no encontrado")
		return
	}

	cookie := http.Cookie{
		Name:     "tk-session",
		Value:    user.ID,
		Path:     "/",                            // Ruta donde la cookie es válida
		Expires:  time.Now().Add(24 * time.Hour), // Caduca en 24 horas
		HttpOnly: true,                           // Protege contra ataques XSS
		Secure:   false,                          // Usar true si es HTTPS
		SameSite: http.SameSiteNoneMode,          // Modo SameSite
	}

	http.SetCookie(w, &cookie)

	writeJSON(w, http.StatusOK, "OK")
}
