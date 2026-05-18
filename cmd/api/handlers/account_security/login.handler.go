package account_security_handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"
)

type loginBody struct {
	Email string `json:"email"`
}

func (l loginBody) Validate() error {
	if l.Email == "" {
		return errors.New("EMAIL_IS_REQUIRED")
	}
	return nil
}

func (h *accountSecurityHandler) Login(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	var body loginBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "JSON inválido")
		return
	}

	if err := body.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	user, err := h.UserApplication.GetByEmail(r.Context(), body.Email)
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
