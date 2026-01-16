package account_security_handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

type VerifyRequest struct {
	Token string `json:"token"`
}

func (vr *VerifyRequest) Validate() error {
	if vr.Token == "" {
		return errors.New("Email o username y token son requeridos")
	}

	return nil
}

func (h *accountSecurityHandler) ActivateTwoFA(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("tk-session")
	if err != nil {
		if err == http.ErrNoCookie {
			fmt.Fprintln(w, "No se encontró la cookie.")
		} else {
			writeError(w, http.StatusInternalServerError, err.Error())
		}
		return
	}

	var req VerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "JSON inválido")
		return
	}

	if err := req.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	user, err := h.UserApplication.GetByID(r.Context(), cookie.Value)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}

	if user.Is2FAEnabled {
		writeError(w, http.StatusBadRequest, "TWO_FA_IS_ENABLE")
		return
	}

	_, err = h.Application.VerifyTwoFAByToken(r.Context(), user.ID, req.Token)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}

	// Activar 2FA en el perfil
	if err := h.UserApplication.SetTwoFAById(r.Context(), user.ID, true); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "Token válido y 2FA habilitado"})
}
