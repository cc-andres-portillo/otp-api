package account_security_handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

type ValidateRequest struct {
	Code string `json:"code"`
}

func (vr *ValidateRequest) Validate() error {
	if vr.Code == "" {
		return errors.New("CODE_IS_REQUIRED")
	}

	return nil
}

func (h *accountSecurityHandler) ValidateRecoveryCode(w http.ResponseWriter, r *http.Request) {
	var req ValidateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "JSON inválido")
		return
	}
	if err := req.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	cookie, err := r.Cookie("tk-session")
	if err != nil {
		if err == http.ErrNoCookie {
			fmt.Fprintln(w, "No se encontró la cookie.")
		} else {
			writeError(w, http.StatusInternalServerError, err.Error())
		}
		return
	}

	user, err := h.UserApplication.GetByID(r.Context(), cookie.Value)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}

	if err := h.Application.UseRecoveryCode(r.Context(), user.ID, req.Code); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "Código de recuperación válido"})
}
