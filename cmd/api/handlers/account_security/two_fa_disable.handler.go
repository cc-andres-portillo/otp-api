package account_security_handlers

import (
	"fmt"
	"log"
	"net/http"
)

func (h *accountSecurityHandler) Disable2FA(w http.ResponseWriter, r *http.Request) {
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

	if !user.Is2FAEnabled {
		writeError(w, http.StatusBadRequest, "TWO_FA_IS_DISABLED")
		return
	}

	// Eliminar secreto OTP
	if err := h.Application.DeleteTwoFAByUserID(r.Context(), user.ID); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Actualizar campo is2FAEnabled a false
	if err := h.UserApplication.SetTwoFAById(r.Context(), user.ID, false); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Log de auditoría
	ip := r.RemoteAddr
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		ip = forwarded
	}
	log.Printf("Usuario %s desactivó 2FA desde IP %s", user.ID, ip)

	writeJSON(w, http.StatusOK, map[string]any{
		"message": "Autenticación en dos pasos desactivada correctamente",
	})
}
