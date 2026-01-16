package account_security_handlers

import (
	"fmt"
	"log"
	"net/http"
)

func (h *accountSecurityHandler) GenerateRecoveryCodes(w http.ResponseWriter, r *http.Request) {
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

	// Generar nuevos códigos y actualizar en DB
	codes, err := h.Application.CreateRecoveryCodes(r.Context(), user.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Error generando nuevos códigos de recuperación")
		return
	}

	// Obtener IP remota
	ip := r.RemoteAddr
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		ip = forwarded
	}

	// Log informativo
	log.Printf("Usuario %s generó nuevos códigos de recuperación desde IP %s", user.ID, ip)

	// TODO: Enviar notificación al usuario por email/sistema interno si es necesario

	writeJSON(w, http.StatusOK, map[string]any{
		"message": "Nuevos códigos de recuperación generados exitosamente",
		"codes":   codes,
	})
}
