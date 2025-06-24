package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"

	"github.com/cc-andres-portillo/otp-api/db"
	"github.com/cc-andres-portillo/otp-api/services"
	"github.com/pquerna/otp/totp"
	"go.mongodb.org/mongo-driver/bson"
)

type SetupRequest struct {
	Email    string `json:"email"`
	Username string `json:"username"`
	Issuer   string `json:"issuer"`
}

type VerifyRequest struct {
	Email    string `json:"email"`
	Username string `json:"username"`
	Token    string `json:"token"`
}

type QRResponse struct {
	Secret   string   `json:"secret"`
	QR       string   `json:"qr"`
	Recovery []string `json:"recovery"`
}

type InfoUserRequest struct {
	Email    string `json:"email"`
	Username string `json:"username"`
}

func (u InfoUserRequest) Valid() error {
	if u.Email == "" && u.Username == "" {
		return errors.New("Email o username es requerido")
	}
	return nil
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

func getUserByEmailOrUsername(ctx context.Context, email, username string) (string, bson.M, error) {
	coll := db.GetCollection("profile")

	var filter bson.M
	if email != "" {
		filter = bson.M{"email": email}
	} else if username != "" {
		filter = bson.M{"username": username}
	} else {
		return "", nil, errors.New("email o username requerido")
	}

	var user bson.M
	err := coll.FindOne(ctx, filter).Decode(&user)
	if err != nil {
		return "", nil, err
	}

	idRaw, ok := user["_id"]
	if !ok {
		return "", nil, errors.New("campo _id no encontrado en usuario")
	}

	userID, ok := idRaw.(string)
	if !ok {
		return "", nil, errors.New("campo _id no es string")
	}

	return userID, user, nil
}

func Setup2FAHandler(w http.ResponseWriter, r *http.Request) {
	var req SetupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "JSON inválido")
		return
	}
	if req.Email == "" && req.Username == "" {
		writeError(w, http.StatusBadRequest, "Email o username es requerido")
		return
	}

	userID, _, err := getUserByEmailOrUsername(r.Context(), req.Email, req.Username)
	if err != nil {
		writeError(w, http.StatusNotFound, "Usuario no encontrado")
		return
	}

	identifier := req.Email
	if identifier == "" {
		identifier = req.Username
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      req.Issuer,
		AccountName: identifier,
		Period:      30,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Error generando clave OTP")
		return
	}

	recoveryCodes, err := services.CreateOrUpdateOTPSecret(services.OTPSecretData{
		UserID: userID,
		Secret: key.Secret(),
		Issuer: req.Issuer,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Error guardando el secreto")
		return
	}

	resp := QRResponse{
		Secret:   key.Secret(),
		QR:       key.URL(),
		Recovery: recoveryCodes,
	}
	writeJSON(w, http.StatusOK, resp)
}

func Verify2FAHandler(w http.ResponseWriter, r *http.Request) {
	var req VerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "JSON inválido")
		return
	}
	if (req.Email == "" && req.Username == "") || req.Token == "" {
		writeError(w, http.StatusBadRequest, "Email o username y token son requeridos")
		return
	}

	userID, user, err := getUserByEmailOrUsername(r.Context(), req.Email, req.Username)
	if err != nil {
		writeError(w, http.StatusNotFound, "Usuario no encontrado")
		return
	}

	otp, err := services.GetOTPByUserID(userID)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "2FA no configurado")
		return
	}

	if !services.ValidateOTP(otp.Secret, req.Token) {
		writeError(w, http.StatusUnauthorized, "Token inválido")
		return
	}

	userHas2FA, ok := user["is2FAEnabled"].(bool)
	if ok && userHas2FA {
		writeJSON(w, http.StatusOK, map[string]string{"message": "Token válido"})
		return
	}

	// Activar 2FA en el perfil
	coll := db.GetCollection("profile")
	update := bson.M{"$set": bson.M{"is2FAEnabled": true}}
	_, err = coll.UpdateOne(r.Context(), bson.M{"_id": userID}, update)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Error actualizando el perfil del usuario")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "Token válido y 2FA habilitado"})
}

func ValidateRecoveryCodeHandler(w http.ResponseWriter, r *http.Request) {
	var req VerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "JSON inválido")
		return
	}
	if (req.Email == "" && req.Username == "") || req.Token == "" {
		writeError(w, http.StatusBadRequest, "Email o username y código son requeridos")
		return
	}

	userID, _, err := getUserByEmailOrUsername(r.Context(), req.Email, req.Username)
	if err != nil {
		writeError(w, http.StatusNotFound, "Usuario no encontrado")
		return
	}

	valid, err := services.UseRecoveryCode(userID, req.Token)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Error verificando código de recuperación")
		return
	}
	if !valid {
		writeError(w, http.StatusUnauthorized, "Código de recuperación inválido")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "Código de recuperación válido"})
}

func GetRecoveryCodes(w http.ResponseWriter, r *http.Request) {
	var req InfoUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "JSON inválido")
		return
	}

	if err := req.Valid(); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	userID, user, err := getUserByEmailOrUsername(r.Context(), req.Email, req.Username)
	if err != nil {
		writeError(w, http.StatusNotFound, "Usuario no encontrado")
		return
	}

	userHas2FA, ok := user["is2FAEnabled"].(bool)
	if ok && !userHas2FA {
		writeJSON(w, http.StatusOK, map[string]string{"message": "2FA disabled"})
		return
	}

	otp, err := services.GetOTPByUserID(userID)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "2FA no configurado")
		return
	}

	writeJSON(w, http.StatusOK, otp.Recovery)
}

func FA2GenerateRecoveryCodes(w http.ResponseWriter, r *http.Request) {
	var req InfoUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "JSON inválido")
		return
	}

	if err := req.Valid(); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	userID, user, err := getUserByEmailOrUsername(r.Context(), req.Email, req.Username)
	if err != nil {
		writeError(w, http.StatusNotFound, "Usuario no encontrado")
		return
	}

	userHas2FA, ok := user["is2FAEnabled"].(bool)
	if !ok || !userHas2FA {
		writeError(w, http.StatusBadRequest, "2FA no está habilitado para este usuario")
		return
	}

	// Obtener el secreto actual
	otpData, err := services.GetOTPByUserID(userID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Error obteniendo secreto 2FA")
		return
	}

	// Generar nuevos códigos y actualizar en DB
	recoveryCodes, err := services.CreateOrUpdateOTPSecret(services.OTPSecretData{
		UserID: userID,
		Secret: otpData.Secret,
		Issuer: otpData.Issuer,
	})
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
	log.Printf("Usuario %s generó nuevos códigos de recuperación desde IP %s", userID, ip)

	// TODO: Enviar notificación al usuario por email/sistema interno si es necesario

	writeJSON(w, http.StatusOK, map[string]any{
		"message":        "Nuevos códigos de recuperación generados exitosamente",
		"recovery_codes": recoveryCodes,
	})
}

func Disable2FAHandler(w http.ResponseWriter, r *http.Request) {
	var req InfoUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "JSON inválido")
		return
	}

	if err := req.Valid(); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	userID, _, err := getUserByEmailOrUsername(r.Context(), req.Email, req.Username)
	if err != nil {
		writeError(w, http.StatusNotFound, "Usuario no encontrado")
		return
	}

	// Eliminar secreto OTP
	if err := services.DeleteOTPByUserID(userID); err != nil {
		writeError(w, http.StatusInternalServerError, "Error eliminando datos OTP")
		return
	}

	// Actualizar campo is2FAEnabled a false
	if err := services.Update2FAStatus(userID, false); err != nil {
		writeError(w, http.StatusInternalServerError, "Error desactivando 2FA")
		return
	}

	// Log de auditoría
	ip := r.RemoteAddr
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		ip = forwarded
	}
	log.Printf("Usuario %s desactivó 2FA desde IP %s", userID, ip)

	writeJSON(w, http.StatusOK, map[string]any{
		"message": "Autenticación en dos pasos desactivada correctamente",
	})
}
