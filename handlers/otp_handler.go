package handlers

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/cc-andres-portillo/otp-api/db"
	"github.com/cc-andres-portillo/otp-api/services"
	"github.com/pquerna/otp/totp"
	"go.mongodb.org/mongo-driver/bson"
	"context"
)

type SetupRequest struct {
	Email string `json:"email"`
	Issuer string `json:"issuer"`
}

type VerifyRequest struct {
	Email string `json:"email"`
	Token string `json:"token"`
}

type QRResponse struct {
	Secret   string   `json:"secret"`
	QR       string   `json:"qr"`
	Recovery []string `json:"recovery"`
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

func getUserByEmail(ctx context.Context, email string) (string, bson.M, error) {
	coll := db.GetCollection("profile")
	filter := bson.M{"email": email}
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
	if req.Email == "" {
		writeError(w, http.StatusBadRequest, "Email es requerido")
		return
	}

	userID, _, err := getUserByEmail(r.Context(), req.Email)
	if err != nil {
		writeError(w, http.StatusNotFound, "Usuario no encontrado")
		return
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      req.Issuer,
		AccountName: req.Email,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Error generando clave OTP")
		return
	}
	recoveryCodes, err := services.CreateOrUpdateOTPSecret(userID, key.Secret(), req.Issuer)
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
	if req.Email == "" || req.Token == "" {
		writeError(w, http.StatusBadRequest, "Email y token son requeridos")
		return
	}

	userID, user, err := getUserByEmail(r.Context(), req.Email)
	if err != nil {
		writeError(w, http.StatusNotFound, "Usuario no encontrado")
		return
	}

	secret, err := services.GetOTPSecretByUserID(userID)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "2FA no configurado")
		return
	}

	if !services.ValidateOTP(secret, req.Token) {
		writeError(w, http.StatusUnauthorized, "Token inválido")
		return
	}

	userHas2FA, ok := user["is2FAEnabled"].(bool)
	if ok && userHas2FA {
		// Ya estaba habilitado
		writeJSON(w, http.StatusOK, map[string]string{"message": "Token válido"})
		return
	}

	// Actualizar para habilitar 2FA
	coll := db.GetCollection("profile")
	update := bson.M{"$set": bson.M{"is2FAEnabled": true}}
	_, err = coll.UpdateOne(r.Context(), bson.M{"_id": userID}, update)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Error actualizando el perfil del usuario")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "Token válido y 2FA habilitado"})
}
