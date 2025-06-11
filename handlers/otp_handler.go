package handlers

import (
	"context"
	"encoding/json"
	"errors"
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
		// Intentar con recovery code
		ok, err := services.UseRecoveryCode(userID, req.Token)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "Error verificando código de recuperación")
			return
		}
		if !ok {
			writeError(w, http.StatusUnauthorized, "Token inválido")
			return
		}

		// Código de recuperación válido
		writeJSON(w, http.StatusOK, map[string]string{"message": "Código de recuperación válido"})
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

func GetRecoveryCodes(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string
		Email    string
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "JSON inválido")
		return
	}
	if req.Email == "" && req.Username == "" {
		writeError(w, http.StatusBadRequest, "Email o username son requeridos")
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
	writeJSON(w, http.StatusOK, struct{}{})
}
