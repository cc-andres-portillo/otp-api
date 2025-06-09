package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/cc-andres-portillo/otp-api/db"
	"github.com/cc-andres-portillo/otp-api/services"
	"github.com/pquerna/otp/totp"
	"go.mongodb.org/mongo-driver/bson"
)

type SetupRequest struct {
	Email string `json:"email"`
}

type VerifyRequest struct {
	Email string `json:"email"`
	Token string `json:"token"`
}

type QRResponse struct {
	Secret string `json:"secret"`
	QR     string `json:"qr"`
}

func Setup2FAHandler(w http.ResponseWriter, r *http.Request) {
	var req SetupRequest
	json.NewDecoder(r.Body).Decode(&req)

	coll := db.GetCollection("profile")
	filter := bson.M{"email": req.Email}
	var user bson.M

	err := coll.FindOne(r.Context(), filter).Decode(&user)
	if err != nil {
		http.Error(w, "Usuario no encontrado", http.StatusNotFound)
		return
	}

	userID, ok := user["_id"].(string)
	if !ok {
		http.Error(w, "ID de usuario inválido (esperado string)", http.StatusInternalServerError)
		return
	}

	key, _ := totp.Generate(totp.GenerateOpts{
		Issuer:      "Futurapps",
		AccountName: req.Email,
	})

	err = services.CreateOrUpdateOTPSecret(userID, key.Secret())
	if err != nil {
		http.Error(w, "Error guardando el secreto", http.StatusInternalServerError)
		return
	}

	resp := QRResponse{
		Secret: key.Secret(),
		QR:     key.URL(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func Verify2FAHandler(w http.ResponseWriter, r *http.Request) {
	var req VerifyRequest
	json.NewDecoder(r.Body).Decode(&req)

	coll := db.GetCollection("profile")
	filter := bson.M{"email": req.Email, "is2FAEnabled": true}
	var user bson.M

	err := coll.FindOne(r.Context(), filter).Decode(&user)
	if err != nil {
		http.Error(w, "Usuario no encontrado", http.StatusNotFound)
		return
	}

	userID, ok := user["_id"].(string)
	if !ok {
		http.Error(w, "ID de usuario inválido (esperado string)", http.StatusInternalServerError)
		return
	}

	secret, err := services.GetOTPSecretByUserID(userID)
	if err != nil {
		http.Error(w, "2FA no configurado", http.StatusUnauthorized)
		return
	}

	if !services.ValidateOTP(secret, req.Token) {
		http.Error(w, "Token inválido", http.StatusUnauthorized)
		return
	}
	userAvaible2Fa := user["is2FAEnabled"].(bool)
	if userAvaible2Fa == true {
		w.Write([]byte("Token válido"))
		return
	}
	// Habilita 2FA en el perfil del usuario
	update := bson.M{"$set": bson.M{"is2FAEnabled": true}}
	_, err = coll.UpdateOne(r.Context(), bson.M{"_id": userID}, update)
	if err != nil {
		http.Error(w, "Error actualizando el perfil del usuario", http.StatusInternalServerError)
		return
	}

	w.Write([]byte("Token válido y 2FA habilitado"))
}
