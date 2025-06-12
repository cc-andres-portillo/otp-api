package services

import (
	"context"
	"time"

	"github.com/cc-andres-portillo/otp-api/db"
	"github.com/cc-andres-portillo/otp-api/models"
	"github.com/cc-andres-portillo/otp-api/utils"

	"github.com/google/uuid"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type OTPSecretData struct {
	UserID string
	Secret string
	Issuer string
}

// Crea o actualiza un secreto OTP con nuevos códigos de recuperación
func CreateOrUpdateOTPSecret(data OTPSecretData) ([]string, error) {
	coll := db.GetCollection("otp_secrets")
	recoveryCodes := utils.GenerateRecoveryCodes(10)

	newID := uuid.New().String()

	filter := bson.M{"userId":  data.UserID, "issuer": data.Issuer}
	update := bson.M{
		"$set": bson.M{
			"userId":        data.UserID,
			"secret":        data.Secret,
			"issuer":        data.Issuer,
			"recoveryCodes": recoveryCodes,
		},
		"$setOnInsert": bson.M{
			"_id": newID,
		},
	}
	opts := options.Update().SetUpsert(true)

	_, err := coll.UpdateOne(context.TODO(), filter, update, opts)
	if err != nil {
		return nil, err
	}

	return recoveryCodes, nil
}

// Obtiene el secreto OTP de un usuario
func GetOTPByUserID(userID string) (models.OTPSecret, error) {
	coll := db.GetCollection("otp_secrets")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var result models.OTPSecret
	err := coll.FindOne(ctx, bson.M{"userId": userID}).Decode(&result)
	if err != nil {
		return models.OTPSecret{}, err
	}
	return result, nil
}

// Valida el token TOTP con expiración estricta
func ValidateOTP(secret, token string) bool {
	valid, err := totp.ValidateCustom(token, secret, time.Now().UTC(), totp.ValidateOpts{
		Period:    30,
		Skew:      0,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	return err == nil && valid
}

// Verifica y marca como usado un código de recuperación
func UseRecoveryCode(userID, code string) (bool, error) {
	coll := db.GetCollection("otp_secrets")

	var result models.OTPSecret
	err := coll.FindOne(context.TODO(), bson.M{"userId": userID}).Decode(&result)
	if err != nil {
		return false, err
	}

	// Buscar el código
	var newCodes []string
	found := false
	for _, c := range result.Recovery {
		if c == code {
			found = true
		} else {
			newCodes = append(newCodes, c)
		}
	}

	if !found {
		return false, nil
	}

	// Eliminar el código usado
	_, err = coll.UpdateOne(
		context.TODO(),
		bson.M{"userId": userID},
		bson.M{"$set": bson.M{"recoveryCodes": newCodes}},
	)
	if err != nil {
		return false, err
	}

	return true, nil
}
