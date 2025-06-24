package services

import (
	"context"
	"errors"
	"time"

	"github.com/cc-andres-portillo/otp-api/db"
	"github.com/cc-andres-portillo/otp-api/models"
	"github.com/cc-andres-portillo/otp-api/utils"

	"github.com/google/uuid"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type OTPSecretData struct {
	UserID string
	Secret string
	Issuer string
}

// Funciones para acceder a las colecciones
func otpSecretsCollection() *mongo.Collection {
	return db.GetCollection("otp_secrets")
}

func profileCollection() *mongo.Collection {
	return db.GetCollection("profile")
}

// Crea o actualiza un secreto OTP con nuevos códigos de recuperación
func CreateOrUpdateOTPSecret(data OTPSecretData) ([]string, error) {
	if data.UserID == "" || data.Secret == "" || data.Issuer == "" {
		return nil, errors.New("CreateOrUpdateOTPSecret: userID, secret o issuer vacíos")
	}

	recoveryCodes := utils.GenerateRecoveryCodes(10)
	now := time.Now().Unix()
	newID := uuid.NewString()

	filter := bson.M{"userId": data.UserID, "issuer": data.Issuer}
	update := bson.M{
		"$set": bson.M{
			"secret":        data.Secret,
			"recoveryCodes": recoveryCodes,
			"updatedAt":     now,
			"isRemove":      false,
		},
		"$setOnInsert": bson.M{
			"_id":       newID,
			"userId":    data.UserID,
			"issuer":    data.Issuer,
			"createdAt": now,
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	opts := options.Update().SetUpsert(true)

	_, err := otpSecretsCollection().UpdateOne(ctx, filter, update, opts)
	return recoveryCodes, err
}

// Obtiene el secreto OTP de un usuario
func GetOTPByUserID(userID string) (models.OTPSecret, error) {
	if userID == "" {
		return models.OTPSecret{}, errors.New("GetOTPByUserID: userID no proporcionado")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var result models.OTPSecret
	err := otpSecretsCollection().FindOne(ctx, bson.M{
		"userId":   userID,
		"isRemove": false,
	}).Decode(&result)
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
	if userID == "" {
		return false, errors.New("UseRecoveryCode: userID no proporcionado")
	}
	if code == "" {
		return false, errors.New("UseRecoveryCode: código vacío")
	}

	var result models.OTPSecret
	err := otpSecretsCollection().FindOne(context.TODO(), bson.M{
		"userId":   userID,
		"isRemove": false,
	}).Decode(&result)
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
	_, err = otpSecretsCollection().UpdateOne(
		context.TODO(),
		bson.M{"userId": userID},
		bson.M{"$set": bson.M{"recoveryCodes": newCodes}},
	)
	if err != nil {
		return false, err
	}

	return true, nil
}

// Marca el registro como eliminado
func DeleteOTPByUserID(userID string) error {
	if userID == "" {
		return errors.New("DeleteOTPByUserID: userID no proporcionado")
	}

	filter := bson.M{"userId": userID}
	update := bson.M{"$set": bson.M{"isRemove": true}}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := otpSecretsCollection().UpdateOne(ctx, filter, update)
	return err
}

// Actualiza el estado de 2FA en el perfil
func Update2FAStatus(userID string, enabled bool) error {
	if userID == "" {
		return errors.New("Update2FAStatus: userID no proporcionado")
	}

	filter := bson.M{"_id": userID}
	update := bson.M{"$set": bson.M{"is2FAEnabled": enabled}}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := profileCollection().UpdateOne(ctx, filter, update)
	return err
}
