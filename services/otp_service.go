package services

import (
	"context"
	"time"

	"github.com/cc-andres-portillo/otp-api/db"
	"github.com/cc-andres-portillo/otp-api/models"
	"github.com/cc-andres-portillo/otp-api/utils"

	"go.mongodb.org/mongo-driver/bson"
	"github.com/pquerna/otp/totp"
	"go.mongodb.org/mongo-driver/mongo/options"
	"github.com/google/uuid"
)

func CreateOrUpdateOTPSecret(userID, secret, issuer string) ([]string, error) {
	coll := db.GetCollection("otp_secrets")
	recoveryCodes := utils.GenerateRecoveryCodes(5)

	otpSecret := models.OTPSecret{
		ID: 	  uuid.New().String(),
		UserID:   userID,
		Secret:   secret,
		Issuer:   issuer,
		Recovery: recoveryCodes,
	}

	filter := bson.M{"userID": userID}
	update := bson.M{"$set": otpSecret}
	opts := options.Update().SetUpsert(true)

	_, err := coll.UpdateOne(context.TODO(), filter, update, opts)
	if err != nil {
		return nil, err
	}

	return recoveryCodes, nil
}

func GetOTPSecretByUserID(userID string) (string, error) {
	coll := db.GetCollection("otp_secrets")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var result models.OTPSecret
	err := coll.FindOne(ctx, bson.M{"userId": userID}).Decode(&result)
	if err != nil {
		return "", err
	}
	return result.Secret, nil
}

func ValidateOTP(secret string, token string) bool {
	return totp.Validate(token, secret)
}

func UseRecoveryCode(userID, code string) (bool, error) {
	coll := db.GetCollection("otp_secrets")

	var result models.OTPSecret
	err := coll.FindOne(context.TODO(), bson.M{"userID": userID}).Decode(&result)
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
		bson.M{"userID": userID},
		bson.M{"$set": bson.M{"recoveryCodes": newCodes}},
	)
	if err != nil {
		return false, err
	}

	return true, nil
}
