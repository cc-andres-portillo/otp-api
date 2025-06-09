package services

import (
	"context"
	"time"

	"github.com/cc-andres-portillo/otp-api/db"
	
	"github.com/cc-andres-portillo/otp-api/models"
	"go.mongodb.org/mongo-driver/bson"
	"github.com/pquerna/otp/totp"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func CreateOrUpdateOTPSecret(userID string, secret string) error {
	coll := db.GetCollection("otp_secrets")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	now := time.Now().Unix()

	filter := bson.M{"userId": userID}
	update := bson.M{
		"$set": bson.M{
			"secret":    secret,
			"updatedAt": now,
		},
		"$setOnInsert": bson.M{
			"userId":    userID,
			"createdAt": now,
		},
	}
	opts := options.Update().SetUpsert(true)
	_, err := coll.UpdateOne(ctx, filter, update, opts)
	return err
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