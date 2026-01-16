package account_security_mongocc

import (
	"context"

	accountsecurity_domains "github.com/cc-andres-portillo/otp-api/internal/core/account_security"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func (r *Repository) UpsertRecoveryCodes(ctx context.Context, userId string, codes []string) error {
	account_security := accountsecurity_domains.AccountSecurity{
		UserID: userId,
		Type:   accountsecurity_domains.AccountSecurity_RecoveryCode,
		RecoveryCodes: accountsecurity_domains.SecurityRecoveryCode{
			Available: codes,
			Used:      []string{},
		},
	}

	account_security = *account_security.New()

	filter := bson.M{"userId": userId}
	update := bson.M{
		"$set": bson.M{
			"recoveryCodes.available": codes,
			"recoveryCodes.used":      []string{},
			"updatedAt":               account_security.UpdatedAt,
		},
		"$setOnInsert": bson.M{
			"_id":       account_security.ID,
			"userId":    account_security.UserID,
			"type":      account_security.Type,
			"createdAt": account_security.CreatedAt,
			"isRemoved": account_security.IsRemoved,
		},
	}

	opts := options.Update().SetUpsert(true)

	if _, err := r.DB.Collection(CollectionName).UpdateOne(ctx, filter, update, opts); err != nil {
		return err
	}

	return nil
}
