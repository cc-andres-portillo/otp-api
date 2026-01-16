package account_security_mongocc

import (
	"context"

	"go.mongodb.org/mongo-driver/bson"
)

func (r *Repository) SetUsedRecoveryCode(ctx context.Context, userId, code string) error {
	filter := bson.M{"userId": userId}

	update := bson.M{
		"$pull": bson.M{
			"recoveryCodes.available": code,
		},
		"$push": bson.M{
			"recoveryCodes.used": code,
		},
	}

	if _, err := r.DB.Collection(CollectionName).UpdateOne(ctx, filter, update); err != nil {
		return err
	}

	return nil
}
