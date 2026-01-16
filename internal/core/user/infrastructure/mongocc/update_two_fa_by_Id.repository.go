package user_mongocc

import (
	"context"

	"go.mongodb.org/mongo-driver/bson"
)

func (r *Repository) UpdateTwoFAById(ctx context.Context, userId string, active bool) error {
	_, err := r.DB.Collection(CollectionName).UpdateOne(ctx, bson.M{"_id": userId}, bson.M{"$set": bson.M{"is2FAEnabled": active}})
	if err != nil {
		return err
	}

	return nil
}
