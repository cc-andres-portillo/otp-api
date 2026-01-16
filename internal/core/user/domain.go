package user_domains

type User struct {
	ID           string `bson:"_id"`
	Email        string `bson:"email"`
	Is2FAEnabled bool   `bson:"is2FAEnabled"`
}
