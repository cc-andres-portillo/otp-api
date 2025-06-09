package models

// OTPSecret representa el secreto de 2FA asociado a un usuario
type OTPSecret struct {
	ID        string	`bson:"_id,omitempty"`
	UserID    string 	`bson:"userId"`
	Secret    string    `bson:"secret"`
	Issuer    string    `bson:"issuer"`
	CreatedAt int64     `bson:"createdAt"`
	UpdatedAt int64     `bson:"updatedAt"`
	Recovery  []string  `bson:"recoveryCodes"`
}