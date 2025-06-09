package models

// OTPSecret representa el secreto de 2FA asociado a un usuario
type OTPSecret struct {
	ID        string	`bson:"_id,omitempty"`
	UserID    string 	`bson:"userId"`
	Secret    string    `bson:"secret"`
	CreatedAt int64     `bson:"createdAt"`
	UpdatedAt int64     `bson:"updatedAt"`
}