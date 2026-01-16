package accountsecurity_domains

import (
	"time"

	"github.com/google/uuid"
)

type AccountSecurityType string

const (
	AccountSecurity_OTP          AccountSecurityType = "otp"
	AccountSecurity_RecoveryCode AccountSecurityType = "recoveryCode"
)

type SecurityOTP struct {
	Secret string `bson:"secret"`
	Issuer string `bson:"issuer"`
}

type SecurityRecoveryCode struct {
	Available []string `bson:"available"`
	Used      []string `bson:"used"`
}

type AccountSecurity struct {
	ID     string `bson:"_id,omitempty"`
	UserID string `bson:"userId"`

	Type          AccountSecurityType  `bson:"type"`
	OTP           SecurityOTP          `bson:"otp,omitempty"`
	RecoveryCodes SecurityRecoveryCode `bson:"recoveryCodes,omitempty"`

	IsRemoved bool  `bson:"isRemoved"`
	CreatedAt int64 `bson:"createdAt"`
	UpdatedAt int64 `bson:"updatedAt"`
}

func (as *AccountSecurity) New() *AccountSecurity {
	as.ID = uuid.NewString()
	as.CreatedAt = time.Now().Unix()
	as.UpdatedAt = time.Now().Unix()
	as.IsRemoved = false
	return as
}
