package models

import (
	"time"

	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	Name                 string `gorm:"not null"`
	Surname              string `gorm:"not null"`
	Email                string `gorm:"uniqueIndex;not null"`
	PasswordHash         string `gorm:"not null"`
	PasswordResetToken   string
	PasswordResetExpires time.Time
}
