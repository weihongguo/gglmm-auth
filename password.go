package auth

import (
	"errors"

	"golang.org/x/crypto/bcrypt"
)

// Err
var (
	ErrPassword = errors.New("密码错误")
)

// GeneratePassword 加密密码
func GeneratePassword(password string) (string, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashedPassword), nil
}

// ComparePassword 比较加密密码和明文密码
func ComparePassword(hash string, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}
