package auth

import (
	"errors"
	"log"
)

// Err --
var (
	ErrAuthJWT          = errors.New("Authorization凭证错误")
	ErrAuthInfoNotFound = errors.New("Authorization不存在")
	ErrAuthType         = errors.New("Authorization类型错误")
)

// ConfigJWT --
type ConfigJWT struct {
	Expires int64
	Secret  string
}

// Check --
func (config ConfigJWT) Check(cmd string) bool {
	if cmd == "all" || cmd == "write" {
		if config.Expires <= 0 {
			return false
		}
	}
	if cmd == "all" || cmd == "read" {
		if config.Secret == "" {
			return false
		}
	}
	log.Println("ConfigJWT check pass")
	return true
}
