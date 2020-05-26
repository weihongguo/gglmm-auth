package auth

import "errors"

var (
	// ErrAuthJWT --
	ErrAuthJWT = errors.New("Authorization凭证错误")
	// ErrAuthInfoNotFound --
	ErrAuthInfoNotFound = errors.New("Authorization不存在")
	// ErrAuthType --
	ErrAuthType = errors.New("Authorization类型错误")
)
