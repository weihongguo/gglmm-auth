package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
)

type reqeustKey string

const (
	// AuthInfoRequestKey 认证信息请求建
	AuthInfoRequestKey reqeustKey = "gglmm-auth-info"
)

// Info 认证信息
type Info struct {
	Type      string `json:"type"`
	ID        int64  `json:"id"`
	Nickname  string `json:"nickname"`
	AvatarURL string `json:"avatarUrl"`
}

// Authenticator 可认证类型
type Authenticator interface {
	AuthInfo() *Info
}

// GenerateToken 生成 Authorization Token
func GenerateToken(user Authenticator, expires int64, secret string) (string, *jwt.StandardClaims, error) {
	jwtClaims, err := jwtGenerateClaims(user.AuthInfo(), expires)
	if err != nil {
		return "", jwtClaims, err
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwtClaims)
	tokenString, err := token.SignedString([]byte(secret))
	if err != nil {
		return "", jwtClaims, err
	}
	return tokenString, jwtClaims, nil
}

// ParseToken 解析 Authorization Token
func ParseToken(tokenString string, secret string) (*Info, *jwt.StandardClaims, error) {
	jwtClaims, err := jwtParseClaims(tokenString, secret)
	if err != nil {
		return nil, nil, err
	}
	info := &Info{}
	err = json.Unmarshal([]byte(jwtClaims.Subject), info)
	if err != nil {
		return nil, nil, ErrAuthJWT
	}
	return info, jwtClaims, nil
}

// GetToken 从请求里取 Authorization Token
func GetToken(r *http.Request) string {
	return strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
}

// RequestWithInfo 给请求设置 Authorization
func RequestWithInfo(r *http.Request, info *Info) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), AuthInfoRequestKey, info))
}

// GetInfo 从请求取 Authorization
func GetInfo(r *http.Request) (*Info, error) {
	value := r.Context().Value(AuthInfoRequestKey)
	if value == nil {
		return nil, ErrAuthInfoNotFound
	}
	info, ok := value.(*Info)
	if !ok {
		return nil, ErrAuthInfoNotFound
	}
	return info, nil
}

// GetType 从请求取 Authorization Type
func GetType(r *http.Request) (string, error) {
	info, err := GetInfo(r)
	if err != nil {
		return "", err
	}
	return info.Type, nil
}

// GetID 从请求取 Authorization ID
func GetID(r *http.Request, checkType string) (int64, error) {
	info, err := GetInfo(r)
	if err != nil {
		return 0, err
	}
	if info.Type != checkType {
		return 0, ErrAuthType
	}
	return info.ID, nil
}

const (
	// JWTExpires JWT失效时间
	JWTExpires int64 = 24 * 60 * 60
)

func jwtGenerateClaims(subject interface{}, expires int64) (*jwt.StandardClaims, error) {
	subjectBytes, err := json.Marshal(subject)
	if err != nil {
		return nil, err
	}
	jwtClaims := &jwt.StandardClaims{}
	now := time.Now().Unix()
	jwtClaims.IssuedAt = now
	jwtClaims.NotBefore = now
	jwtClaims.ExpiresAt = now + expires
	jwtClaims.Subject = string(subjectBytes)
	return jwtClaims, nil
}

func jwtParseClaims(tokenString string, secret string) (*jwt.StandardClaims, error) {
	jwtClaims := &jwt.StandardClaims{}
	token, err := jwt.ParseWithClaims(tokenString, jwtClaims, func(token *jwt.Token) (interface{}, error) {
		return []byte(secret), nil
	})
	if err != nil {
		return nil, err
	}
	if !token.Valid {
		return nil, ErrAuthJWT
	}
	return jwtClaims, nil
}
