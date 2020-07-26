package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/weihongguo/gglmm"
	weixin "github.com/weihongguo/gglmm-weixin"
)

type reqeustKey string

const (
	authInfoRequestKey reqeustKey = "gglmm-auth-info"
)

// Info 认证信息
type Info struct {
	Type      string `json:"type"`
	ID        int64  `json:"id"`
	Nickname  string `json:"nickname"`
	AvatarURL string `json:"avatarUrl"`
}

// User --
type User interface {
	Login(request LoginRequest) (*Info, error)
	AuthInfo(request gglmm.IDRequest) (*Info, error)
}

// WeixinMiniProgramUser --
type WeixinMiniProgramUser interface {
	Login(code2SessionResponse *weixin.MiniProgramCode2SessionResponse) (*Info, error)
	AuthInfoRaw(userID int64, userInfoRequest *weixin.MiniProgramUserInfoRequest) (*Info, error)
	AuthInfoEncrypted(userID int64, userInfoRequest *weixin.MiniProgramUserInfoRequest) (*Info, error)
}

// GenerateToken 生成认证凭证
func GenerateToken(info *Info, expires int64, secret string) (string, *jwt.StandardClaims, error) {
	jwtClaims, err := jwtGenerateClaims(info, expires)
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

// ParseToken 解析认证凭证
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

// TokenFrom 从请求里取认证凭证
func TokenFrom(r *http.Request) string {
	return strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
}

// RequestWithInfo 给请求设置认证信息
func RequestWithInfo(r *http.Request, info *Info) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), authInfoRequestKey, info))
}

// InfoFrom 从请求取认证信息
func InfoFrom(r *http.Request) (*Info, error) {
	value := r.Context().Value(authInfoRequestKey)
	if value == nil {
		return nil, ErrAuthInfoNotFound
	}
	info, ok := value.(*Info)
	if !ok {
		return nil, ErrAuthInfoNotFound
	}
	return info, nil
}

// TypeFrom 从请求取认证类型
func TypeFrom(r *http.Request) (string, error) {
	info, err := InfoFrom(r)
	if err != nil {
		return "", err
	}
	return info.Type, nil
}

// IDFrom 从请求取认证ID
func IDFrom(r *http.Request, checkType string) (int64, error) {
	info, err := InfoFrom(r)
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
