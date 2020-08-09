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
	requestKeySecret  reqeustKey = "gglmm-auth-secret"
	requestKeySubject reqeustKey = "gglmm-auth-subject"
)

// Subject --
type Subject struct {
	Project string `json:"project"`
	Type    string `json:"type"`
	ID      uint64 `json:"id"`
}

// Info 认证信息
type Info struct {
	*Subject
	Nickname  string `json:"nickname"`
	AvatarURL string `json:"avatarUrl"`
}

// User --
type User interface {
	Login(request LoginRequest) (*Info, error)
	Info(request gglmm.IDRequest) (*Info, error)
}

// WeixinMiniProgramUser --
type WeixinMiniProgramUser interface {
	Login(code2SessionResponse *weixin.MiniProgramCode2SessionResponse) (*Info, error)
	UserInfoRaw(userID uint64, userInfoRequest *weixin.MiniProgramUserInfoRequest) (*Info, error)
	UserInfoEncrypted(userID uint64, userInfoRequest *weixin.MiniProgramUserInfoRequest) (*Info, error)
}

// GenerateToken 生成认证凭证
func GenerateToken(subject *Subject, expires int64, secret string) (string, *jwt.StandardClaims, error) {
	jwtClaims, err := jwtGenerateClaims(subject, expires)
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
func ParseToken(tokenString string, secret string) (*Subject, *jwt.StandardClaims, error) {
	jwtClaims, err := jwtParseClaims(tokenString, secret)
	if err != nil {
		return nil, nil, err
	}
	subject := &Subject{}
	err = json.Unmarshal([]byte(jwtClaims.Subject), subject)
	if err != nil {
		return nil, nil, ErrAuthJWT
	}
	return subject, jwtClaims, nil
}

// TokenFrom 从请求里取认证凭证
func TokenFrom(r *http.Request) string {
	return strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
}

// WithSecret --
func WithSecret(r *http.Request, secret string) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), requestKeySecret, secret))
}

// SecretFrom --
func SecretFrom(r *http.Request) (string, error) {
	value := r.Context().Value(requestKeySubject)
	if value == nil {
		return "", ErrAuthInfoNotFound
	}
	secret, ok := value.(string)
	if !ok {
		return "", ErrAuthInfoNotFound
	}
	return secret, nil
}

// WithSubject 给请求设置认证信息
func WithSubject(r *http.Request, subject *Subject) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), requestKeySubject, subject))
}

// SubjectFrom 从请求取认证信息
func SubjectFrom(r *http.Request) (*Subject, error) {
	value := r.Context().Value(requestKeySubject)
	if value == nil {
		return nil, ErrAuthInfoNotFound
	}
	subject, ok := value.(*Subject)
	if !ok {
		return nil, ErrAuthInfoNotFound
	}
	return subject, nil
}

// ProjectFrom 从请求取认证类型
func ProjectFrom(r *http.Request) (string, error) {
	subject, err := SubjectFrom(r)
	if err != nil {
		return "", err
	}
	return subject.Project, nil
}

// TypeFrom 从请求取认证类型
func TypeFrom(r *http.Request) (string, error) {
	subject, err := SubjectFrom(r)
	if err != nil {
		return "", err
	}
	return subject.Type, nil
}

// IDFrom 从请求取认证ID
func IDFrom(r *http.Request, checkType string) (uint64, error) {
	subject, err := SubjectFrom(r)
	if err != nil {
		return 0, err
	}
	if subject.Type != checkType {
		return 0, ErrAuthType
	}
	return subject.ID, nil
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
