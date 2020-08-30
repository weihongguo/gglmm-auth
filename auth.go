package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/weihongguo/gglmm"
	weixin "github.com/weihongguo/gglmm-weixin"
)

type requestKey string

const (
	requestKeySubject requestKey = "gglmm-auth-subject"
)

// Subject --
type Subject struct {
	Project  string `json:"project"`
	UserType string `json:"userType"`
	UserID   uint64 `json:"userId"`
}

// Info 认证信息
type Info struct {
	*Subject
	Nickname  string `json:"nickname"`
	AvatarURL string `json:"avatarUrl"`
}

// User --
type User interface {
	Login(request *LoginRequest) (*Info, error)
	Info(request *gglmm.IDRequest) (*Info, error)
}

// WeixinMiniProgramUser --
type WeixinMiniProgramUser interface {
	Login(code2SessionResponse *weixin.MiniProgramCode2SessionResponse) (*Info, error)
	UserInfoRaw(userID uint64, userInfoRequest *weixin.MiniProgramUserInfoRequest) (*Info, error)
	UserInfoEncrypted(userID uint64, userInfoRequest *weixin.MiniProgramUserInfoRequest) (*Info, error)
}

func generateToken(subject *Subject, expires int64, secret string) (string, *jwt.StandardClaims, error) {
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

func authorizationToken(r *http.Request) string {
	return strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
}

func parseToken(tokenString string, secret string) (*Subject, *jwt.StandardClaims, error) {
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

func withSubject(r *http.Request, subject *Subject) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), requestKeySubject, subject))
}

func subject(r *http.Request) (*Subject, error) {
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

// Project 从请求取认证类型
func Project(r *http.Request) (string, error) {
	subject, err := subject(r)
	if err != nil {
		return "", err
	}
	return subject.Project, nil
}

// UserTypeID --
func UserTypeID(r *http.Request) (string, uint64, error) {
	subject, err := subject(r)
	if err != nil {
		return "", 0, err
	}
	return subject.UserType, subject.UserID, nil
}

// UserType 从请求取认证类型
func UserType(r *http.Request) (string, error) {
	subject, err := subject(r)
	if err != nil {
		return "", err
	}
	return subject.UserType, nil
}

// UserID 从请求取认证ID
func UserID(r *http.Request, checkType string) (uint64, error) {
	subject, err := subject(r)
	if err != nil {
		return 0, err
	}
	if subject.UserType != checkType {
		return 0, ErrAuthType
	}
	return subject.UserID, nil
}
