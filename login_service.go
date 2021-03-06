package auth

import (
	"net/http"

	"github.com/weihongguo/gglmm"
)

// LoginHelper --
type LoginHelper interface {
	Login(request *LoginRequest) (*Info, error)
}

// LoginService 登录服务
type LoginService struct {
	jwtExpires  int64
	jwtSecret   string
	loginHelper LoginHelper
}

// NewLoginService --
func NewLoginService(jwtConfig ConfigJWT, loginHelper LoginHelper) *LoginService {
	return &LoginService{
		jwtExpires:  jwtConfig.Expires,
		jwtSecret:   jwtConfig.Secret,
		loginHelper: loginHelper,
	}
}

// Login 登录
func (service *LoginService) Login(w http.ResponseWriter, r *http.Request) {
	request := LoginRequest{}
	if err := gglmm.DecodeBody(r, &request); err != nil {
		gglmm.FailResponse(gglmm.NewErrFileLine(err)).JSON(w)
		return
	}
	if !request.Check() {
		gglmm.FailResponse(gglmm.NewErrFileLine(gglmm.ErrRequest)).JSON(w)
		return
	}
	authInfo, err := service.loginHelper.Login(&request)
	if err != nil {
		gglmm.FailResponse(gglmm.NewErrFileLine(err)).JSON(w)
		return
	}
	authToken, jwtClaims, err := generateToken(authInfo.Subject, service.jwtExpires, service.jwtSecret)
	if err != nil {
		gglmm.FailResponse(gglmm.NewErrFileLine(err)).JSON(w)
		return
	}
	gglmm.OkResponse().
		AddData("authToken", authToken).
		AddData("authTokenIssuedAt", jwtClaims.IssuedAt).
		AddData("authTokenExpiresAt", jwtClaims.ExpiresAt).
		AddData("authInfo", authInfo).
		JSON(w)
}
