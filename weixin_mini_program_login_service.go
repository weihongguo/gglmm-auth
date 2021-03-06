package auth

import (
	"net/http"

	"github.com/weihongguo/gglmm"
	weixin "github.com/weihongguo/gglmm-weixin"
)

// WeixinMiniProgramLoginHelper --
type WeixinMiniProgramLoginHelper interface {
	Login(code2SessionResponse *weixin.MiniProgramCode2SessionResponse) (*Info, error)
}

// WeixinMiniProgramLoginService --
type WeixinMiniProgramLoginService struct {
	appID       string
	appSecret   string
	jwtExpires  int64
	jwtSecret   string
	loginHelper WeixinMiniProgramLoginHelper
}

// NewWeixinMiniProgramLoginService --
func NewWeixinMiniProgramLoginService(miniProgramConfig weixin.ConfigMiniProgram, jwtConfig ConfigJWT, loginHelper WeixinMiniProgramLoginHelper) *WeixinMiniProgramLoginService {
	return &WeixinMiniProgramLoginService{
		appID:       miniProgramConfig.AppID,
		appSecret:   miniProgramConfig.AppSecret,
		jwtExpires:  jwtConfig.Expires,
		jwtSecret:   jwtConfig.Secret,
		loginHelper: loginHelper,
	}
}

// Login 登录-微信
// Session已经过期或第一次登录，下发token
func (service *WeixinMiniProgramLoginService) Login(w http.ResponseWriter, r *http.Request) {
	request, err := weixin.DecodeMiniProgramLoginRequest(r)
	if err != nil {
		gglmm.FailResponse(gglmm.NewErrFileLine(err)).JSON(w)
		return
	}
	if !request.Check() {
		gglmm.FailResponse(gglmm.NewErrFileLine(gglmm.ErrRequest)).JSON(w)
		return
	}
	code2SessionResponse, err := weixin.MiniProgramCode2Session(service.appID, service.appSecret, request.Code)
	if err != nil {
		gglmm.FailResponse(gglmm.NewErrFileLine(err)).JSON(w)
		return
	}
	authInfo, err := service.loginHelper.Login(code2SessionResponse)
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
