package auth

import (
	"log"
	"net/http"

	"github.com/weihongguo/gglmm"
	weixin "github.com/weihongguo/gglmm-weixin"
)

// WeixinMiniProgramLoginService --
type WeixinMiniProgramLoginService struct {
	appID      string
	appSecret  string
	jwtExpires int64
	jwtSecret  string
	user       WeixinMiniProgramUser
}

// NewWeixinMiniProgramLoginService --
func NewWeixinMiniProgramLoginService(miniProgramConfig weixin.ConfigMiniProgram, jwtConfig ConfigJWT, user WeixinMiniProgramUser) *WeixinMiniProgramLoginService {
	if !miniProgramConfig.Check() || !jwtConfig.Check("all") {
		log.Printf("%+v %+v\n", miniProgramConfig, jwtConfig)
		log.Fatal("Config check invalid")
	}
	return &WeixinMiniProgramLoginService{
		appID:      miniProgramConfig.AppID,
		appSecret:  miniProgramConfig.AppSecret,
		jwtExpires: jwtConfig.Expires,
		jwtSecret:  jwtConfig.Secret,
		user:       user,
	}
}

// Login 登录-微信
// Session已经过期或第一次登录，下发token
func (service *WeixinMiniProgramLoginService) Login(w http.ResponseWriter, r *http.Request) {
	request, err := weixin.DecodeMiniProgramLoginRequest(r)
	if err != nil {
		gglmm.Panic(err)
	}
	if !request.Check() {
		gglmm.Panic(gglmm.ErrRequest)
	}
	code2SessionResponse, err := weixin.MiniProgramCode2Session(service.appID, service.appSecret, request.Code)
	if err != nil {
		gglmm.Panic(err)
	}
	authInfo, err := service.user.Login(code2SessionResponse)
	if err != nil {
		gglmm.Panic(err)
	}
	authToken, jwtClaims, err := GenerateToken(authInfo, service.jwtExpires, service.jwtSecret)
	if err != nil {
		gglmm.Panic(err)
	}
	gglmm.OkResponse().
		AddData("authToken", authToken).
		AddData("authTokenIssuedAt", jwtClaims.IssuedAt).
		AddData("authTokenExpiresAt", jwtClaims.ExpiresAt).
		AddData("authInfo", authInfo).
		JSON(w)
}