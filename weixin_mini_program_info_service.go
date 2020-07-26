package auth

import (
	"log"
	"net/http"

	"github.com/weihongguo/gglmm"
	weixin "github.com/weihongguo/gglmm-weixin"
)

// WeixinMiniProgramInfoService --
type WeixinMiniProgramInfoService struct {
	appID      string
	appSecret  string
	jwtExpires int64
	jwtSecret  string
	authType   string
	user       WeixinMiniProgramUser
}

// NewWeixinMiniProgramInfoService --
func NewWeixinMiniProgramInfoService(miniProgramConfig weixin.ConfigMiniProgram, jwtConfig ConfigJWT, authType string, user WeixinMiniProgramUser) *WeixinMiniProgramInfoService {
	if !miniProgramConfig.Check() || !jwtConfig.Check("all") {
		log.Printf("%+v %+v\n", miniProgramConfig, jwtConfig)
		log.Fatal("Config check invalid")
	}
	return &WeixinMiniProgramInfoService{
		appID:      miniProgramConfig.AppID,
		appSecret:  miniProgramConfig.AppSecret,
		jwtExpires: jwtConfig.Expires,
		jwtSecret:  jwtConfig.Secret,
		authType:   authType,
		user:       user,
	}
}

// Info --
func (service *WeixinMiniProgramInfoService) Info(w http.ResponseWriter, r *http.Request) {
	userID, err := IDFrom(r, service.authType)
	if err != nil {
		gglmm.Panic(err)
		return
	}
	userInfoRequest, err := weixin.DecodeMiniProgramUserInfoRequest(r)
	if err != nil {
		gglmm.Panic(err)
		return
	}
	if userInfoRequest.Check("raw") {
		authInfo, err := service.user.AuthInfoRaw(userID, userInfoRequest)
		if err != nil {
			gglmm.Panic(err)
		}
		gglmm.OkResponse().
			AddData("authInfo", authInfo).
			JSON(w)
	} else if userInfoRequest.Check("encrypted") {
		authInfo, err := service.user.AuthInfoEncrypted(userID, userInfoRequest)
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
	} else {
		gglmm.Panic("user info type error")
	}
}
