package auth

import (
	"net/http"

	"github.com/weihongguo/gglmm"
	weixin "github.com/weihongguo/gglmm-weixin"
)

// WeixinMiniProgramUserInfoHelper --
type WeixinMiniProgramUserInfoHelper interface {
	UserInfoRaw(userID uint64, userInfoRequest *weixin.MiniProgramUserInfoRequest) (*Info, error)
	UserInfoEncrypted(userID uint64, userInfoRequest *weixin.MiniProgramUserInfoRequest) (*Info, error)
}

// WeixinMiniProgramInfoService --
type WeixinMiniProgramInfoService struct {
	appID          string
	appSecret      string
	jwtExpires     int64
	jwtSecret      string
	authType       string
	userInfoHelper WeixinMiniProgramUserInfoHelper
}

// NewWeixinMiniProgramInfoService --
func NewWeixinMiniProgramInfoService(miniProgramConfig weixin.ConfigMiniProgram, jwtConfig ConfigJWT, authType string, userInfoHelper WeixinMiniProgramUserInfoHelper) *WeixinMiniProgramInfoService {
	return &WeixinMiniProgramInfoService{
		appID:          miniProgramConfig.AppID,
		appSecret:      miniProgramConfig.AppSecret,
		jwtExpires:     jwtConfig.Expires,
		jwtSecret:      jwtConfig.Secret,
		authType:       authType,
		userInfoHelper: userInfoHelper,
	}
}

// UserInfo --
func (service *WeixinMiniProgramInfoService) UserInfo(w http.ResponseWriter, r *http.Request) {
	userID, err := UserID(r, service.authType)
	if err != nil {
		gglmm.FailResponse(gglmm.NewErrFileLine(err)).JSON(w)
		return
	}
	userInfoRequest, err := weixin.DecodeMiniProgramUserInfoRequest(r)
	if err != nil {
		gglmm.FailResponse(gglmm.NewErrFileLine(err)).JSON(w)
		return
	}
	if userInfoRequest.Check("raw") {
		authInfo, err := service.userInfoHelper.UserInfoRaw(userID, userInfoRequest)
		if err != nil {
			gglmm.FailResponse(gglmm.NewErrFileLine(err)).JSON(w)
			return
		}
		gglmm.OkResponse().
			AddData("authInfo", authInfo).
			JSON(w)
	} else if userInfoRequest.Check("encrypted") {
		authInfo, err := service.userInfoHelper.UserInfoEncrypted(userID, userInfoRequest)
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
	} else {
		gglmm.FailResponse("user info type error").JSON(w)
	}
}
