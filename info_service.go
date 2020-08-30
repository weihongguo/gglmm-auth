package auth

import (
	"net/http"

	"github.com/weihongguo/gglmm"
)

// InfoService --
type InfoService struct {
	authType string
	user     User
}

// NewInfoService --
func NewInfoService(authType string, user User) *InfoService {
	return &InfoService{
		authType: authType,
		user:     user,
	}
}

// Info --
func (service *InfoService) Info(w http.ResponseWriter, r *http.Request) {
	userID, err := UserID(r, service.authType)
	if err != nil {
		gglmm.FailResponse(gglmm.NewErrFileLine(err)).JSON(w)
		return
	}
	idRequest := gglmm.IDRequest{
		ID: userID,
	}
	authInfo, err := service.user.Info(&idRequest)
	if err != nil {
		gglmm.FailResponse(gglmm.NewErrFileLine(err)).JSON(w)
		return
	}
	gglmm.OkResponse().
		AddData("authInfo", authInfo).
		JSON(w)
}
