package auth

import (
	"net/http"

	"github.com/weihongguo/gglmm"
)

// InfoHelper --
type InfoHelper interface {
	Info(request *gglmm.IDRequest) (*Info, error)
}

// InfoService --
type InfoService struct {
	authType   string
	infoHelper InfoHelper
}

// NewInfoService --
func NewInfoService(authType string, infoHelper InfoHelper) *InfoService {
	return &InfoService{
		authType:   authType,
		infoHelper: infoHelper,
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
	authInfo, err := service.infoHelper.Info(&idRequest)
	if err != nil {
		gglmm.FailResponse(gglmm.NewErrFileLine(err)).JSON(w)
		return
	}
	gglmm.OkResponse().
		AddData("authInfo", authInfo).
		JSON(w)
}
