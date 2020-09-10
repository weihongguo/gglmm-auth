package auth

import (
	"net/http"

	"github.com/weihongguo/gglmm"
)

// PasswordHelper --
type PasswordHelper interface {
	OldPassword(userID uint64) (string, error)
	UpdatePassword(userID uint64, hashedPassword string) error
}

// PasswordService --
type PasswordService struct {
	authType       string
	passwordHelper PasswordHelper
}

// NewPasswordService --
func NewPasswordService(authType string, passwordHelper PasswordHelper) *PasswordService {
	return &PasswordService{
		authType:       authType,
		passwordHelper: passwordHelper,
	}
}

// UpdatePassword --
func (service *PasswordService) UpdatePassword(w http.ResponseWriter, r *http.Request) {
	request := PasswordUpdateRequest{}
	if err := gglmm.DecodeBody(r, &request); err != nil {
		gglmm.FailResponse(gglmm.NewErrFileLine(err)).JSON(w)
		return
	}
	if !request.Check() {
		gglmm.FailResponse(gglmm.NewErrFileLine(gglmm.ErrRequest)).JSON(w)
		return
	}
	userID, err := UserID(r, service.authType)
	if err != nil {
		gglmm.FailResponse(gglmm.NewErrFileLine(gglmm.ErrRequest)).JSON(w)
		return
	}
	oldPassword, err := service.passwordHelper.OldPassword(userID)
	if err != nil {
		gglmm.FailResponse(gglmm.NewErrFileLine(err)).JSON(w)
		return
	}
	if err := ComparePassword(oldPassword, request.OldPassword); err != nil {
		gglmm.FailResponse(gglmm.NewErrFileLine(ErrPassword)).JSON(w)
		return
	}
	newPassword, err := GeneratePassword(request.NewPassword)
	if err != nil {
		gglmm.FailResponse(gglmm.NewErrFileLine(ErrPassword)).JSON(w)
		return
	}
	if err := service.passwordHelper.UpdatePassword(userID, newPassword); err != nil {
		gglmm.FailResponse(gglmm.NewErrFileLine(err)).JSON(w)
		return
	}
	gglmm.SuccessResponse().JSON(w)
}
