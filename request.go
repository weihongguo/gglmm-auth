package auth

// RegisterRequest 注册请求
type RegisterRequest struct {
	UserName string `json:"userName"`
	Password string `json:"password"`
}

// Check --
func (request RegisterRequest) Check() bool {
	if request.UserName == "" || request.Password == "" {
		return false
	}
	return true
}

// LoginRequest 登录请求
type LoginRequest struct {
	UserName string `json:"userName"`
	Password string `json:"password"`
}

// Check --
func (request LoginRequest) Check() bool {
	if request.UserName == "" || request.Password == "" {
		return false
	}
	return true
}

// PasswordUpdateRequest 修改密码请求
type PasswordUpdateRequest struct {
	OldPassword string `json:"oldPassword"`
	NewPassword string `json:"newPassword"`
}

// Check --
func (request PasswordUpdateRequest) Check() bool {
	if request.OldPassword == "" || request.NewPassword == "" {
		return false
	}
	return true
}
