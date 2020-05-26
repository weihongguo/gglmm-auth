package auth

import (
	"fmt"
	"net/http"

	"github.com/weihongguo/gglmm"
)

// JWTAuthentication JWT通用认证中间件
func JWTAuthentication(secrets ...string) gglmm.Middleware {
	return gglmm.Middleware{
		Name: fmt.Sprintf("%s%+v", "JWTAuthentication", secrets),
		Func: func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				for _, secret := range secrets {
					authInfo, _, err := ParseAuthJWT(GetAuthJWT(r), secret)
					if err == nil {
						r = RequestWithAuthInfo(r, authInfo)
						next.ServeHTTP(w, r)
						return
					}
				}
				gglmm.UnauthorizedResponse().JSON(w)
			})
		},
	}
}
