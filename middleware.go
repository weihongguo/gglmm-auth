package auth

import (
	"fmt"
	"net/http"

	"github.com/weihongguo/gglmm"
)

// MiddlewareJWTAuth JWT通用认证中间件
func MiddlewareJWTAuth(secrets ...string) gglmm.Middleware {
	return gglmm.Middleware{
		Name: fmt.Sprintf("%s%+v", "JWTAuth", secrets),
		Func: func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				for _, secret := range secrets {
					info, _, err := ParseToken(TokenFrom(r), secret)
					if err == nil {
						r = RequestWithInfo(r, info)
						next.ServeHTTP(w, r)
						return
					}
				}
				gglmm.UnauthorizedResponse().JSON(w)
			})
		},
	}
}
