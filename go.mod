module github.com/weihongguo/gglmm-auth

go 1.13

replace github.com/weihongguo/gglmm => ../gglmm

replace github.com/weihongguo/gglmm-weixin => ../gglmm-weixin

require (
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/weihongguo/gglmm v0.0.0-20200225064623-73efc6160d28
	github.com/weihongguo/gglmm-weixin v0.0.0-20200527134538-2891bdb031a2
	golang.org/x/crypto v0.0.0-20190325154230-a5d413f7728c
)
