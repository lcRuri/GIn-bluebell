package jwt

import (
	"errors"
	"time"

	"github.com/dgrijalva/jwt-go"
)

//定义过期时间
const TokenExpireDuration = time.Hour * 2

//自定义盐
var mySecret = []byte("你的脸没有化妆我却疯狂爱上")

type MyClaims struct {
	UserID   int64  `json:"user_id"`
	Username string `json:"username"`
	jwt.StandardClaims
}

//生成Token
func GenToken(userID int64, username string) (string, error) {
	c := MyClaims{
		UserID:   userID,
		Username: username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(TokenExpireDuration).Unix(), //过期时间
			Issuer:    "bluebell",                                 //签发人

		},
	}
	//使用指定的签名方法创建对象
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, c)
	//使用指定的secret签名并获得完整的编码后的字符串token
	return token.SignedString(mySecret)
}

//解析jwt
func ParseToken(tokenString string) (*MyClaims, error) {
	//解析Token
	var mc = new(MyClaims)
	token, err := jwt.ParseWithClaims(tokenString, mc, func(token *jwt.Token) (i interface{}, err error) {
		return mySecret, nil
	})
	if err != nil {
		return nil, err
	}
	if token.Valid { // 校验token
		return mc, nil
	}
	return nil, errors.New("invalid token")
}
