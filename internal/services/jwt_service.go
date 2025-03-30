package services

import (
	"github.com/abandontech/abandonauth/internal/config"
	"github.com/golang-jwt/jwt/v5"
)

type JwtService struct {
	secret []byte
}

func NewJwtService(conf config.Jwt) JwtService {
	return JwtService{
		secret: []byte(conf.Secret),
	}
}

func (s JwtService) CreateToken(claims jwt.MapClaims) *jwt.Token {
	return jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
}

func (s JwtService) CreateSignedToken(claims jwt.MapClaims) (string, error) {
	return s.SignToken(s.CreateToken(claims))
}

func (s JwtService) SignToken(token *jwt.Token) (string, error) {
	return token.SignedString(s.secret)
}
