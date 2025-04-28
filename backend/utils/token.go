package utils

import (
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"os"
)

// VerifyToken - Верификация токена
func VerifyToken(tokenString string) (*jwt.Token, error) {
	jwtSecret := []byte(os.Getenv("JWT_SECRET"))

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})
	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	return token, nil
}
