package token

import "time"

//go:generate mockgen -source=$GOFILE -destination=../../test/mock/pkg/token/jwt_manager_mock.go -package=token_mock
type JWTManagerInterface interface {
	GenerateAccessToken(userID string) (string, string, time.Time, error)
	GenerateRefreshToken(userID string) (string, time.Time, error)
	VerifyToken(tokenStr string) (*UserClaims, error)
}
