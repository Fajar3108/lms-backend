package auth

import (
	"context"

	"github.com/fajar3108/lms-backend/internal/user"
)

//go:generate mockgen -source=$GOFILE -destination=../../test/mock/auth/auth_service_mock.go -package=auth_mock
type AuthServiceInterace interface {
	Register(ctx context.Context, req *RegisterRequest) (*user.UserResource, error)
	Login(ctx context.Context, req *LoginRequest) (*user.LoginResource, error)
	RefreshToken(ctx context.Context, req *RefreshTokenRequest) (*user.LoginResource, error)
	GetProfile(ctx context.Context, userID string) (*user.UserResource, error)
	Logout(ctx context.Context, userID, sessionID, refreshToken string) error
}
