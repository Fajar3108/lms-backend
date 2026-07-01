package auth

import (
	"context"
	"time"

	"github.com/fajar3108/lms-backend/internal/user"
)

//go:generate mockgen -source=$GOFILE -destination=../../test/mock/auth/auth_action_mock.go -package=auth_mock
type AuthActionInterface interface {
	CreateRefreshToken(ctx context.Context, userID, token string, expiresAt time.Time) (*user.RefreshToken, error)
	RotateRefreshToken(ctx context.Context, userID, oldToken, newToken string, newExpiresAt time.Time) error
	FindRefreshToken(ctx context.Context, token string) (*user.RefreshToken, error)
	RevokeAllUserRefreshTokens(ctx context.Context, userID string) error
	RevokeRefreshToken(ctx context.Context, token string) error

	CreateSession(ctx context.Context, session *Session) error
	GetSession(ctx context.Context, userID, sessionID string) (*Session, error)
	DeleteSession(ctx context.Context, userID, sessionID string) error
}
