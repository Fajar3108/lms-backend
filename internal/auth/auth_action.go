package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/fajar3108/lms-backend/internal/user"
	"github.com/fajar3108/lms-backend/pkg/redis"
	"gorm.io/gorm"
)

type AuthAction struct {
	db    *gorm.DB
	redis redis.RedisClient
}

func NewAuthAction(db *gorm.DB, redisClient redis.RedisClient) *AuthAction {
	return &AuthAction{db: db, redis: redisClient}
}

func (a *AuthAction) CreateRefreshToken(ctx context.Context, userID, token string, expiresAt time.Time) (*user.RefreshToken, error) {
	const operation = "auth.action.create_refresh_token"

	refreshToken := &user.RefreshToken{
		UserID:    userID,
		Token:     token,
		ExpiresAt: expiresAt,
		IsRevoked: false,
	}

	if err := a.db.WithContext(ctx).Create(refreshToken).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", operation, err)
	}

	return refreshToken, nil
}

func (a *AuthAction) RotateRefreshToken(
	ctx context.Context,
	userID string,
	oldToken string,
	newToken string,
	newExpiresAt time.Time,
) error {
	const operation = "auth.action.rotate_refresh_token"

	return a.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		result := tx.
			Model(&user.RefreshToken{}).
			Where(
				"token = ? AND user_id = ? AND is_revoked = ?",
				oldToken,
				userID,
				false,
			).
			Updates(map[string]any{
				"is_revoked": true,
			})

		if result.Error != nil {
			return fmt.Errorf(
				"%s: revoke old token: %w",
				operation,
				result.Error,
			)
		}

		if result.RowsAffected == 0 {
			return fmt.Errorf(
				"%s: %w",
				operation,
				ErrRefreshTokenRevoked,
			)
		}

		newRefreshToken := &user.RefreshToken{
			UserID:    userID,
			Token:     newToken,
			ExpiresAt: newExpiresAt,
			IsRevoked: false,
		}

		if err := tx.Create(newRefreshToken).Error; err != nil {
			return fmt.Errorf(
				"%s: create new token: %w",
				operation,
				err,
			)
		}

		return nil
	})
}

func (a *AuthAction) FindRefreshToken(ctx context.Context, token string) (*user.RefreshToken, error) {
	const operation = "auth.action.find_refresh_token"

	var rt user.RefreshToken
	if err := a.db.WithContext(ctx).Preload("User").Where("token = ?", token).First(&rt).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("%s: %w", operation, ErrRefreshTokenNotFound)
		}
		return nil, fmt.Errorf("%s: %w", operation, err)
	}
	return &rt, nil
}

func (a *AuthAction) RevokeAllUserRefreshTokens(ctx context.Context, userID string) error {
	const operation = "auth.action.revoke_all_user_refresh_tokens"

	tx := a.db.WithContext(ctx).
		Model(&user.RefreshToken{}).
		Where("user_id = ?", userID).
		Update("is_revoked", true)

	if err := tx.Error; err != nil {
		return fmt.Errorf("%s: %w", operation, err)
	}

	return nil
}

func (a *AuthAction) RevokeRefreshToken(ctx context.Context, token string) error {
	const operation = "auth.action.revoke_refresh_token"

	tx := a.db.WithContext(ctx).
		Model(&user.RefreshToken{}).
		Where("token = ?", token).
		Update("is_revoked", true)

	if err := tx.Error; err != nil {
		return fmt.Errorf("%s: %w", operation, err)
	}

	return nil
}

func (a *AuthAction) CreateSession(ctx context.Context, session *Session) error {
	const operation = "auth.action.create_session"

	data, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("%s: marshal session: %w", operation, err)
	}

	key := GetSessionKey(session.UserID, session.ID)
	expiration := time.Until(session.ExpiresAt)
	if expiration <= 0 {
		return fmt.Errorf("%s: invalid session expiration", operation)
	}

	if err := a.redis.Set(ctx, key, string(data), expiration); err != nil {
		return fmt.Errorf("%s: save to redis: %w", operation, err)
	}

	return nil
}

func (a *AuthAction) GetSession(ctx context.Context, userID, sessionID string) (*Session, error) {
	const operation = "auth.action.get_session"

	key := GetSessionKey(userID, sessionID)
	data, err := a.redis.Get(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("%s: get from redis: %w", operation, err)
	}

	var session Session
	if err := json.Unmarshal([]byte(data), &session); err != nil {
		return nil, fmt.Errorf("%s: unmarshal session: %w", operation, err)
	}

	return &session, nil
}

func (a *AuthAction) DeleteSession(ctx context.Context, userID, sessionID string) error {
	const operation = "auth.action.delete_session"

	key := GetSessionKey(userID, sessionID)
	if err := a.redis.Del(ctx, key); err != nil {
		return fmt.Errorf("%s: delete from redis: %w", operation, err)
	}

	return nil
}
