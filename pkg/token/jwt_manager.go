package token

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

var (
	ErrTokenExpired = errors.New("token is expired")
)

type UserClaims struct {
	UserID string `json:"user_id"`
	jwt.RegisteredClaims
}

type JWTManager struct {
	secretKey      []byte
	accessExpHours int
	refreshExpDays int
}

func NewJWTManager(secretKey string, accessExpHours int, refreshExpDays int) *JWTManager {
	return &JWTManager{
		secretKey:      []byte(secretKey),
		accessExpHours: accessExpHours,
		refreshExpDays: refreshExpDays,
	}
}

func (m *JWTManager) GenerateAccessToken(userID string) (string, string, time.Time, error) {
	tokenID := uuid.NewString()
	expiration := time.Now().Add(time.Duration(m.accessExpHours) * time.Hour)
	claims := &UserClaims{
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiration),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ID:        tokenID,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenStr, err := token.SignedString(m.secretKey)
	if err != nil {
		return "", "", time.Time{}, fmt.Errorf("failed to sign access token: %w", err)
	}

	return tokenStr, tokenID, expiration, nil
}

func (m *JWTManager) GenerateRefreshToken(userID string) (string, time.Time, error) {
	expiration := time.Now().Add(time.Duration(m.refreshExpDays) * 24 * time.Hour)
	claims := &UserClaims{
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiration),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenStr, err := token.SignedString(m.secretKey)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to sign refresh token: %w", err)
	}

	return tokenStr, expiration, nil
}

func (m *JWTManager) VerifyToken(tokenStr string) (*UserClaims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &UserClaims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return m.secretKey, nil
	})

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrTokenExpired
		}
		return nil, fmt.Errorf("token validation failed: %w", err)
	}

	claims, ok := token.Claims.(*UserClaims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token payload or validation state")
	}

	return claims, nil
}
