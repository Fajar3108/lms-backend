package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/fajar3108/lms-backend/internal/user"
	app_error "github.com/fajar3108/lms-backend/pkg/app-error"
	"github.com/fajar3108/lms-backend/pkg/helpers"
	"github.com/fajar3108/lms-backend/pkg/token"
)

type AuthService struct {
	authAction AuthActionInterface
	userAction user.UserActionInterface
	jwtManager token.JWTManagerInterface
	now        func() time.Time
}

func NewAuthService(authAction AuthActionInterface, userAction user.UserActionInterface, jwtManager token.JWTManagerInterface) *AuthService {
	return &AuthService{
		authAction: authAction,
		userAction: userAction,
		jwtManager: jwtManager,
		now:        time.Now,
	}
}

type tokenPair struct {
	accessToken      string
	accessTokenID    string
	refreshToken     string
	accessExpiresAt  time.Time
	refreshExpiresAt time.Time
}

func (s *AuthService) generateTokenPair(userID string) (*tokenPair, error) {
	const operation = "auth.service.generate_token_pair"

	accessToken, accessTokenID, accessExpiresAt, err := s.jwtManager.GenerateAccessToken(userID)
	if err != nil {
		return nil, fmt.Errorf("%s: generate access token: %w", operation, err)
	}

	refreshToken, refreshExpiresAt, err := s.jwtManager.GenerateRefreshToken(userID)
	if err != nil {
		return nil, fmt.Errorf("%s: generate refresh token: %w", operation, err)
	}

	return &tokenPair{
		accessToken:      accessToken,
		accessTokenID:    accessTokenID,
		refreshToken:     refreshToken,
		accessExpiresAt:  accessExpiresAt,
		refreshExpiresAt: refreshExpiresAt,
	}, nil
}

func (s *AuthService) Register(ctx context.Context, req *RegisterRequest) (*user.UserResource, error) {
	const operation = "auth.service.register"

	createdUser, err := s.userAction.CreateUser(ctx, req.Name, req.Email, req.Password)
	if err != nil {
		if errors.Is(err, user.ErrEmailAlreadyExist) {
			return nil, app_error.NewAppError(
				app_error.KindConflict,
				"AUTH_EMAIL_ALREADY_EXISTS",
				"email already registered",
				operation,
				err,
			)
		}
		return nil, fmt.Errorf("%s: create user: %w", operation, err)
	}

	res := user.TransformUser(createdUser)
	return &res, nil
}

func (s *AuthService) Login(ctx context.Context, req *LoginRequest) (*user.LoginResource, error) {
	const operation = "auth.service.login"

	foundUser, err := s.userAction.GetUserByEmail(ctx, req.Email)
	if err != nil {
		if errors.Is(err, user.ErrEmailNotFound) {
			return nil, app_error.NewAppError(
				app_error.KindUnauthorized,
				"AUTH_INVALID_CREDENTIALS",
				"invalid email or password",
				operation,
				ErrInvalidCredentials,
			)
		}
		return nil, fmt.Errorf("%s: get user: %w", operation, err)
	}

	if !helpers.ComparePassword(foundUser.Password, req.Password) {
		return nil, app_error.NewAppError(
			app_error.KindUnauthorized,
			"AUTH_INVALID_CREDENTIALS",
			"invalid email or password",
			operation,
			ErrInvalidCredentials,
		)
	}

	tokens, err := s.generateTokenPair(foundUser.ID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", operation, err)
	}

	sess := &Session{
		ID:        tokens.accessTokenID,
		UserID:    foundUser.ID,
		Token:     tokens.accessToken,
		ExpiresAt: tokens.accessExpiresAt,
	}
	if err := s.authAction.CreateSession(ctx, sess); err != nil {
		return nil, fmt.Errorf("%s: create session: %w", operation, err)
	}

	if _, err := s.authAction.CreateRefreshToken(ctx, foundUser.ID, tokens.refreshToken, tokens.refreshExpiresAt); err != nil {
		return nil, fmt.Errorf("%s: create refresh token: %w", operation, err)
	}

	res := user.TransformLogin(foundUser, tokens.accessToken, tokens.refreshToken, tokens.accessExpiresAt)
	return &res, nil
}

func (s *AuthService) RefreshToken(ctx context.Context, req *RefreshTokenRequest) (*user.LoginResource, error) {
	const operation = "auth.service.refresh_token"

	_, err := s.jwtManager.VerifyToken(req.RefreshToken)
	if err != nil {
		if errors.Is(err, token.ErrTokenExpired) {
			return nil, app_error.NewAppError(
				app_error.KindUnauthorized,
				"AUTH_INVALID_REFRESH_TOKEN",
				"refresh token expired",
				operation,
				err,
			)
		}

		return nil, app_error.NewAppError(
			app_error.KindUnauthorized,
			"AUTH_INVALID_REFRESH_TOKEN",
			"invalid refresh token",
			operation,
			err,
		)
	}

	rt, err := s.authAction.FindRefreshToken(ctx, req.RefreshToken)
	if err != nil {
		if errors.Is(err, ErrRefreshTokenNotFound) {
			return nil, app_error.NewAppError(
				app_error.KindUnauthorized,
				"AUTH_INVALID_REFRESH_TOKEN",
				"invalid refresh token",
				operation,
				err,
			)
		}
		return nil, fmt.Errorf("%s: find refresh token: %w", operation, err)
	}

	if rt.IsRevoked {
		if revokeErr := s.authAction.RevokeAllUserRefreshTokens(
			ctx,
			rt.UserID,
		); revokeErr != nil {
			return nil, fmt.Errorf(
				"%s: revoke all user refresh tokens: %w",
				operation,
				revokeErr,
			)
		}

		return nil, app_error.NewAppError(
			app_error.KindUnauthorized,
			"AUTH_INVALID_REFRESH_TOKEN",
			"invalid refresh token",
			operation,
			ErrRefreshTokenRevoked,
		)
	}

	if !rt.ExpiresAt.After(s.now()) {
		return nil, app_error.NewAppError(
			app_error.KindUnauthorized,
			"AUTH_INVALID_REFRESH_TOKEN",
			"invalid or expired refresh token",
			operation,
			ErrRefreshTokenExpired,
		)
	}

	tokens, err := s.generateTokenPair(rt.UserID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", operation, err)
	}

	sess := &Session{
		ID:        tokens.accessTokenID,
		UserID:    rt.UserID,
		Token:     tokens.accessToken,
		ExpiresAt: tokens.accessExpiresAt,
	}
	if err := s.authAction.CreateSession(ctx, sess); err != nil {
		return nil, fmt.Errorf("%s: create session: %w", operation, err)
	}

	if err := s.authAction.RotateRefreshToken(ctx, rt.UserID, rt.Token, tokens.refreshToken, tokens.refreshExpiresAt); err != nil {
		return nil, fmt.Errorf("%s: rotate refresh token: %w", operation, err)
	}

	res := user.TransformLogin(&rt.User, tokens.accessToken, tokens.refreshToken, tokens.accessExpiresAt)
	return &res, nil
}

func (s *AuthService) GetProfile(ctx context.Context, userID string) (*user.UserResource, error) {
	const operation = "auth.service.get_profile"

	foundUser, err := s.userAction.GetUserByID(ctx, userID)
	if err != nil {
		if errors.Is(err, user.ErrUserNotFound) {
			return nil, app_error.NewAppError(
				app_error.KindNotFound,
				"AUTH_USER_NOT_FOUND",
				"user not found",
				operation,
				err,
			)
		}
		return nil, fmt.Errorf("%s: get user: %w", operation, err)
	}

	res := user.TransformUser(foundUser)
	return &res, nil
}

func (s *AuthService) Logout(ctx context.Context, userID, sessionID, refreshToken string) error {
	const operation = "auth.service.logout"

	if err := s.authAction.DeleteSession(ctx, userID, sessionID); err != nil {
		return fmt.Errorf("%s: delete session from redis: %w", operation, err)
	}

	if err := s.authAction.RevokeRefreshToken(ctx, refreshToken); err != nil {
		return fmt.Errorf("%s: revoke refresh token in db: %w", operation, err)
	}

	return nil
}
