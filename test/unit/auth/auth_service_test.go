package auth_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/fajar3108/lms-backend/internal/auth"
	"github.com/fajar3108/lms-backend/internal/user"
	app_error "github.com/fajar3108/lms-backend/pkg/app-error"
	"github.com/fajar3108/lms-backend/pkg/helpers"
	"github.com/fajar3108/lms-backend/pkg/token"
	auth_mock "github.com/fajar3108/lms-backend/test/mock/auth"
	token_mock "github.com/fajar3108/lms-backend/test/mock/pkg/token"
	user_mock "github.com/fajar3108/lms-backend/test/mock/user"
	"github.com/stretchr/testify/suite"
	"go.uber.org/mock/gomock"
)

type AuthServiceTestSuite struct {
	suite.Suite
	mockCtrl       *gomock.Controller
	jwtManagerMock *token_mock.MockJWTManagerInterface
	authActionMock *auth_mock.MockAuthActionInterface
	userActionMock *user_mock.MockUserActionInterface
	authService    *auth.AuthService
}

func TestAuthService(t *testing.T) {
	suite.Run(t, &AuthServiceTestSuite{})
}

func (s *AuthServiceTestSuite) SetupSubTest() {
	s.mockCtrl = gomock.NewController(s.T())
	s.authActionMock = auth_mock.NewMockAuthActionInterface(s.mockCtrl)
	s.userActionMock = user_mock.NewMockUserActionInterface(s.mockCtrl)
	s.jwtManagerMock = token_mock.NewMockJWTManagerInterface(s.mockCtrl)
	s.authService = auth.NewAuthService(s.authActionMock, s.userActionMock, s.jwtManagerMock)
}

func (s *AuthServiceTestSuite) TearDownSubTest() {
	s.mockCtrl.Finish()
}

func (s *AuthServiceTestSuite) TestRegister() {
	req := auth.RegisterRequest{
		Name:  "Test User",
		Email: "test@example.com",
	}

	expectedUser := &user.User{
		ID:        "1",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		Name:      req.Name,
		Email:     req.Email,
	}

	s.Run("Register successfully", func() {
		expectedUserResource := user.TransformUser(expectedUser)

		s.userActionMock.EXPECT().
			GetUserByEmail(gomock.Any(), req.Email).
			Return(nil, user.ErrEmailNotFound).
			AnyTimes()

		s.userActionMock.EXPECT().
			CreateUser(gomock.Any(), req.Name, req.Email, gomock.Any()).
			Return(expectedUser, nil).
			AnyTimes()

		res, err := s.authService.Register(context.Background(), &req)
		s.Require().NoError(err)
		s.Require().NotNil(res)
		s.Equal(expectedUserResource.ID, res.ID)
		s.Equal(expectedUserResource.Name, res.Name)
		s.Equal(expectedUserResource.Email, res.Email)
	})

	s.Run("Failed when email already registered", func() {
		s.userActionMock.EXPECT().
			CreateUser(gomock.Any(), req.Name, req.Email, gomock.Any()).
			Return(nil, user.ErrEmailAlreadyExist).
			AnyTimes()

		res, err := s.authService.Register(context.Background(), &req)
		s.Require().Nil(res)
		s.Require().Error(err)
		var appErr *app_error.AppError
		s.Require().True(errors.As(err, &appErr))
		s.Equal(app_error.KindConflict, appErr.Kind)
		s.ErrorIs(err, user.ErrEmailAlreadyExist)
	})
}

func (s *AuthServiceTestSuite) TestLogin() {
	const (
		dummyEmail    = "usertest@mail.com"
		dummyPassword = "password123"
	)

	hashedPassword, err := helpers.HashPassword(dummyPassword)
	s.Require().NoError(err)

	expectedUser := &user.User{
		ID:       "1",
		Name:     "Test User",
		Email:    dummyEmail,
		Password: hashedPassword,
	}

	expectedAccessToken := "dummyAccessToken"
	expectedRefreshToken := "dummyRefreshToken"
	expectedAccessTokenExp := time.Now().Add(15 * time.Minute)
	expectedRefreshTokenExp := time.Now().Add(24 * 7 * time.Hour)

	s.Run("Login successfully", func() {
		req := &auth.LoginRequest{
			Email:    dummyEmail,
			Password: dummyPassword,
		}

		expectedLoginResource := user.TransformLogin(expectedUser, expectedAccessToken, expectedRefreshToken, expectedAccessTokenExp)

		s.userActionMock.EXPECT().
			GetUserByEmail(gomock.Any(), req.Email).
			Return(expectedUser, nil).
			AnyTimes()

		s.jwtManagerMock.EXPECT().
			GenerateAccessToken(expectedUser.ID).
			Return(expectedAccessToken, "dummyJti", expectedAccessTokenExp, nil).
			AnyTimes()

		s.jwtManagerMock.EXPECT().
			GenerateRefreshToken(expectedUser.ID).
			Return(expectedRefreshToken, expectedRefreshTokenExp, nil).
			AnyTimes()

		s.authActionMock.EXPECT().
			CreateSession(gomock.Any(), gomock.Any()).
			Return(nil).
			AnyTimes()

		s.authActionMock.EXPECT().
			CreateRefreshToken(gomock.Any(), expectedUser.ID, expectedRefreshToken, expectedRefreshTokenExp).
			Return(nil, nil).
			AnyTimes()

		res, err := s.authService.Login(context.Background(), req)
		s.Require().NoError(err)
		s.Require().NotNil(res)
		s.Equal(expectedLoginResource.AccessToken, res.AccessToken)
		s.Equal(expectedLoginResource.RefreshToken, res.RefreshToken)
		s.Equal(expectedLoginResource.ExpiresAt, res.ExpiresAt)
		s.Equal(expectedLoginResource.User.ID, res.User.ID)
		s.Equal(expectedLoginResource.User.Name, res.User.Name)
		s.Equal(expectedLoginResource.User.Email, res.User.Email)
	})

	s.Run("Failed when email not registered", func() {
		req := &auth.LoginRequest{
			Email:    "nonexisted@mail.com",
			Password: dummyPassword,
		}

		s.userActionMock.EXPECT().
			GetUserByEmail(gomock.Any(), req.Email).
			Return(nil, user.ErrEmailNotFound).
			AnyTimes()

		res, err := s.authService.Login(context.Background(), req)
		s.Require().Nil(res)
		s.Require().Error(err)
		var appErr *app_error.AppError
		s.Require().True(errors.As(err, &appErr))
		s.Equal(app_error.KindUnauthorized, appErr.Kind)
		s.ErrorIs(err, auth.ErrInvalidCredentials)
	})

	s.Run("Failed when password is wrong", func() {
		req := &auth.LoginRequest{
			Email:    dummyEmail,
			Password: "wrongpassword",
		}

		s.userActionMock.EXPECT().
			GetUserByEmail(gomock.Any(), req.Email).
			Return(expectedUser, nil).
			AnyTimes()

		res, err := s.authService.Login(context.Background(), req)
		s.Require().Nil(res)
		s.Require().Error(err)
		var appErr *app_error.AppError
		s.Require().True(errors.As(err, &appErr))
		s.Equal(app_error.KindUnauthorized, appErr.Kind)
		s.ErrorIs(err, auth.ErrInvalidCredentials)
	})
}

func (s *AuthServiceTestSuite) TestGetProfile() {
	s.Run("Get user profile successfully", func() {
		const dummyUserID = "1"

		expectedUser := &user.User{
			ID:       dummyUserID,
			Name:     "Test User",
			Email:    "usertest@mail.com",
			Password: "password123",
		}

		expectedUserResource := user.TransformUser(expectedUser)

		s.userActionMock.EXPECT().
			GetUserByID(gomock.Any(), dummyUserID).
			Return(expectedUser, nil).
			AnyTimes()

		res, err := s.authService.GetProfile(context.Background(), dummyUserID)
		s.Require().NoError(err)
		s.Require().NotNil(res)
		s.Equal(expectedUserResource.ID, res.ID)
		s.Equal(expectedUserResource.Name, res.Name)
		s.Equal(expectedUserResource.Email, res.Email)
	})

	s.Run("Failed when user not found", func() {
		const dummyUserID = "1"

		s.userActionMock.EXPECT().
			GetUserByID(gomock.Any(), dummyUserID).
			Return(nil, user.ErrUserNotFound).
			AnyTimes()

		res, err := s.authService.GetProfile(context.Background(), dummyUserID)
		s.Require().Nil(res)
		s.Require().Error(err)
		var appErr *app_error.AppError
		s.Require().True(errors.As(err, &appErr))
		s.Equal(app_error.KindNotFound, appErr.Kind)
		s.ErrorIs(err, user.ErrUserNotFound)
	})
}

func (s *AuthServiceTestSuite) TestRefreshToken() {
	s.Run("Refresh token successfully", func() {
		req := &auth.RefreshTokenRequest{
			RefreshToken: "dummyRefreshToken",
		}

		expectedUser := &user.User{
			ID:    "1",
			Name:  "Test User",
			Email: "test@example.com",
		}

		rt := &user.RefreshToken{
			Token:     "dummyRefreshToken",
			UserID:    "1",
			ExpiresAt: time.Now().Add(24 * time.Hour),
			User:      *expectedUser,
		}

		claims := &token.UserClaims{
			UserID: "1",
		}

		s.jwtManagerMock.EXPECT().
			VerifyToken(req.RefreshToken).
			Return(claims, nil).
			AnyTimes()

		s.authActionMock.EXPECT().
			FindRefreshToken(gomock.Any(), req.RefreshToken).
			Return(rt, nil).
			AnyTimes()

		s.jwtManagerMock.EXPECT().
			GenerateAccessToken(expectedUser.ID).
			Return("newAccessToken", "newJti", time.Now().Add(15*time.Minute), nil).
			AnyTimes()

		s.jwtManagerMock.EXPECT().
			GenerateRefreshToken(expectedUser.ID).
			Return("newRefreshToken", time.Now().Add(24*7*time.Hour), nil).
			AnyTimes()

		s.authActionMock.EXPECT().
			CreateSession(gomock.Any(), gomock.Any()).
			Return(nil).
			AnyTimes()

		s.authActionMock.EXPECT().
			RotateRefreshToken(gomock.Any(), expectedUser.ID, "dummyRefreshToken", "newRefreshToken", gomock.Any()).
			Return(nil).
			AnyTimes()

		res, err := s.authService.RefreshToken(context.Background(), req)
		s.Require().NoError(err)
		s.Require().NotNil(res)
		s.Equal("newAccessToken", res.AccessToken)
		s.Equal("newRefreshToken", res.RefreshToken)
	})
}

func (s *AuthServiceTestSuite) TestLogout() {
	s.Run("Logout successfully", func() {
		s.authActionMock.EXPECT().
			DeleteSession(gomock.Any(), "1", "session-123").
			Return(nil).
			AnyTimes()

		s.authActionMock.EXPECT().
			RevokeRefreshToken(gomock.Any(), "refresh-token-123").
			Return(nil).
			AnyTimes()

		err := s.authService.Logout(context.Background(), "1", "session-123", "refresh-token-123")
		s.Require().NoError(err)
	})
}
