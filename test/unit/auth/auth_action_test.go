package auth_test

import (
	"context"
	"testing"
	"time"

	"github.com/fajar3108/lms-backend/internal/auth"
	"github.com/fajar3108/lms-backend/internal/user"
	"github.com/fajar3108/lms-backend/test/test_helper"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/suite"
	"gorm.io/gorm"
)

const (
	dummyID           = "existing-uuid-123"
	dummyName         = "Fajar"
	dummyEmail        = "fajar@example.com"
	dummyPassword     = "password123"
	dummyRefreshToken = "dumm-token"
)

type AuthActionTestSuite struct {
	suite.Suite
	db         *gorm.DB
	tx         *gorm.DB
	fakeRedis  *FakeRedisClient
	authAction *auth.AuthAction
}

func TestAuthActionSuite(t *testing.T) {
	suite.Run(t, new(AuthActionTestSuite))
}

func (s *AuthActionTestSuite) SetupSuite() {
	s.db = test_helper.NewTestDB(s.T())
}

func (s *AuthActionTestSuite) SetupSubTest() {
	s.tx = s.db.Begin()
	s.fakeRedis = NewFakeRedisClient()
	s.authAction = auth.NewAuthAction(s.tx, s.fakeRedis)
}

func (s *AuthActionTestSuite) TearDownSubTest() {
	s.tx.Rollback()
}

func (s *AuthActionTestSuite) seedDummyUser() user.User {
	user := user.User{
		ID:       dummyID,
		Name:     dummyName,
		Email:    dummyEmail,
		Password: dummyPassword,
	}
	s.Require().NoError(s.tx.Create(&user).Error)
	return user
}

func (s *AuthActionTestSuite) TestStoreRefreshToken() {
	s.Run("Store refresh token successfully", func() {
		user := s.seedDummyUser()

		rt, err := s.authAction.CreateRefreshToken(context.Background(), user.ID, dummyRefreshToken, time.Now().Add(24*time.Hour))

		s.Require().NoError(err)
		s.Require().NotNil(rt)
		s.NotEmpty(rt.ID)
		s.Equal(dummyRefreshToken, rt.Token)
		s.Equal(user.ID, rt.UserID)
		s.False(rt.IsRevoked)
	})
}

func (s *AuthActionTestSuite) TestFindRefreshToken() {
	s.Run("Find refresh token successfully", func() {
		user := s.seedDummyUser()

		rt, err := s.authAction.CreateRefreshToken(context.Background(), user.ID, dummyRefreshToken, time.Now().Add(24*time.Hour))

		s.Require().NoError(err)
		s.Require().NotNil(rt)

		found, err := s.authAction.FindRefreshToken(context.Background(), dummyRefreshToken)

		s.Require().NoError(err)
		s.Require().NotNil(found)
		s.Equal(rt.ID, found.ID)
		s.Equal(dummyRefreshToken, found.Token)
		s.Equal(user.ID, found.UserID)
		s.False(found.IsRevoked)
	})

	s.Run("Failed to find refresh token when not found", func() {
		found, err := s.authAction.FindRefreshToken(context.Background(), "notfound-token")

		s.Require().Error(err)
		s.ErrorIs(err, auth.ErrRefreshTokenNotFound)
		s.Nil(found)
	})
}

func (s *AuthActionTestSuite) TestRevokeAllUserRefreshTokens() {
	s.Run("Revoke all user refresh tokens successfully", func() {
		user := s.seedDummyUser()

		_, err := s.authAction.CreateRefreshToken(context.Background(), user.ID, dummyRefreshToken, time.Now().Add(24*time.Hour))
		s.Require().NoError(err)

		_, err = s.authAction.CreateRefreshToken(context.Background(), user.ID, "another-token", time.Now().Add(24*time.Hour))
		s.Require().NoError(err)

		err = s.authAction.RevokeAllUserRefreshTokens(context.Background(), user.ID)
		s.Require().NoError(err)

		found1, err := s.authAction.FindRefreshToken(context.Background(), dummyRefreshToken)
		s.Require().NoError(err)
		s.True(found1.IsRevoked)

		found2, err := s.authAction.FindRefreshToken(context.Background(), "another-token")
		s.Require().NoError(err)
		s.True(found2.IsRevoked)
	})
}

func (s *AuthActionTestSuite) TestRevokeRefreshToken() {
	s.Run("Revoke refresh token successfully", func() {
		user := s.seedDummyUser()

		rt, err := s.authAction.CreateRefreshToken(context.Background(), user.ID, dummyRefreshToken, time.Now().Add(24*time.Hour))
		s.Require().NoError(err)
		s.False(rt.IsRevoked)

		err = s.authAction.RevokeRefreshToken(context.Background(), dummyRefreshToken)
		s.Require().NoError(err)

		found, err := s.authAction.FindRefreshToken(context.Background(), dummyRefreshToken)
		s.Require().NoError(err)
		s.True(found.IsRevoked)
	})
}

func (s *AuthActionTestSuite) TestSessions() {
	s.Run("Manage session in Redis successfully", func() {
		sess := &auth.Session{
			ID:        "session-123",
			UserID:    "user-123",
			Token:     "access-token-123",
			ExpiresAt: time.Now().Add(1 * time.Hour),
		}

		// Get non-existing session
		found, err := s.authAction.GetSession(context.Background(), sess.UserID, sess.ID)
		s.Require().Error(err)
		s.Nil(found)

		// Create session
		err = s.authAction.CreateSession(context.Background(), sess)
		s.Require().NoError(err)

		// Get existing session
		found, err = s.authAction.GetSession(context.Background(), sess.UserID, sess.ID)
		s.Require().NoError(err)
		s.Require().NotNil(found)
		s.Equal(sess.ID, found.ID)
		s.Equal(sess.UserID, found.UserID)
		s.Equal(sess.Token, found.Token)

		// Delete session
		err = s.authAction.DeleteSession(context.Background(), sess.UserID, sess.ID)
		s.Require().NoError(err)

		// Verify deleted
		found, err = s.authAction.GetSession(context.Background(), sess.UserID, sess.ID)
		s.Require().Error(err)
		s.Nil(found)
	})
}

type FakeRedisClient struct {
	store map[string]string
}

func NewFakeRedisClient() *FakeRedisClient {
	return &FakeRedisClient{
		store: make(map[string]string),
	}
}

func (f *FakeRedisClient) Get(ctx context.Context, key string) (string, error) {
	val, ok := f.store[key]
	if !ok {
		return "", redis.Nil
	}
	return val, nil
}

func (f *FakeRedisClient) Set(ctx context.Context, key string, value string, expiration time.Duration) error {
	f.store[key] = value
	return nil
}

func (f *FakeRedisClient) Del(ctx context.Context, key string) error {
	delete(f.store, key)
	return nil
}
