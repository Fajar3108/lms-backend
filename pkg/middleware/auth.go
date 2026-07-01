package middleware

import (
	"strings"

	errorhandler "github.com/fajar3108/lms-backend/pkg/error-handler"
	"github.com/fajar3108/lms-backend/pkg/token"
	"github.com/gofiber/fiber/v3"
	"github.com/redis/go-redis/v9"
)

func AuthRequired(jwtManager *token.JWTManager, redisClient *redis.Client) fiber.Handler {
	return func(c fiber.Ctx) error {
		authHeader := c.Get("Authorization")
		if authHeader == "" {
			return errorhandler.GlobalErrorHandler(c, fiber.NewError(fiber.StatusUnauthorized, "missing authorization header"))
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			return errorhandler.GlobalErrorHandler(c, fiber.NewError(fiber.StatusUnauthorized, "authorization header must be in 'Bearer <token>' format"))
		}

		tokenStr := parts[1]
		claims, err := jwtManager.VerifyToken(tokenStr)
		if err != nil {
			return errorhandler.GlobalErrorHandler(c, fiber.NewError(fiber.StatusUnauthorized, "invalid or expired access token"))
		}

		// Verify session in Redis
		key := "session:" + claims.UserID + ":" + claims.ID
		exists, err := redisClient.Exists(c.Context(), key).Result()
		if err != nil || exists == 0 {
			return errorhandler.GlobalErrorHandler(c, fiber.NewError(fiber.StatusUnauthorized, "invalid or expired access token"))
		}

		c.Locals("userID", claims.UserID)
		c.Locals("sessionID", claims.ID)

		return c.Next()
	}
}
