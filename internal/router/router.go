package router

import (
	"github.com/fajar3108/lms-backend/config"
	"github.com/fajar3108/lms-backend/pkg/token"
	"github.com/fajar3108/lms-backend/pkg/validation"
	"github.com/gofiber/fiber/v3"
	"github.com/redis/go-redis/v9"
	"gorm.io/gorm"
)

func SetupRoutes(app *fiber.App, cfg *config.Config, db *gorm.DB, redisClient *redis.Client, validator *validation.Validator) {
	jwtManager := token.NewJWTManager(cfg.JWTSecretKey, cfg.JWTExpirationHours, cfg.JWTRefreshExpirationDays)

	api := app.Group("/api/v1")

	api.Get("/", func(c fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"message": "Welcome to the LMS API",
		})
	})

	AuthRouter(api, jwtManager, db, redisClient, validator)
}
