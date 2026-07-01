package router

import (
	"github.com/fajar3108/lms-backend/internal/auth"
	"github.com/fajar3108/lms-backend/internal/user"
	"github.com/fajar3108/lms-backend/pkg/middleware"
	pkgredis "github.com/fajar3108/lms-backend/pkg/redis"
	"github.com/fajar3108/lms-backend/pkg/token"
	"github.com/fajar3108/lms-backend/pkg/validation"
	"github.com/gofiber/fiber/v3"
	"github.com/redis/go-redis/v9"
	"gorm.io/gorm"
)

func AuthRouter(route fiber.Router, jwtManager *token.JWTManager, db *gorm.DB, redisClient *redis.Client, validator *validation.Validator) {
	redisWrapper := pkgredis.NewGoRedisWrapper(redisClient)
	authActions := auth.NewAuthAction(db, redisWrapper)
	userAction := user.NewUserAction(db)
	authService := auth.NewAuthService(authActions, userAction, jwtManager)
	authCtrl := auth.NewAuthController(authService, validator)

	authGroup := route.Group("/auth")
	authGroup.Post("/register", authCtrl.Register)
	authGroup.Post("/login", authCtrl.Login)
	authGroup.Post("/refresh", authCtrl.Refresh)
	authGroup.Post("/logout", middleware.AuthRequired(jwtManager, redisClient), authCtrl.Logout)

	authGroup.Get("/me", middleware.AuthRequired(jwtManager, redisClient), authCtrl.Me)
}
