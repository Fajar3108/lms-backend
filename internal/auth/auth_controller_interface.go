package auth

import (
	"github.com/gofiber/fiber/v3"
)

type AuthControllerInterface interface {
	Register(ctx fiber.Ctx) error
	Login(ctx fiber.Ctx) error
	Refresh(ctx fiber.Ctx) error
	Me(ctx fiber.Ctx) error
	Logout(ctx fiber.Ctx) error
}
