package auth

import (
	"net/http"

	"github.com/fajar3108/lms-backend/pkg/helpers"
	"github.com/fajar3108/lms-backend/pkg/validation"
	"github.com/gofiber/fiber/v3"
)

type AuthController struct {
	service   AuthServiceInterace
	validator *validation.Validator
}

func NewAuthController(service AuthServiceInterace, validator *validation.Validator) *AuthController {
	return &AuthController{
		service:   service,
		validator: validator,
	}
}

func (ctrl *AuthController) Register(c fiber.Ctx) error {
	var req RegisterRequest
	if err := validation.RequestBind(c, &req); err != nil {
		return err
	}

	result, err := ctrl.service.Register(c.Context(), &req)
	if err != nil {
		return err
	}

	resp := helpers.NewAPIResponse(http.StatusCreated, "User registered successfully").Success(result, nil, nil)
	return c.Status(resp.StatusCode).JSON(resp)
}

func (ctrl *AuthController) Login(c fiber.Ctx) error {
	var req LoginRequest
	if err := validation.RequestBind(c, &req); err != nil {
		return err
	}

	res, err := ctrl.service.Login(c.Context(), &req)
	if err != nil {
		return err
	}

	resp := helpers.NewAPIResponse(http.StatusOK, "Authentication successful").Success(res, nil, nil)
	return c.Status(resp.StatusCode).JSON(resp)
}

func (ctrl *AuthController) Refresh(c fiber.Ctx) error {
	var req RefreshTokenRequest
	if err := validation.RequestBind(c, &req); err != nil {
		return err
	}

	res, err := ctrl.service.RefreshToken(c.Context(), &req)
	if err != nil {
		return err
	}

	resp := helpers.NewAPIResponse(http.StatusOK, "Tokens rotated successfully").Success(res, nil, nil)
	return c.Status(resp.StatusCode).JSON(resp)
}

func (ctrl *AuthController) Me(c fiber.Ctx) error {
	userID, ok := c.Locals("userID").(string)
	if !ok || userID == "" {
		return fiber.NewError(fiber.StatusUnauthorized, "unauthorized session")
	}

	res, err := ctrl.service.GetProfile(c.Context(), userID)
	if err != nil {
		return err
	}

	resp := helpers.NewAPIResponse(http.StatusOK, "Profile details retrieved successfully").Success(res, nil, nil)
	return c.Status(resp.StatusCode).JSON(resp)
}

func (ctrl *AuthController) Logout(c fiber.Ctx) error {
	userID, ok := c.Locals("userID").(string)
	if !ok || userID == "" {
		return fiber.NewError(fiber.StatusUnauthorized, "unauthorized session")
	}

	sessionID, ok := c.Locals("sessionID").(string)
	if !ok || sessionID == "" {
		return fiber.NewError(fiber.StatusUnauthorized, "unauthorized session")
	}

	var req LogoutRequest
	if err := validation.RequestBind(c, &req); err != nil {
		return err
	}

	err := ctrl.service.Logout(c.Context(), userID, sessionID, req.RefreshToken)
	if err != nil {
		return err
	}

	resp := helpers.NewAPIResponse(http.StatusOK, "Logout successful")
	return c.Status(resp.StatusCode).JSON(resp)
}
