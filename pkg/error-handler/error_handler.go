package errorhandler

import (
	"errors"
	"log/slog"

	app_error "github.com/fajar3108/lms-backend/pkg/app-error"
	"github.com/fajar3108/lms-backend/pkg/helpers"
	"github.com/gofiber/fiber/v3"
)

func GlobalErrorHandler(ctx fiber.Ctx, err error) error {
	var res *helpers.APIResponse

	switch e := err.(type) {
	case *ValidationError:
		res = helpers.NewAPIResponse(fiber.StatusBadRequest, err.Error()).
			Error("VALIDATION_ERROR", e.Details, nil)
	}

	var appErr *app_error.AppError

	if errors.As(err, &appErr) {
		statusCode := statusFromKind(appErr.Kind)
		res = helpers.NewAPIResponse(statusCode, appErr.Message).
			Error(appErr.Code, nil, nil)
	}

	var fiberError *fiber.Error

	if errors.As(err, &fiberError) {
		res = helpers.NewAPIResponse(fiberError.Code, fiberError.Message).
			Error("HTTP_ERROR", nil, nil)
	}

	if res == nil {
		res = helpers.NewAPIResponse(fiber.StatusInternalServerError, "internal server error").
			Error("INTERNAL_SERVER_ERROR", nil, err)
	}

	slog.Error(
		"request failed",
		"method", ctx.Method(),
		"path", ctx.Path(),
		"status", res.StatusCode,
		"error", err,
	)

	return ctx.Status(res.StatusCode).JSON(res)
}

func statusFromKind(kind app_error.Kind) int {

	switch kind {
	case app_error.KindNotFound:
		return fiber.StatusNotFound

	case app_error.KindConflict:
		return fiber.StatusConflict

	case app_error.KindUnauthorized:
		return fiber.StatusUnauthorized

	case app_error.KindForbidden:
		return fiber.StatusForbidden

	case app_error.KindInvalidArgument:
		return fiber.StatusBadRequest

	default:
		return fiber.StatusInternalServerError
	}
}
