# Tech Stack
- Language: Go (Golang)
- Framework: Fiber v3
- ORM: GORM
- Config: Viper (reading from .env)
- Authentication: JWT (golang-jwt/v5) with Refresh Token Rotation
- Validation: Go Playground Validator v10
- Email: Gomail v2

# Projects Structure
.
├── cmd/
│   ├── api/main.go                     # API application entry point
├── config/                             # Viper setup & .env constants
├── database/                           # Database / Redis Connection
├── internal/
|   ├── auth/                           # Auth Modules
|   │   ├── auth_action.go              # Repository implementation (not knowing fiber)
|   │   ├── auth_action_interface.go    # Repository interface
|   │   ├── auth_service.go             # Service Implementation. (not knowing fiber&gorm)
|   │   ├── auth_service_interface.go   # Service Interface.
|   │   ├── auth_controller.go          # HTTP Controller Implementation.
|   │   ├── auth_controller_interface.go# HTTP Controller Interface.
|   │   ├── auth_request.go             # Structs for request body validation.
|   │   ├── auth_resource               # Structs for response transformation (DTOs).
|   |   └── auth_error                  # Error Declaration
│   ├── router/                         # Fiber route definitions (Auth, Category, etc).
├── pkg/
│   ├── error-handler/                  # Custom http error definitions & global error handler.
│   ├── app-error/                      # Custom app error.
│   ├── helpers/                        # Utility functions (encrpyt, pagination, resource collection, UUID, slug, response).
│   ├── mail/                           # Email sending helper.
│   ├── middleware/                     # Custom middleware (e.g., JWT).
│   ├── token/                          # JWT generation & parsing.
│   └── validation/                     # Form Validation
├── storage/                            # (gitignored) Uploaded files are stored here.
├── .env.example                        # Configuration file template.
└── go.mod                              # Go dependencies.
