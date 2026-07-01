package config

import (
	"fmt"
	"reflect"

	"github.com/spf13/viper"
)

type Config struct {
	AppEnv                   string `mapstructure:"APP_ENV"`
	AppPort                  string `mapstructure:"APP_PORT"`
	JWTSecretKey             string `mapstructure:"JWT_SECRET_KEY"`
	JWTExpirationHours       int    `mapstructure:"JWT_EXPIRATION_HOURS"`
	JWTRefreshExpirationDays int    `mapstructure:"JWT_REFRESH_EXPIRATION_DAYS"`
	RedisURL                 string `mapstructure:"REDIS_URL"`
	DatabaseURL              string `mapstructure:"DATABASE_URL"`
	SMTPHost                 string `mapstructure:"SMTP_HOST"`
	SMTPPort                 int    `mapstructure:"SMTP_PORT"`
	SMTPUser                 string `mapstructure:"SMTP_USER"`
	SMTPPassword             string `mapstructure:"SMTP_PASSWORD"`
	SMTPSender               string `mapstructure:"SMTP_SENDER"`
}

func LoadConfig() (*Config, error) {
	viper.SetConfigFile(".env")
	viper.SetConfigType("env")
	viper.AutomaticEnv()

	viper.SetDefault("APP_PORT", "8080")
	viper.SetDefault("JWT_EXPIRATION_HOURS", 24)
	viper.SetDefault("JWT_REFRESH_EXPIRATION_DAYS", 14)
	viper.SetDefault("REDIS_URL", "redis://localhost:6379")
	_ = viper.ReadInConfig()

	t := reflect.TypeOf(Config{})
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		tag := field.Tag.Get("mapstructure")

		if tag != "" {
			_ = viper.BindEnv(tag)
		}
	}

	var cfg Config
	if err := viper.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("failed to decode configuration structure: %w", err)
	}

	return &cfg, nil
}
