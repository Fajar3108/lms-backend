package database

import (
	"context"
	"crypto/tls"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

func ConnectRedis(ctx context.Context, redisUrl string) (*redis.Client, error) {
	options, err := redis.ParseURL(redisUrl)

	if err != nil {
		return nil, fmt.Errorf("parse redis URL: %w", err)
	}

	if options.TLSConfig != nil {
		options.TLSConfig.MinVersion = tls.VersionTLS12
	}

	options.DialTimeout = 5 * time.Second
	options.ReadTimeout = 3 * time.Second
	options.WriteTimeout = 3 * time.Second

	client := redis.NewClient(options)

	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	if err := client.Ping(pingCtx).Err(); err != nil {
		_ = client.Close()

		return nil, fmt.Errorf("ping redis: %w", err)
	}

	return client, nil
}
