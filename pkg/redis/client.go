package redis

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

type RedisClient interface {
	Get(ctx context.Context, key string) (string, error)
	Set(ctx context.Context, key string, value string, expiration time.Duration) error
	Del(ctx context.Context, key string) error
}

type GoRedisWrapper struct {
	client *redis.Client
}

func NewGoRedisWrapper(client *redis.Client) *GoRedisWrapper {
	return &GoRedisWrapper{client: client}
}

func (w *GoRedisWrapper) Get(ctx context.Context, key string) (string, error) {
	return w.client.Get(ctx, key).Result()
}

func (w *GoRedisWrapper) Set(ctx context.Context, key string, value string, expiration time.Duration) error {
	return w.client.Set(ctx, key, value, expiration).Err()
}

func (w *GoRedisWrapper) Del(ctx context.Context, key string) error {
	return w.client.Del(ctx, key).Err()
}
