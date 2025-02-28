package repository

import (
	"context"

	"github.com/redis/go-redis/v9"
)

type RedisAuthKeyValueRepository struct {
	client *redis.Client
}

func NewRedisAuthKeyValueRepository(c *redis.Client) RedisAuthKeyValueRepository {
	return RedisAuthKeyValueRepository{client: c}
}

func (r *RedisAuthKeyValueRepository) updateUserStatus(email, status string) error {
	ctx := context.Background()
	err := r.client.Set(ctx, email, status, 0)
	return err.Err()
}

func (r *RedisAuthKeyValueRepository) IsUserLogged(email string) (bool, error) {
	ctx := context.Background()
	status, err := r.client.Get(ctx, email).Result()
	if err != nil {
		return false, err
	}
	return status == "logged", nil
}

func (r *RedisAuthKeyValueRepository) LoginUser(email string) error {
	return r.updateUserStatus(email, "logged")
}

func (r *RedisAuthKeyValueRepository) LogoutUser(email string) error {
	return r.updateUserStatus(email, "unlogged")
}
