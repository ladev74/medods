package config

import (
	"fmt"

	"github.com/ilyakaznacheev/cleanenv"

	"authentication-service/internal/api"
	"authentication-service/internal/auth"
	"authentication-service/internal/logger"
	"authentication-service/internal/storage/postgresClient"
)

type Config struct {
	HttpServer api.HttpServer
	Auth       auth.Config
	Postgres   postgresClient.Config
	Logger     logger.Config
}

func New(path string) (*Config, error) {
	var cfg Config

	if err := cleanenv.ReadConfig(path, &cfg); err != nil {
		return nil, fmt.Errorf("failed to read config: %w", err)
	}

	return &cfg, nil
}
