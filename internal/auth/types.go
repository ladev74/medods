package auth

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"
)

var signatureType = jwt.SigningMethodHS512

type Config struct {
	TokenSecret     string        `env:"TOKEN_SECRET"`
	AccessTokenTTL  time.Duration `env:"ACCESS_TOKEN_TTL"`
	RefreshTokenTTL time.Duration `env:"REFRESH_TOKEN_TTL"`
}

type Auth struct {
	config *Config
	logger *zap.Logger
}

type AuthService interface {
	GenerateAccessToken(string) (string, error)
	GenerateRefreshToken(string) (string, error)
	HashRefreshToken(string) ([]byte, error)
}
