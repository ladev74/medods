package auth

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
)

var signatureType = jwt.SigningMethodHS512

type Config struct {
	TokenSecret     string        `env:"TOKEN_SECRET"`
	AccessTokenTTL  time.Duration `env:"ACCESS_TOKEN_TTL"`
	RefreshTokenTTL time.Duration `env:"REFRESH_TOKEN_TTL"`
}

type AuthService struct {
	config *Config
	logger *zap.Logger
}

func New(config *Config, logger *zap.Logger) *AuthService {
	return &AuthService{
		config: config,
		logger: logger,
	}
}

func (a *AuthService) GenerateAccessToken(guid string) (string, error) {
	ttl := time.Now().Add(a.config.AccessTokenTTL).Unix()

	token := a.generateJWT(guid, ttl)

	signedToken, err := token.SignedString([]byte(a.config.TokenSecret))
	if err != nil {
		a.logger.Error("GenerateAccessToken: failed to sign access token", zap.Error(err))
		return "", fmt.Errorf("GenerateAccessToken: failed to sign access token: %w", err)
	}

	return signedToken, nil
}

func (a *AuthService) GenerateRefreshToken(guid string) (string, error) {
	ttl := time.Now().Add(a.config.RefreshTokenTTL).Unix()

	token := a.generateJWT(guid, ttl)

	signedToken, err := token.SignedString([]byte(a.config.TokenSecret))
	if err != nil {
		a.logger.Error("GenerateRefreshToken: failed to sign refresh token", zap.Error(err))
		return "", fmt.Errorf("GenerateRefreshToken: failed to sign refresh token: %w", err)
	}

	return signedToken, nil
}

func (a *AuthService) HashRefreshToken(token string) ([]byte, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(token), bcrypt.DefaultCost)
	if err != nil {
		a.logger.Error("HashRefreshToken: failed to hash refresh token", zap.Error(err))
		return nil, fmt.Errorf("HashRefreshToken: failed to hash refresh token: %w", err)
	}

	return hash, nil
}

func (a *AuthService) generateJWT(guid string, ttl int64) *jwt.Token {
	return jwt.NewWithClaims(signatureType,
		jwt.MapClaims{
			"GUID": guid,
			"exp":  ttl,
		})
}
