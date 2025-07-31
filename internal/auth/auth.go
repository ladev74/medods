package auth

import (
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
)

func New(config *Config, logger *zap.Logger) *Auth {
	return &Auth{
		config: config,
		logger: logger,
	}
}

func (a *Auth) GenerateAccessToken(guid string) (string, error) {
	ttl := time.Now().Add(a.config.AccessTokenTTL).Unix()

	token := a.generateJWT(guid, ttl)

	signedToken, err := token.SignedString([]byte(a.config.TokenSecret))
	if err != nil {
		a.logger.Error("GenerateAccessToken: failed to sign access token", zap.Error(err))
		return "", fmt.Errorf("GenerateAccessToken: failed to sign access token: %w", err)
	}

	return signedToken, nil
}

func (a *Auth) GenerateRefreshToken(guid string) (string, error) {
	ttl := time.Now().Add(a.config.RefreshTokenTTL).Unix()

	token := a.generateJWT(guid, ttl)

	signedToken, err := token.SignedString([]byte(a.config.TokenSecret))
	if err != nil {
		a.logger.Error("GenerateRefreshToken: failed to sign refresh token", zap.Error(err))
		return "", fmt.Errorf("GenerateRefreshToken: failed to sign refresh token: %w", err)
	}

	return signedToken, nil
}

func (a *Auth) HashRefreshToken(token string) ([]byte, error) {
	shaHash := sha256.Sum256([]byte(token))

	hash, err := bcrypt.GenerateFromPassword(shaHash[:], bcrypt.DefaultCost)
	if err != nil {
		a.logger.Error("HashRefreshToken: failed to hash refresh token", zap.Error(err))
		return nil, fmt.Errorf("HashRefreshToken: failed to hash refresh token: %w", err)
	}

	return hash, nil
}

func (a *Auth) generateJWT(guid string, ttl int64) *jwt.Token {
	return jwt.NewWithClaims(signatureType,
		jwt.MapClaims{
			"GUID": guid,
			"exp":  ttl,
		})
}
