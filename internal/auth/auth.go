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

func (a *Auth) ParseToken(tokenString string) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if token.Method.Alg() != SignatureType.Alg() {
			return nil, fmt.Errorf("ParseToken: unexpected signing method: %v", token.Header["alg"])
		}

		return []byte(a.config.TokenSecret), nil
	})
	if err != nil {
		a.logger.Error("ParseToken: invalid authorization header format", zap.Error(err))
		return nil, fmt.Errorf("ParseToken: invalid authorization header format: %w", err)
	}

	return token, nil
}

func (a *Auth) ExtractGUID(token *jwt.Token) (string, error) {
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		a.logger.Error("ExtractGUID: invalid token claims")
		return "", fmt.Errorf("ExtractGUID: invalid token claims")
	}

	guid, ok := claims["GUID"].(string)
	if !ok || guid == "" {
		a.logger.Error("ExtractGUID: GUID not found in token")
		return "", fmt.Errorf("ExtractGUID: GUID not found in token")
	}

	return guid, nil
}

func (a *Auth) generateJWT(guid string, ttl int64) *jwt.Token {
	return jwt.NewWithClaims(SignatureType,
		jwt.MapClaims{
			"GUID": guid,
			"exp":  ttl,
		})
}
