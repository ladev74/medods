package auth

import (
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
)

func New(config *Config, logger *zap.Logger) *Auth {
	return &Auth{
		config: config,
		logger: logger,
	}
}

func (a *Auth) GenerateTokenPair(guid string) (string, string, error) {
	jti := uuid.New().String()

	accessToken, err := a.generateAccessToken(guid, jti)
	if err != nil {
		a.logger.Error("GenerateTokenPair: failed to generate access token", zap.Error(err))
		return "", "", fmt.Errorf("GenerateTokenPair: failed to generate access token: %w", err)
	}

	refreshToken, err := a.generateRefreshToken(guid, jti)
	if err != nil {
		a.logger.Error("GenerateTokenPair: failed to generate refresh token", zap.Error(err))
		return "", "", fmt.Errorf("GenerateTokenPair: failed to generate refresh token: %w", err)
	}

	return accessToken, refreshToken, nil
}

func (a *Auth) generateAccessToken(guid string, jti string) (string, error) {
	ttl := time.Now().Add(a.config.AccessTokenTTL).Unix()

	token := a.generateJWT(guid, ttl, jti)

	signedToken, err := token.SignedString([]byte(a.config.TokenSecret))
	if err != nil {
		a.logger.Error("GenerateAccessToken: failed to sign access token", zap.Error(err))
		return "", fmt.Errorf("GenerateAccessToken: failed to sign access token: %w", err)
	}

	return signedToken, nil
}

func (a *Auth) generateRefreshToken(guid string, jti string) (string, error) {
	ttl := time.Now().Add(a.config.RefreshTokenTTL).Unix()

	token := a.generateJWT(guid, ttl, jti)

	signedToken, err := token.SignedString([]byte(a.config.TokenSecret))
	if err != nil {
		a.logger.Error("GenerateRefreshToken: failed to sign refresh token", zap.Error(err))
		return "", fmt.Errorf("GenerateRefreshToken: failed to sign refresh token: %w", err)
	}

	return signedToken, nil
}

func (a *Auth) HashRefreshToken(token string) ([]byte, error) {
	shaHash := a.GenerateShaHash(token)

	hash, err := bcrypt.GenerateFromPassword(shaHash[:], bcrypt.DefaultCost)
	if err != nil {
		a.logger.Error("HashRefreshToken: failed to hash refresh token", zap.Error(err))
		return nil, fmt.Errorf("HashRefreshToken: failed to hash refresh token: %w", err)
	}

	return hash, nil
}

func (a *Auth) GenerateShaHash(refreshToken string) [32]byte {
	shaHash := sha256.Sum256([]byte(refreshToken))
	return shaHash
}

func (a *Auth) ParseToken(tokenString string) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if token.Method.Alg() != SigningMethod.Alg() {
			a.logger.Error("ParseToken: unexpected signing method", zap.Any("alg", token.Header["alg"]))
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

	guid, ok := claims[claimsSub].(string)
	if !ok || guid == "" {
		a.logger.Error("ExtractGUID: GUID not found in token")
		return "", fmt.Errorf("ExtractGUID: GUID not found in token")
	}

	return guid, nil
}

func (a *Auth) ExtractJTI(token *jwt.Token) (string, error) {
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		a.logger.Error("ExtractJTI: invalid token claims")
		return "", fmt.Errorf("ExtractJTI: invalid token claims")
	}

	jti, ok := claims[claimsJTI].(string)
	if !ok || jti == "" {
		a.logger.Error("ExtractJTI: JTI not found in token")
		return "", fmt.Errorf("ExtractJTI: JTI not found in token")
	}

	return jti, nil
}

func (a *Auth) ExtractExpiration(token *jwt.Token) (*time.Time, error) {
	exp, err := token.Claims.GetExpirationTime()
	if err != nil || exp == nil {
		a.logger.Error("ExtractExpiration: expiration not found in token")
		return nil, fmt.Errorf("ExtractExpiration: expiration not found in token")
	}

	return &exp.Time, nil
}

func (a *Auth) generateJWT(guid string, ttl int64, jti string) *jwt.Token {
	token := jwt.NewWithClaims(SigningMethod,
		jwt.MapClaims{
			claimsJTI: jti,
			claimsSub: guid,
			claimsExp: ttl,
		},
	)

	return token
}
