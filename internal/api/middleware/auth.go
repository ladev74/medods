package middleware

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"go.uber.org/zap"

	"authentication-service/internal/api"
	"authentication-service/internal/auth"
	"authentication-service/internal/storage/postgresClient"
)

const bearerPrefix = "Bearer "

func AuthMiddleware(as auth.AuthService, ps postgresClient.PostgresClient, logger *zap.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			header, err := getAuthorizationHeader(r)
			if err != nil {
				api.WriteError(w, logger, "No authorization header found", http.StatusUnauthorized)
				logger.Error("AuthMiddleware:", zap.Error(err))
				return
			}

			tokenString, err := extractToken(header)
			if err != nil {
				api.WriteError(w, logger, "Invalid authorization header format", http.StatusUnauthorized)
				logger.Error("AuthMiddleware:", zap.Error(err))
				return
			}

			token, err := as.ParseToken(tokenString)
			if err != nil {
				api.WriteError(w, logger, "Invalid token", http.StatusUnauthorized)
				logger.Error("AuthMiddleware: invalid token", zap.Error(err))
				return
			}

			if !token.Valid {
				api.WriteError(w, logger, "No valid token", http.StatusUnauthorized)
				logger.Error("AuthMiddleware: no valid token")
				return
			}

			jti, err := as.ExtractJTI(token)
			if err != nil {
				api.WriteError(w, logger, "Invalid token", http.StatusUnauthorized)
				logger.Error("AuthMiddleware: failed to extract JTI", zap.Error(err))
				return
			}

			isBlacklisted, err := ps.IsBlacklisted(ctx, jti)
			if err != nil {
				api.WriteError(w, logger, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				logger.Error("AuthMiddleware: failed to check whether blacklisted", zap.Error(err))
				return
			}

			if isBlacklisted {
				api.WriteError(w, logger, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
				logger.Info("AuthMiddleware: token was blacklisted", zap.String("jti", jti))
				return
			}

			ctx = context.WithValue(ctx, auth.ContextKeyToken, token)
			r = r.WithContext(ctx)

			logger.Info("AuthMiddleware: authorization was successfully")

			next.ServeHTTP(w, r)
		}

		return http.HandlerFunc(fn)
	}
}

func getAuthorizationHeader(r *http.Request) (string, error) {
	header := r.Header.Get("Authorization")
	if header == "" {
		return "", fmt.Errorf("getAuthorizationHeader: no authorization header found")
	}

	return header, nil
}

func extractToken(header string) (string, error) {
	if !strings.HasPrefix(header, bearerPrefix) {
		return "", fmt.Errorf("extractToken: invalid authorization header format")
	}

	tokenString := strings.TrimPrefix(header, bearerPrefix)

	return tokenString, nil
}
