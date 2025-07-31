package middleware

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"go.uber.org/zap"

	"medods/internal/api"
	"medods/internal/auth"
)

const bearerPrefix = "Bearer "

func AuthMiddleware(authService auth.AuthService, logger *zap.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			header, err := getAuthorizationHeader(r)
			if err != nil {
				api.WriteErrorResponse(w, logger, "No authorization header found", http.StatusUnauthorized)
				logger.Error("AuthMiddleware:", zap.Error(err))
				return
			}

			tokenString, err := extractToken(header)
			if err != nil {
				api.WriteErrorResponse(w, logger, "Invalid authorization header format", http.StatusUnauthorized)
				logger.Error("AuthMiddleware: ", zap.Error(err))
				return
			}

			token, err := authService.ParseToken(tokenString)
			if err != nil {
				api.WriteErrorResponse(w, logger, "Invalid token", http.StatusUnauthorized)
				logger.Error("AuthMiddleware:", zap.Error(err))
				return
			}

			if !token.Valid {
				api.WriteErrorResponse(w, logger, "No valid token", http.StatusUnauthorized)
				logger.Error("AuthMiddleware: no valid token")
				return
			}

			ctx := context.WithValue(r.Context(), "token", token)
			r = r.WithContext(ctx)

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
