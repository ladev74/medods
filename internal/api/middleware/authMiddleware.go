package middleware

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"

	"medods/internal/api"
	"medods/internal/auth"
)

func AuthMiddleware(logger *zap.Logger, cfg *auth.Config) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			header := r.Header.Get("Authorization")
			if header == "" {
				api.WriteErrorResponse(w, logger, "No authorization header found", http.StatusUnauthorized)
				logger.Error("AuthMiddleware: no authorization header found")
				return
			}

			const bearerPrefix = "Bearer "

			if !strings.HasPrefix(header, bearerPrefix) {
				api.WriteErrorResponse(w, logger, "Invalid authorization header format", http.StatusUnauthorized)
				return
			}

			tokenString := strings.TrimPrefix(header, bearerPrefix)

			token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
				if token.Method != auth.SignatureType {
					return nil, fmt.Errorf("AuthMiddleware: unexpected signing method: %v", token.Header["alg"])
				}

				return []byte(cfg.TokenSecret), nil
			})
			if err != nil {
				logger.Error("AuthMiddleware: invalid authorization header format", zap.Error(err))
				api.WriteErrorResponse(w, logger, "Invalid authorization header format", http.StatusUnauthorized)
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
