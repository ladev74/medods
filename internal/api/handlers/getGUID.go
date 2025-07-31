package handlers

import (
	"net/http"

	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"

	"medods/internal/api"
)

func GetGUIDHandler(logger *zap.Logger) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		token, ok := r.Context().Value("token").(*jwt.Token)
		if !ok {
			api.WriteErrorResponse(w, logger, "guid not found in token", http.StatusUnauthorized)
			logger.Error("GetGUIDHandler: guid not found in token")
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			api.WriteErrorResponse(w, logger, "Invalid token claims", http.StatusUnauthorized)
			logger.Error("GetGUIDHandler: invalid token claims")
			return
		}

		guid, ok := claims["GUID"].(string)
		if !ok || guid == "" {
			api.WriteErrorResponse(w, logger, "GUID not found in token", http.StatusUnauthorized)
			logger.Error("GetGUIDHandler: GUID not found in token")
			return
		}

		api.WriteSuccessResponseWithGUID(w, logger, guid)
	}
}
