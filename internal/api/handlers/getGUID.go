package handlers

import (
	"net/http"

	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"

	"medods/internal/api"
	"medods/internal/auth"
)

func GetGUIDHandler(authService auth.AuthService, logger *zap.Logger) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		token, ok := r.Context().Value("token").(*jwt.Token)
		if !ok {
			api.WriteErrorResponse(w, logger, "GUID not found in token", http.StatusUnauthorized)
			logger.Error("GetGUIDHandler: GUID not found in token")
			return
		}

		guid, err := authService.ExtractGUID(token)
		if err != nil {
			api.WriteErrorResponse(w, logger, "Cannot get GUID from token", http.StatusUnauthorized)
			logger.Error("GetGUIDHandler: failed to extract GUID:", zap.Error(err))
			return
		}

		api.WriteSuccessResponseWithGUID(w, logger, guid)
	}
}
