package handlers

import (
	"net/http"

	"go.uber.org/zap"

	"medods/internal/api"
	"medods/internal/auth"
	"medods/internal/storage/postgresClient"
)

func GetTokensHandler(authService auth.AuthService, ps postgresClient.PostgresClient, logger *zap.Logger) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		guid := r.URL.Query().Get("guid")
		if guid == "" {
			api.WriteErrorResponse(w, logger, "guid must not be empty", http.StatusBadRequest)
			logger.Error("GetTokensHandler: empty guid in the query parameters")
			return
		}

		accessToken, err := authService.GenerateAccessToken(guid)
		if err != nil {
			api.WriteErrorResponse(w, logger, "cannot generate access token", http.StatusInternalServerError)
			logger.Error("GetTokensHandler:", zap.Error(err))
			return
		}

		refreshToken, err := authService.GenerateRefreshToken(guid)
		if err != nil {
			api.WriteErrorResponse(w, logger, "cannot generate refresh token", http.StatusInternalServerError)
			logger.Error("GetTokensHandler:", zap.Error(err))
			return
		}

		hash, err := authService.HashRefreshToken(refreshToken)
		if err != nil {
			api.WriteErrorResponse(w, logger, "cannot hash refresh token", http.StatusInternalServerError)
			logger.Error("GetTokensHandler:", zap.Error(err))
			return
		}

		err = ps.StoreRefreshTokenHash(r.Context(), guid, hash)
		if err != nil {
			api.WriteErrorResponse(w, logger, "cannot store hash", http.StatusInternalServerError)
			logger.Error("GetTokensHandler:", zap.Error(err))
			return
		}

		api.WriteSuccessResponse(w, logger, accessToken, refreshToken)
	}
}
