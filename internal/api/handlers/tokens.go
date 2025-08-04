package handlers

import (
	"net/http"

	"go.uber.org/zap"

	"medods/internal/api"
	"medods/internal/auth"
	"medods/internal/storage/postgresClient"
)

const guidKey = "guid"

func CreateTokensHandler(as auth.AuthService, ps postgresClient.PostgresClient, logger *zap.Logger) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		guid := r.URL.Query().Get(guidKey)
		if guid == "" {
			api.WriteError(w, logger, "guid must not be empty", http.StatusBadRequest)
			logger.Error("CreateTokensHandler: empty guid in the query parameters")
			return
		}

		accessToken, refreshToken, err := as.GenerateTokenPair(guid)
		if err != nil {
			api.WriteError(w, logger, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			logger.Error("CreateTokensHandler: cannot generate access and refresh tokens", zap.String("guid", guid), zap.Error(err))
			return
		}

		hash, err := as.HashRefreshToken(refreshToken)
		if err != nil {
			api.WriteError(w, logger, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			logger.Error("CreateTokensHandler: cannot generate hash refresh token", zap.String("guid", guid), zap.Error(err))
			return
		}

		err = ps.StoreRefreshTokenHash(r.Context(), guid, hash)
		if err != nil {
			api.WriteError(w, logger, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			logger.Error("CreateTokensHandler: cannot store hash refresh token", zap.String("guid", guid), zap.Error(err))
			return
		}

		api.WriteWithTokens(w, logger, accessToken, refreshToken)
		logger.Info("CreateTokensHandler: successfully created and stored tokens", zap.String("guid", guid))
	}
}
