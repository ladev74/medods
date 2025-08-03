package handlers

import (
	"encoding/json"
	"net/http"

	"go.uber.org/zap"

	"medods/internal/api"
	"medods/internal/auth"
	"medods/internal/storage/postgresClient"
)

func CreateTokensHandler(as auth.AuthService, ps postgresClient.PostgresClient, logger *zap.Logger) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		guid := r.URL.Query().Get("guid")
		if guid == "" {
			api.WriteError(w, logger, "guid must not be empty", http.StatusBadRequest)
			logger.Error("CreateTokensHandler: empty guid in the query parameters")
			return
		}

		accessToken, err := as.GenerateAccessToken(guid)
		if err != nil {
			api.WriteError(w, logger, "cannot generate access token", http.StatusInternalServerError)
			logger.Error("CreateTokensHandler:", zap.Error(err))
			return
		}

		refreshToken, err := as.GenerateRefreshToken(guid)
		if err != nil {
			api.WriteError(w, logger, "cannot generate refresh token", http.StatusInternalServerError)
			logger.Error("CreateTokensHandler:", zap.Error(err))
			return
		}

		hash, err := as.HashRefreshToken(refreshToken)
		if err != nil {
			api.WriteError(w, logger, "cannot hash refresh token", http.StatusInternalServerError)
			logger.Error("CreateTokensHandler:", zap.Error(err))
			return
		}

		err = ps.StoreRefreshTokenHash(r.Context(), guid, hash)
		if err != nil {
			api.WriteError(w, logger, "cannot store hash", http.StatusInternalServerError)
			logger.Error("CreateTokensHandler:", zap.Error(err))
			return
		}

		writeWithTokens(w, logger, accessToken, refreshToken)
		logger.Info("CreateTokensHandler: successfully created and stored tokens")
	}
}

func writeWithTokens(w http.ResponseWriter, logger *zap.Logger, accessToken string, refreshToken string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	err := json.NewEncoder(w).Encode(struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	})
	if err != nil {
		logger.Error("writeWithTokens: failed to encoding response", zap.Error(err))
	}
}
