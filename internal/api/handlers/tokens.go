package handlers

import (
	"net/http"

	"go.uber.org/zap"

	"authentication-service/internal/api"
	"authentication-service/internal/auth"
	"authentication-service/internal/storage/postgresClient"
)

const guidKey = "guid"

// CreateTokensHandler создает новую пару токенов для указанного GUID.
// @Summary Создать токены
// @Description Генерирует access и refresh токены по GUID пользователя
// @Tags Auth
// @Produce json
// @Param guid query string true "GUID пользователя"
// @Success 200 {object} api.RespWithTokens
// @Failure 400 {object} api.ErrorResponse
// @Failure 500 {object} api.ErrorResponse
// @Router /auth/tokens [post]
func CreateTokensHandler(as auth.AuthService, ps postgresClient.PostgresClient, logger *zap.Logger) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

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

		userAgent := r.UserAgent()
		ip := r.RemoteAddr

		err = ps.StoreRefreshTokenHash(ctx, guid, hash, userAgent, ip)
		if err != nil {
			api.WriteError(w, logger, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			logger.Error("CreateTokensHandler: cannot store hash refresh token", zap.String("guid", guid), zap.Error(err))
			return
		}

		api.WriteWithTokens(w, logger, accessToken, refreshToken)
		logger.Info("CreateTokensHandler: successfully created and stored tokens", zap.String("guid", guid))
	}
}
