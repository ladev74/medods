package handlers

import (
	"net/http"

	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"

	"medods/internal/api"
	"medods/internal/auth"
	"medods/internal/storage/postgresClient"
)

// LogoutHandler выполняет выход пользователя, занося текущий токен в черный список.
// @Summary Выход пользователя
// @Description Инвалидирует access и refresh токены
// @Tags Auth
// @Produce json
// @Security BearerAuth
// @Success 200 {object} api.OKResponse
// @Failure 401 {object} api.ErrorResponse
// @Failure 500 {object} api.ErrorResponse
// @Router /auth/logout [post]
func LogoutHandler(as auth.AuthService, ps postgresClient.PostgresClient, logger *zap.Logger) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		token := ctx.Value(auth.ContextKeyToken).(*jwt.Token)

		jti, guid, exp, err := as.ExtractAccessTokenMetadata(token)
		if err != nil {
			api.WriteError(w, logger, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			logger.Error("LogoutHandler: failed to extract access token metadata", zap.String("guid", guid), zap.Error(err))
			return
		}

		err = ps.StoreTokenToBlacklist(ctx, jti, exp)
		if err != nil {
			api.WriteError(w, logger, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			logger.Error("LogoutHandler: failed to store token to blacklist", zap.String("guid", guid), zap.Error(err))
			return
		}

		err = ps.DeleteRefreshTokenHash(ctx, guid)
		if err != nil {
			api.WriteError(w, logger, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			logger.Error("LogoutHandler: failed to delete refresh token hash", zap.String("guid", guid), zap.Error(err))
			return
		}

		api.WriteOK(w, logger)
		logger.Info("LogoutHandler: successfully logged out", zap.String("guid", guid))
	}
}
