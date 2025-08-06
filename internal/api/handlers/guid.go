package handlers

import (
	"net/http"

	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"

	"medods/internal/api"
	"medods/internal/auth"
)

// GetGUIDHandler возвращает GUID пользователя, извлечённый из JWT токена.
// @Summary Получить GUID пользователя
// @Description Извлекает GUID из access token и возвращает его
// @Tags User
// @Produce json
// @Security BearerAuth
// @Success 200 {object} api.GUIDResponse
// @Failure 401 {object} api.ErrorResponse
// @Failure 500 {object} api.ErrorResponse
// @Router /auth/guid [post]
func GetGUIDHandler(as auth.AuthService, logger *zap.Logger) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		token := ctx.Value(auth.ContextKeyToken).(*jwt.Token)

		guid, err := as.ExtractGUID(token)
		if err != nil {
			api.WriteError(w, logger, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			logger.Error("GetGUIDHandler: failed to extract GUID:", zap.Error(err))
			return
		}

		api.WriteWithGUID(w, logger, guid)
		logger.Info("GetGUIDHandler: successfully returned GUID", zap.String("guid", guid))
	}
}
