package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"

	"medods/internal/api"
	"medods/internal/auth"
	"medods/internal/storage/postgresClient"
)

func LogoutHandler(as auth.AuthService, ps postgresClient.PostgresClient, logger *zap.Logger) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		token := ctx.Value(auth.ContextKeyToken).(*jwt.Token)

		jti, err := as.ExtractJTI(token)
		if err != nil {
			api.WriteError(w, logger, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			logger.Error("LogoutHandler: failed to extract JTI", zap.Error(err))
			return
		}

		exp, err := as.ExtractExpiration(token)
		if err != nil {
			api.WriteError(w, logger, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			logger.Error("LogoutHandler: failed to extract expiration", zap.Error(err))
			return
		}

		err = ps.StoreTokenToBlacklist(ctx, jti, exp)
		if err != nil {
			api.WriteError(w, logger, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			logger.Error("LogoutHandler: failed to store token to blacklist", zap.Error(err))
			return
		}

		guid, err := as.ExtractGUID(token)
		if err != nil {
			api.WriteError(w, logger, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			logger.Error("LogoutHandler: failed to extract GUID", zap.Error(err))
			return
		}

		err = ps.DeleteRefreshTokenHash(ctx, guid)
		if err != nil {
			api.WriteError(w, logger, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			logger.Error("LogoutHandler: failed to delete refresh token hash", zap.Error(err))
			return
		}

		writeOK(w, logger)
		logger.Info("LogoutHandler: successfully logged out")
	}
}

func writeOK(w http.ResponseWriter, logger *zap.Logger) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	err := json.NewEncoder(w).Encode(struct {
		Status string
	}{
		Status: http.StatusText(http.StatusOK),
	})
	if err != nil {
		logger.Error("writeOK: failed to encoding response", zap.Error(err))
	}
}
