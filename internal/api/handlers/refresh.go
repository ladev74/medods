package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"

	"medods/internal/api"
	"medods/internal/auth"
	"medods/internal/storage/postgresClient"
)

// TODO: Требования к операции refresh!!!

func RefreshHandler(as auth.AuthService, ps postgresClient.PostgresClient, logger *zap.Logger) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		accessToken := ctx.Value(auth.ContextKeyToken).(*jwt.Token)

		guid, err := as.ExtractGUID(accessToken)
		if err != nil {
			api.WriteError(w, logger, "cannot get GUID from token", http.StatusUnauthorized)
			logger.Error("RefreshHandler: failed to extract GUID", zap.Error(err))
			return
		}

		storedHash, err := ps.GetStoredRefreshHash(ctx, guid)
		if err != nil {
			api.WriteError(w, logger, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			logger.Error("RefreshHandler: failed to get hash", zap.Error(err))
			return
		}

		refreshToken, err := decodeRefreshTokenFromRequest(r)
		if err != nil {
			api.WriteError(w, logger, "refresh token not found", http.StatusUnauthorized)
			logger.Error("RefreshHandler: failed to get refresh token", zap.Error(err))
			return
		}

		shaHash := as.GenerateShaHash(refreshToken)

		err = bcrypt.CompareHashAndPassword(storedHash, shaHash[:])
		if err != nil {
			api.WriteError(w, logger, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			logger.Error("RefreshHandler: hashes not equal", zap.String("guid", guid), zap.Error(err))
			return
		}

		err = ps.DeleteRefreshTokenHash(ctx, guid)
		if err != nil {
			api.WriteError(w, logger, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			logger.Error("RefreshHandler: failed to delete hash", zap.String("guid", guid), zap.Error(err))
			return
		}

		jti, err := as.ExtractJTI(accessToken)
		if err != nil {
			api.WriteError(w, logger, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			logger.Error("RefreshHandler: failed to extract JTI", zap.String("guid", guid), zap.Error(err))
			return
		}

		exp, err := as.ExtractExpiration(accessToken)
		if err != nil {
			api.WriteError(w, logger, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			logger.Error("RefreshHandler: failed to extract expiration", zap.String("guid", guid), zap.Error(err))
			return
		}

		err = ps.StoreTokenToBlacklist(ctx, jti, exp)
		if err != nil {
			api.WriteError(w, logger, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			logger.Error("RefreshHandler: failed to store token to blacklist", zap.String("guid", guid), zap.Error(err))
			return
		}

		newAccessToken, newRefreshToken, err := as.GenerateTokenPair(guid)
		if err != nil {
			api.WriteError(w, logger, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			logger.Error("RefreshHandler: cannot generate access and refresh tokens", zap.String("guid", guid), zap.Error(err))
			return
		}

		newHash, err := as.HashRefreshToken(newRefreshToken)
		if err != nil {
			api.WriteError(w, logger, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			logger.Error("RefreshHandler: cannot generate hash refresh token", zap.String("guid", guid), zap.Error(err))
			return
		}

		err = ps.StoreRefreshTokenHash(r.Context(), guid, newHash)
		if err != nil {
			api.WriteError(w, logger, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			logger.Error("RefreshHandler: cannot store hash refresh token", zap.String("guid", guid), zap.Error(err))
			return
		}

		api.WriteWithTokens(w, logger, newAccessToken, newRefreshToken)
		logger.Info("RefreshHandler: successfully refreshed tokens", zap.String("guid", guid))
	}
}

func decodeRefreshTokenFromRequest(r *http.Request) (string, error) {
	resp := struct {
		RefreshToken string `json:"refresh_token"`
	}{}

	err := json.NewDecoder(r.Body).Decode(&resp)
	if err != nil {
		return "", err
	}

	return resp.RefreshToken, nil
}
