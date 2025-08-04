package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"

	"medods/internal/api"
	"medods/internal/auth"
)

func RefreshHandler(as auth.AuthService, logger *zap.Logger) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		refreshToken, err := decodeRefreshTokenFromRequest(r)
		if err != nil {
			api.WriteError(w, logger, "refresh token not found", http.StatusUnauthorized)
			logger.Error("RefreshHandler: failed to get refresh token", zap.Error(err))
			return
		}

		refreshHah, err := as.HashRefreshToken(refreshToken)
		if err != nil {
			api.WriteError(w, logger, "cannot hash refresh token", http.StatusInternalServerError)
			logger.Error("RefreshHandler:", zap.Error(err))
			return
		}
		_ = refreshHah

		accessToken, ok := ctx.Value(auth.ContextKeyToken).(*jwt.Token)
		if !ok {
			api.WriteError(w, logger, "access token not found", http.StatusUnauthorized)
			logger.Error("RefreshHandler: failed to get access token")
			return
		}

		guid, err := as.ExtractGUID(accessToken)
		if err != nil {
			api.WriteError(w, logger, "cannot get GUID from token", http.StatusUnauthorized)
			logger.Error("RefreshHandler: failed to extract GUID", zap.Error(err))
			return
		}
		_ = guid

		fmt.Println(r.UserAgent())
		fmt.Println(r.RemoteAddr)

		fmt.Println(accessToken)
		fmt.Println(refreshToken)
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
