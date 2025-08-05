package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"

	"medods/internal/api"
	"medods/internal/auth"
	"medods/internal/storage/postgresClient"
)

func RefreshHandler(as auth.AuthService, ps postgresClient.PostgresClient, cfg *api.HttpServer, logger *zap.Logger) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		accessToken := ctx.Value(auth.ContextKeyToken).(*jwt.Token)

		jti, guid, exp, err := as.ExtractAccessTokenMetadata(accessToken)
		if err != nil {
			api.WriteError(w, logger, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			logger.Error("RefreshHandler: failed to extract access token metadata", zap.String("guid", guid), zap.Error(err))
			return
		}

		storedHash, storedUserAgent, storedIp, err := ps.GetStoredRefreshTokenData(ctx, guid)
		if err != nil {
			api.WriteError(w, logger, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			logger.Error("RefreshHandler: failed to get hash", zap.Error(err))
			return
		}

		currentUserAgent := r.UserAgent()

		if currentUserAgent != storedUserAgent {
			api.WriteError(w, logger, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			logger.Error(
				"RefreshHandler: user agents not equal",
				zap.String("guid", guid),
				zap.String("currentUserAgent", currentUserAgent),
				zap.String("storedUserAgent", storedUserAgent),
			)

			err = ps.StoreTokenToBlacklist(ctx, jti, exp)
			if err != nil {
				api.WriteError(w, logger, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				logger.Error("RefreshHandler: failed to store token to blacklist", zap.String("guid", guid), zap.Error(err))
				return
			}

			err = ps.DeleteRefreshTokenHash(ctx, guid)
			if err != nil {
				api.WriteError(w, logger, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				logger.Error("RefreshHandler: failed to delete refresh token hash", zap.String("guid", guid), zap.Error(err))
				return
			}

			logger.Info("RefreshHandler: successfully logout", zap.String("guid", guid))
			return
		}

		currentIp := r.RemoteAddr

		if currentIp != storedIp {
			err = sendMessageWebhook(ctx, cfg.WebHookURL, storedIp, currentIp)
			if err != nil {
				logger.Warn(
					"RefreshHandler: failed to send message webhook",
					zap.String("guid", guid),
					zap.String("currentIp", currentIp),
					zap.String("storedIp", storedIp),
					zap.Error(err),
				)

			} else {
				logger.Info("RefreshHandler: successfully sent message webhook", zap.String("guid", guid))
			}

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

		err = ps.StoreRefreshTokenHash(ctx, guid, newHash, currentUserAgent, currentIp)
		if err != nil {
			api.WriteError(w, logger, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			logger.Error("RefreshHandler: cannot store hash refresh token", zap.String("guid", guid), zap.Error(err))
			return
		}

		api.WriteWithTokens(w, logger, newAccessToken, newRefreshToken)
		logger.Info("RefreshHandler: successfully refreshed tokens", zap.String("guid", guid))
	}
}

func sendMessageWebhook(ctx context.Context, url string, storedIp string, currentIp string) error {
	message := fmt.Sprintf("An attempt to update the token from a new IP: %s Received IP:%s", storedIp, currentIp)

	jsonMessage, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("sendMessageWebhook: failed to marshal message: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBuffer(jsonMessage))
	if err != nil {
		return fmt.Errorf("sendMessageWebhook: failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}

	_, err = client.Do(req)
	if err != nil {
		return fmt.Errorf("sendMessageWebhook: failed to send message: %w", err)
	}

	return nil
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
