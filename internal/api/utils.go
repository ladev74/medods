package api

import (
	"encoding/json"
	"net/http"

	"go.uber.org/zap"
)

func WriteError(w http.ResponseWriter, logger *zap.Logger, errMessage string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	resp := ErrorResponse{
		Status:     http.StatusText(statusCode),
		ErrMessage: errMessage,
	}

	err := json.NewEncoder(w).Encode(resp)
	if err != nil {
		logger.Error("WriteError: failed to encoding response", zap.Error(err))
	}
}

type ErrorResponse struct {
	Status     string `json:"status"`
	ErrMessage string `json:"error"`
}

func WriteOK(w http.ResponseWriter, logger *zap.Logger) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	resp := OKResponse{
		Status: http.StatusText(http.StatusOK),
	}

	err := json.NewEncoder(w).Encode(resp)
	if err != nil {
		logger.Error("writeOK: failed to encoding response", zap.Error(err))
	}
}

type OKResponse struct {
	Status string `json:"status"`
}

func WriteWithGUID(w http.ResponseWriter, logger *zap.Logger, guid string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	resp := GUIDResponse{
		GUID: guid,
	}

	err := json.NewEncoder(w).Encode(resp)
	if err != nil {
		logger.Error("writeWithGUID: failed to encoding response", zap.Error(err))
	}
}

type GUIDResponse struct {
	GUID string `json:"guid"`
}

func WriteWithTokens(w http.ResponseWriter, logger *zap.Logger, accessToken string, refreshToken string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	resp := RespWithTokens{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}

	err := json.NewEncoder(w).Encode(resp)
	if err != nil {
		logger.Error("writeWithTokens: failed to encoding response", zap.Error(err))
	}
}

type RespWithTokens struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token" example:"your_refresh_token"`
}
