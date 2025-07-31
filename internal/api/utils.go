package api

import (
	"encoding/json"
	"net/http"

	"go.uber.org/zap"
)

type successResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type errorResponse struct {
	Status     string `json:"status"`
	ErrMessage string `json:"error"`
}

func WriteErrorResponse(w http.ResponseWriter, logger *zap.Logger, errMessage string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	resp := errorResponse{
		Status:     http.StatusText(statusCode),
		ErrMessage: errMessage,
	}

	err := json.NewEncoder(w).Encode(resp)
	if err != nil {
		logger.Error("writeErrorResponse: failed to encoding response", zap.Error(err))

	}
}

func WriteSuccessResponse(w http.ResponseWriter, logger *zap.Logger, accessToken string, refreshToken string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	resp := successResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}

	err := json.NewEncoder(w).Encode(resp)
	if err != nil {
		logger.Error("writeSuccessResponse: failed to encoding response", zap.Error(err))
	}
}

func WriteSuccessResponseWithGUID(w http.ResponseWriter, logger *zap.Logger, guid string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	err := json.NewEncoder(w).Encode(struct {
		GUID string `json:"guid"`
	}{
		GUID: guid,
	})
	if err != nil {
		logger.Error("writeSuccessResponse: failed to encoding response", zap.Error(err))
	}
}
