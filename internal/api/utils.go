package api

import (
	"encoding/json"
	"net/http"

	"go.uber.org/zap"
)

func WriteError(w http.ResponseWriter, logger *zap.Logger, errMessage string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	err := json.NewEncoder(w).Encode(struct {
		Status     string `json:"status"`
		ErrMessage string `json:"error"`
	}{
		Status:     http.StatusText(statusCode),
		ErrMessage: errMessage,
	})
	if err != nil {
		logger.Error("WriteError: failed to encoding response", zap.Error(err))
	}
}
