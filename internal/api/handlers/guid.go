package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"

	"medods/internal/api"
	"medods/internal/auth"
)

func GetGUIDHandler(as auth.AuthService, logger *zap.Logger) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		token, ok := r.Context().Value(auth.ContextKeyToken).(*jwt.Token)
		if !ok {
			api.WriteError(w, logger, "GUID not found in token", http.StatusUnauthorized)
			logger.Error("GetGUIDHandler: GUID not found in token")
			return
		}

		guid, err := as.ExtractGUID(token)
		if err != nil {
			api.WriteError(w, logger, "Cannot get GUID from token", http.StatusUnauthorized)
			logger.Error("GetGUIDHandler: failed to extract GUID:", zap.Error(err))
			return
		}

		writeWithGUID(w, logger, guid)
		logger.Info("GetGUIDHandler: successfully returned GUID")
	}
}

func writeWithGUID(w http.ResponseWriter, logger *zap.Logger, guid string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	err := json.NewEncoder(w).Encode(struct {
		GUID string `json:"guid"`
	}{
		GUID: guid,
	})
	if err != nil {
		logger.Error("writeWithGUID: failed to encoding response", zap.Error(err))
	}
}
