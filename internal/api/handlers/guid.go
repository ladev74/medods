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
		ctx := r.Context()

		token := ctx.Value(auth.ContextKeyToken).(*jwt.Token)

		guid, err := as.ExtractGUID(token)
		if err != nil {
			api.WriteError(w, logger, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			logger.Error("GetGUIDHandler: failed to extract GUID:", zap.Error(err))
			return
		}

		writeWithGUID(w, logger, guid)
		logger.Info("GetGUIDHandler: successfully returned GUID", zap.String("guid", guid))
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
