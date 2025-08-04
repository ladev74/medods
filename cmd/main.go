package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"go.uber.org/zap"

	"medods/internal/api/handlers"
	mmiddleware "medods/internal/api/middleware"
	aauth "medods/internal/auth"
	cconfig "medods/internal/config"
	llogger "medods/internal/logger"
	ppostgresClient "medods/internal/storage/postgresClient"
)

const (
	pathToConfigFile     = "./config/config.env"
	pathToMigrationsFile = "file://./database/migrations"
	shoutdownTime        = 15 * time.Second
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
		syscall.SIGQUIT,
	)
	defer cancel()

	config, err := cconfig.New(pathToConfigFile)
	if err != nil {
		log.Fatalf("failed to initialize config: %v", err)
	}

	logger, err := llogger.New(&config.Logger)
	if err != nil {
		log.Fatalf("failed to initialize logger: %v", err)
	}
	defer logger.Sync()

	postgresClient, err := ppostgresClient.New(ctx, &config.Postgres, logger, pathToMigrationsFile)
	if err != nil {
		logger.Fatal("failed to initialize postgres client", zap.Error(err))
	}

	authService := aauth.New(&config.Auth, logger)

	router := chi.NewRouter()

	router.Use(middleware.RealIP)
	router.Use(middleware.RequestID)
	router.Use(llogger.MiddlewareLogger(logger, &config.Logger))
	router.Use(middleware.Recoverer)
	router.Use(middleware.URLFormat)

	router.Route("/auth", func(r chi.Router) {
		r.With(mmiddleware.AuthMiddleware(authService, postgresClient, logger)).Group(func(r chi.Router) {
			r.Post("/guid", handlers.GetGUIDHandler(authService, logger))
			r.Post("/logout", handlers.LogoutHandler(authService, postgresClient, logger))
			r.Post("/refresh", handlers.RefreshHandler(authService, postgresClient, logger))
		})

		r.Post("/tokens", handlers.CreateTokensHandler(authService, postgresClient, logger))
	})

	server := http.Server{
		Addr:    fmt.Sprintf("%s:%d", config.HttpServer.Host, config.HttpServer.Port),
		Handler: router,
	}

	go func() {
		logger.Info("starting http server", zap.String("addr", server.Addr))
		if err = server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("failed to start server", zap.Error(err))
		}
	}()

	<-ctx.Done()

	logger.Info("received shutdown signal")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), shoutdownTime)
	defer shutdownCancel()

	if err = server.Shutdown(shutdownCtx); err != nil {
		logger.Error("cannot shutdown http server", zap.Error(err))
		return
	}

	postgresClient.Close()

	logger.Info("stopping http server", zap.String("addr", server.Addr))

	logger.Info("application shutdown completed successfully")
}

// TODO: documentation
// TODO: tests
// TODO: rename project
// TODO: refactoring middleware?
