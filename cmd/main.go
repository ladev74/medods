package main

import (
	"fmt"
	"log"

	aauth "medods/internal/auth"
	cconfig "medods/internal/config"
	llogger "medods/internal/logger"
)

const (
	pathToConfigFile = "./config/config.env"
)

func main() {
	//ctx, cancel := signal.NotifyContext(context.Background(),
	//	os.Interrupt,
	//	syscall.SIGTERM,
	//	syscall.SIGQUIT,
	//)
	//defer cancel()

	config, err := cconfig.New(pathToConfigFile)
	if err != nil {
		log.Fatalf("failed to initialize config: %v", err)
	}

	logger, err := llogger.New(&config.Logger)
	if err != nil {
		log.Fatalf("failed to initialize logger: %v", err)
	}
	defer logger.Sync()

	auth := aauth.New(&config.Auth, logger)

	token, err := auth.GenerateAccessToken("ladev")
	if err != nil {
		log.Fatalf("failed to generate access token: %v", err)
	}
	fmt.Println(token)

	//router := chi.NewRouter()
	//
	//router.Use(middleware.RequestID)
	//router.Use(middleware.RealIP)
	//router.Use(llogger.MiddlewareLogger(logger, &llogger.Config{Env: "dev"}))
	//router.Use(middleware.Recoverer)
	//router.Use(middleware.URLFormat)
	//
	//router.Post("/")

}

// TODO: documentation
// TODO: tests
