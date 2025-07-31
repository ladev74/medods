package postgresClient

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/mock"
	"go.uber.org/zap"
)

const DefaultPostgresTimeout = 3 * time.Second

type Config struct {
	Host     string        `env:"POSTGRES_HOST"`
	Port     string        `env:"POSTGRES_PORT"`
	User     string        `env:"POSTGRES_USER"`
	Password string        `env:"POSTGRES_PASSWORD"`
	Database string        `env:"POSTGRES_DATABASE"`
	Timeout  time.Duration `env:"POSTGRES_TIMEOUT"`
	MaxConns int           `env:"POSTGRES_MAX_CONNECTIONS"`
	MinConns int           `env:"POSTGRES_MIN_CONNECTIONS"`
}

type PostgresService struct {
	pool    *pgxpool.Pool
	logger  *zap.Logger
	timeout time.Duration
}

type PostgresClient interface {
	StoreRefreshTokenHash(context.Context, string, []byte) error
	Close()
}

type MockPostgresService struct {
	mock.Mock
}
