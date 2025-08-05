package postgresClient

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/golang-migrate/migrate"
	_ "github.com/golang-migrate/migrate/database/postgres"
	_ "github.com/golang-migrate/migrate/source/file"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"
)

func New(ctx context.Context, config *Config, logger *zap.Logger, migrationsPath string) (*PostgresService, error) {
	if config.Timeout == 0 {
		config.Timeout = DefaultPostgresTimeout
	}

	url := buildURL(config)
	dsn := buildDSN(config)

	pool, err := pgxpool.New(ctx, dsn)

	if err != nil {
		return nil, err
	}

	err = upMigration(url, migrationsPath)
	if err != nil {
		return nil, err
	}

	return &PostgresService{
		pool:    pool,
		logger:  logger,
		timeout: config.Timeout,
	}, nil
}

func (ps *PostgresService) StoreRefreshTokenHash(ctx context.Context, guid string, hash []byte, userAgent string, ip string) error {
	ctx, cancel := context.WithTimeout(ctx, ps.timeout)
	defer cancel()

	tag, err := ps.pool.Exec(ctx, queryStoreRefreshTokenHash, guid, hash, userAgent, ip)
	if err != nil {
		ps.logger.Error("StoreRefreshTokenHash: failed to store hash", zap.Error(err))
		return fmt.Errorf("StoreRefreshTokenHash: failed to store hash: %w", err)
	}

	if tag.RowsAffected() == 0 {
		ps.logger.Error("StoreRefreshTokenHash: no rows affected")
		return fmt.Errorf("StoreRefreshTokenHash: no rows affected")
	}

	ps.logger.Info("StoreRefreshTokenHash: hash stored successfully")
	return nil
}

func (ps *PostgresService) DeleteRefreshTokenHash(ctx context.Context, guid string) error {
	ctx, cancel := context.WithTimeout(ctx, ps.timeout)
	defer cancel()

	_, err := ps.pool.Exec(ctx, queryDeleteRefreshTokenHash, guid)
	if err != nil {
		ps.logger.Error("DeleteRefreshTokenHash: failed to delete hash", zap.Error(err))
		return fmt.Errorf("DeleteRefreshTokenHash: failed to delete hash: %w", err)
	}

	ps.logger.Info("DeleteRefreshTokenHash: hash deleted successfully")
	return nil
}

func (ps *PostgresService) StoreTokenToBlacklist(ctx context.Context, jti string, exp *time.Time) error {
	ctx, cancel := context.WithTimeout(ctx, ps.timeout)
	defer cancel()

	tag, err := ps.pool.Exec(ctx, queryStoreTokenToBlacklist, jti, exp)
	if err != nil {
		ps.logger.Error("StoreTokenToBlacklist: failed to store", zap.Error(err))
		return fmt.Errorf("StoreTokenToBlacklist: failed to store: %w", err)
	}

	if tag.RowsAffected() == 0 {
		ps.logger.Error("StoreTokenToBlacklist: no rows affected")
		return fmt.Errorf("StoreTokenToBlacklist: no rows affected")
	}

	ps.logger.Info("StoreTokenToBlacklist: jti and exp stored successfully")
	return nil
}

func (ps *PostgresService) IsBlacklisted(ctx context.Context, jti string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, ps.timeout)
	defer cancel()

	var exists bool

	err := ps.pool.QueryRow(ctx, queryIsBlacklisted, jti).Scan(&exists)
	if err != nil {
		ps.logger.Error("IsBlacklisted: failed to get jti", zap.Error(err))
		return false, fmt.Errorf("IsBlacklisted: failed to get jti: %w", err)
	}

	return exists, nil
}

func (ps *PostgresService) GetStoredRefreshTokenData(ctx context.Context, guid string) ([]byte, string, string, error) {
	ctx, cancel := context.WithTimeout(ctx, ps.timeout)
	defer cancel()

	var hash []byte
	var userAgent string
	var ip string

	err := ps.pool.QueryRow(ctx, queryGetStoredRefreshTokenData, guid).Scan(&hash, &userAgent, &ip)
	if err != nil {
		ps.logger.Error("GetStoredRefreshHash: failed to get jti", zap.Error(err))
		return nil, "", "", fmt.Errorf("GetStoredRefreshHash: failed to get hash: %w", err)
	}

	return hash, userAgent, ip, nil
}

func (ps *PostgresService) Close() {
	ps.pool.Close()
}

func buildURL(config *Config) string {
	url := fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable",
		config.User,
		config.Password,
		config.Host,
		config.Port,
		config.Database,
	)

	return url
}

func buildDSN(config *Config) string {
	dsn := fmt.Sprintf("user=%s password=%s host=%s port=%s dbname=%s pool_max_conns=%d pool_min_conns=%d",
		config.User,
		config.Password,
		config.Host,
		config.Port,
		config.Database,
		config.MaxConns,
		config.MinConns,
	)

	return dsn
}

func upMigration(url string, path string) error {
	migration, err := migrate.New(path, url)
	if err != nil {
		return fmt.Errorf("failed to create migration: %w", err)
	}

	err = migration.Up()
	if err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("failed to run migration: %w", err)
	}

	return nil
}
