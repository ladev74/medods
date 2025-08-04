package postgresClient

const (
	queryStoreRefreshTokenHash = `INSERT INTO schema_users.refresh_token_hashes (guid, refresh_token_hash) VALUES ($1, $2)`

	queryDeleteRefreshTokenHash = `DELETE FROM schema_users.refresh_token_hashes WHERE guid = $1`

	queryStoreTokenToBlacklist = `INSERT INTO schema_users.access_token_blacklist (access_token_jti, expires) VALUES ($1,$2)`

	queryIsBlacklisted = `SELECT EXISTS (SELECT 1 FROM schema_users.access_token_blacklist WHERE access_token_jti = $1)`

	queryGetStoredRefreshHash = `SELECT refresh_token_hash FROM schema_users.refresh_token_hashes WHERE guid = $1`
)
