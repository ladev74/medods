package postgresClient

const (
	queryForStoreHash = `INSERT INTO schema_users.users_tokens (guid, refresh_token_hash) VALUES ($1, $2)`
)
