CREATE SCHEMA IF NOT EXISTS schema_users;


CREATE TABLE IF NOT EXISTS schema_users.users_tokens
(
    guid TEXT PRIMARY KEY,
    refresh_token_hash TEXT NOT NULL
);

