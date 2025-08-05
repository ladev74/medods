CREATE SCHEMA IF NOT EXISTS schema_users;


CREATE TABLE IF NOT EXISTS schema_users.refresh_token_hashes
(
    guid TEXT PRIMARY KEY,
    refresh_token_hash TEXT NOT NULL,
    user_agent TEXT NOT NULL,
    user_ip TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS schema_users.access_token_blacklist
(
    access_token_jti TEXT PRIMARY KEY,
    expires TIMESTAMP NOT NULL
);
