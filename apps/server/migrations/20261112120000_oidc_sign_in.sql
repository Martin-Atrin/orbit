-- Sign in with OpenID Connect (apps/server/src/sign_in_providers.rs): a third provider, `oidc`, next to Google and
-- GitHub. Its endpoints come from the issuer's discovery document, so the row also holds the issuer, the button
-- label and the extra scopes. An OIDC `sub` is unique only per issuer: `user_identities.issuer` records the issuer
-- of each OIDC identity, and saving another issuer removes the identities of the old one.
--
-- SQLite cannot alter a CHECK constraint, so both tables are rebuilt (see 0021). Nothing references them, and they
-- have no triggers or indexes besides their own keys.
PRAGMA defer_foreign_keys = ON;

CREATE TABLE sign_in_providers_backup AS SELECT * FROM sign_in_providers;
DROP TABLE sign_in_providers;

CREATE TABLE sign_in_providers (
    provider TEXT PRIMARY KEY CHECK (provider IN ('google', 'github', 'oidc')),
    client_id TEXT NOT NULL CHECK (length(client_id) BETWEEN 1 AND 256),
    client_secret BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    -- OIDC only: the sign-in button label ("Authentik").
    display_name TEXT CHECK (display_name IS NULL OR length(display_name) BETWEEN 1 AND 40),
    -- OIDC only: the issuer URL, exactly as the discovery document reports it.
    issuer TEXT CHECK (issuer IS NULL OR length(issuer) BETWEEN 1 AND 512),
    -- OIDC only: scopes requested on top of `openid email profile`, space-separated; '' for none.
    scopes TEXT CHECK (scopes IS NULL OR length(scopes) <= 512),
    CHECK (provider <> 'oidc' OR (display_name IS NOT NULL AND issuer IS NOT NULL AND scopes IS NOT NULL))
);

INSERT INTO sign_in_providers (provider, client_id, client_secret, created_at, updated_at)
SELECT provider, client_id, client_secret, created_at, updated_at FROM sign_in_providers_backup;

DROP TABLE sign_in_providers_backup;

CREATE TABLE user_identities_backup AS SELECT * FROM user_identities;
DROP TABLE user_identities;

CREATE TABLE user_identities (
    provider TEXT NOT NULL CHECK (provider IN ('google', 'github', 'oidc')),
    subject TEXT NOT NULL CHECK (length(subject) BETWEEN 1 AND 256),
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    email TEXT,
    created_at INTEGER NOT NULL,
    -- OIDC only: the issuer that vouched for `subject`. NULL for Google and GitHub.
    issuer TEXT,
    PRIMARY KEY (provider, subject),
    UNIQUE (user_id, provider)
);

INSERT INTO user_identities (provider, subject, user_id, email, created_at)
SELECT provider, subject, user_id, email, created_at FROM user_identities_backup;

DROP TABLE user_identities_backup;
