-- Sign in with OpenID Connect (apps/server/src/sign_in_providers.rs): a third provider, `oidc`, next to Google and
-- GitHub. Its endpoints come from the issuer's discovery document, so the row also holds the issuer, the button
-- label and the extra scopes. An OIDC `sub` is unique only per issuer: `user_identities.issuer` records the issuer
-- of each OIDC identity, and saving another issuer removes the identities of the old one.
-- The same change as apps/server/migrations/20261112120000_oidc_sign_in.sql.
ALTER TABLE sign_in_providers DROP CONSTRAINT sign_in_providers_provider_check;
ALTER TABLE sign_in_providers ADD CONSTRAINT sign_in_providers_provider_check
    CHECK (provider IN ('google', 'github', 'oidc'));
-- OIDC only: the sign-in button label ("Authentik").
ALTER TABLE sign_in_providers ADD COLUMN display_name TEXT
    CHECK (display_name IS NULL OR length(display_name) BETWEEN 1 AND 40);
-- OIDC only: the issuer URL, exactly as the discovery document reports it.
ALTER TABLE sign_in_providers ADD COLUMN issuer TEXT CHECK (issuer IS NULL OR length(issuer) BETWEEN 1 AND 512);
-- OIDC only: scopes requested on top of `openid email profile`, space-separated; '' for none.
ALTER TABLE sign_in_providers ADD COLUMN scopes TEXT CHECK (scopes IS NULL OR length(scopes) <= 512);
ALTER TABLE sign_in_providers ADD CONSTRAINT sign_in_providers_oidc_check
    CHECK (provider <> 'oidc' OR (display_name IS NOT NULL AND issuer IS NOT NULL AND scopes IS NOT NULL));

ALTER TABLE user_identities DROP CONSTRAINT user_identities_provider_check;
ALTER TABLE user_identities ADD CONSTRAINT user_identities_provider_check
    CHECK (provider IN ('google', 'github', 'oidc'));
-- OIDC only: the issuer that vouched for `subject`. NULL for Google and GitHub.
ALTER TABLE user_identities ADD COLUMN issuer TEXT;
