//! Google, GitHub and a generic OpenID Connect provider as sign-in providers: the authorization URL, the code
//! exchange and the profile. Everything that knows a provider's wire format is here. Callers get a
//! [`ProviderProfile`] or a [`ProviderFailure`].

use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use orbit_platform::TimestampMillis;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use url::Url;
use utoipa::ToSchema;

/// The redirect URI the Orbit app registers. Native sign-ins may only return here, or to an exact
/// `ORBIT_DEV_NATIVE_REDIRECTS` entry.
pub const APP_REDIRECT: &str = "orbit://auth/callback";

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum Provider {
    Google,
    Github,
    /// Any OpenID Connect provider (Authentik, Keycloak, Zitadel, Entra ID, Okta...), found by its issuer.
    Oidc,
}

impl Provider {
    pub const ALL: [Self; 3] = [Self::Google, Self::Github, Self::Oidc];

    /// The value in paths, JSON and the `provider` columns.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Google => "google",
            Self::Github => "github",
            Self::Oidc => "oidc",
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|provider| provider.as_str() == value)
    }

    /// `{public_origin}/api/v1/auth/providers/{provider}/callback`: what the admin registers at the provider.
    #[must_use]
    pub fn callback_url(self, public_origin: &str) -> String {
        format!(
            "{}/api/v1/auth/providers/{}/callback",
            public_origin.trim_end_matches('/'),
            self.as_str()
        )
    }
}

/// The OAuth client an admin saved, decrypted.
pub struct ProviderCredentials {
    pub client_id: String,
    pub client_secret: String,
    /// `Some` exactly for [`Provider::Oidc`].
    pub oidc: Option<OidcSettings>,
}

/// What an OpenID Connect provider needs on top of the OAuth client.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OidcSettings {
    /// The sign-in button label: "Continue with {display_name}".
    pub display_name: String,
    /// The issuer URL, exactly as the discovery document reports it.
    pub issuer: String,
    /// Scopes on top of [`OIDC_SCOPES`], space-separated; empty for none.
    pub scopes: String,
}

/// The scopes every OIDC sign-in asks for.
pub const OIDC_SCOPES: &str = "openid email profile";

/// At most this many characters in an OIDC button label.
pub const OIDC_DISPLAY_NAME_MAX: usize = 40;

/// Why an OIDC setting cannot be saved. The text is for the admin.
#[derive(Debug, Eq, PartialEq)]
pub struct InvalidOidcSetting(pub String);

/// A trimmed, checked issuer URL: `https`, or `http` on a loopback host (for a provider on the same machine), with no
/// credentials, query or fragment. It stays as typed, since the discovery document must report the same string.
pub fn oidc_issuer(value: &str) -> Result<String, InvalidOidcSetting> {
    let issuer = value.trim();
    let invalid = |detail: &str| Err(InvalidOidcSetting(format!("issuer: {detail}")));
    if issuer.is_empty() || issuer.len() > 512 {
        return invalid("enter the issuer URL (at most 512 characters).");
    }
    let Ok(url) = Url::parse(issuer) else {
        return invalid("enter a URL such as https://auth.example.com/application/o/orbit/.");
    };
    if !allowed_endpoint(&url) {
        return invalid("use an https URL.");
    }
    if url.query().is_some() || url.fragment().is_some() {
        return invalid("an issuer URL has no query or fragment.");
    }
    Ok(issuer.to_owned())
}

/// The extra scopes, normalized: split on spaces, without `openid email profile` and without repeats. Each must be a
/// scope token (RFC 6749 3.3).
pub fn oidc_extra_scopes(value: &str) -> Result<String, InvalidOidcSetting> {
    let mut scopes: Vec<&str> = Vec::new();
    for scope in value.split_whitespace() {
        let token = scope
            .bytes()
            .all(|byte| matches!(byte, 0x21 | 0x23..=0x5B | 0x5D..=0x7E));
        if !token {
            return Err(InvalidOidcSetting(format!(
                "scopes: \"{scope}\" is not a scope. Separate scopes with spaces."
            )));
        }
        if !OIDC_SCOPES.split(' ').any(|default| default == scope) && !scopes.contains(&scope) {
            scopes.push(scope);
        }
    }
    let scopes = scopes.join(" ");
    if scopes.len() > 512 {
        return Err(InvalidOidcSetting(
            "scopes: at most 512 characters.".to_owned(),
        ));
    }
    Ok(scopes)
}

/// Where Orbit may send a browser or a request for an OIDC provider: `https`, or `http` on a loopback host. Never
/// a URL with credentials in it.
fn allowed_endpoint(url: &Url) -> bool {
    let loopback = match url.host() {
        Some(url::Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    };
    url.host().is_some()
        && url.username().is_empty()
        && url.password().is_none()
        && (url.scheme() == "https" || (url.scheme() == "http" && loopback))
}

/// The endpoints of an OIDC provider, from `{issuer}/.well-known/openid-configuration`.
#[derive(Clone, Debug)]
pub struct OidcDiscovery {
    pub issuer: String,
    pub authorization_endpoint: Url,
    pub token_endpoint: Url,
    pub userinfo_endpoint: Option<Url>,
    /// `client_secret_basic` (the default of the spec) unless the provider only lists `client_secret_post`.
    pub secret_in_body: bool,
}

/// Why a discovery document is not usable. The text is for the admin.
#[derive(Debug, Eq, PartialEq)]
pub enum DiscoveryError {
    /// Unreachable, a non-2xx answer, or not a discovery document.
    Unavailable(String),
    /// The document names another issuer than the configured one.
    IssuerMismatch { reported: String },
    /// An endpoint is not `https`.
    InsecureEndpoint(&'static str),
}

impl std::fmt::Display for DiscoveryError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unavailable(reason) => write!(
                formatter,
                "issuer: Orbit could not read the discovery document ({reason})."
            ),
            Self::IssuerMismatch { reported } => write!(
                formatter,
                "issuer: the provider reports the issuer \"{reported}\". Enter exactly that URL."
            ),
            Self::InsecureEndpoint(field) => write!(
                formatter,
                "issuer: the discovery document's {field} is not an https URL."
            ),
        }
    }
}

/// The ID token claims Orbit checks. The token comes straight from the token endpoint over TLS, so its signature is
/// not checked (OpenID Connect Core 3.1.3.7, step 6); its issuer, audience, expiry and nonce are.
#[derive(Deserialize)]
struct IdTokenClaims {
    iss: String,
    sub: String,
    aud: Audience,
    azp: Option<String>,
    exp: i64,
    nonce: Option<String>,
    auth_time: Option<i64>,
    #[serde(flatten)]
    profile: OidcClaims,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Audience {
    One(String),
    Many(Vec<String>),
}

impl Audience {
    fn contains(&self, client_id: &str) -> bool {
        match self {
            Self::One(audience) => audience == client_id,
            Self::Many(audiences) => audiences.iter().any(|audience| audience == client_id),
        }
    }

    fn len(&self) -> usize {
        match self {
            Self::One(_) => 1,
            Self::Many(audiences) => audiences.len(),
        }
    }
}

/// The profile claims, from the userinfo endpoint or the ID token.
#[derive(Default, Deserialize)]
struct OidcClaims {
    email: Option<String>,
    /// A boolean; some providers send the string `"true"`.
    email_verified: Option<serde_json::Value>,
    name: Option<String>,
    preferred_username: Option<String>,
}

impl OidcClaims {
    fn email(&self) -> Option<&str> {
        self.email
            .as_deref()
            .map(str::trim)
            .filter(|email| !email.is_empty())
    }

    fn email_verified(&self) -> bool {
        match &self.email_verified {
            Some(serde_json::Value::Bool(verified)) => *verified,
            Some(serde_json::Value::String(verified)) => verified == "true",
            _ => false,
        }
    }

    fn name(&self) -> Option<&str> {
        self.name
            .as_deref()
            .or(self.preferred_username.as_deref())
            .filter(|name| !name.trim().is_empty())
    }
}

/// What the OIDC callback must check besides the code.
pub struct OidcCheck<'a> {
    pub nonce: &'a str,
    /// The authorization asked for `max_age=0`: the ID token must report a sign-in after this time.
    pub authenticated_since: Option<i64>,
}

/// Clock skew Orbit allows against the provider's `exp` and `auth_time`, in seconds.
const CLOCK_SKEW_SECONDS: i64 = 120;

/// Where the providers are. `Default` is production; tests point every URL at one local fake server.
#[derive(Clone, Debug)]
pub struct ProviderEndpoints {
    google_authorize: Url,
    google_token: Url,
    google_userinfo: Url,
    github_authorize: Url,
    github_token: Url,
    github_api: Url,
}

impl Default for ProviderEndpoints {
    fn default() -> Self {
        let url = |value: &str| Url::parse(value).expect("static provider URL");
        Self {
            google_authorize: url("https://accounts.google.com/o/oauth2/v2/auth"),
            google_token: url("https://oauth2.googleapis.com/token"),
            google_userinfo: url("https://openidconnect.googleapis.com/v1/userinfo"),
            github_authorize: url("https://github.com/login/oauth/authorize"),
            github_token: url("https://github.com/login/oauth/access_token"),
            github_api: url("https://api.github.com/"),
        }
    }
}

impl ProviderEndpoints {
    /// Every endpoint under `base`: `{base}/google/authorize`, `/google/token`, `/google/userinfo`,
    /// `/github/authorize`, `/github/token`, and the GitHub API at `{base}/github/api/`.
    #[must_use]
    pub fn local(base: &str) -> Self {
        let base = base.trim_end_matches('/');
        let url = |path: &str| Url::parse(&format!("{base}{path}")).expect("local provider URL");
        Self {
            google_authorize: url("/google/authorize"),
            google_token: url("/google/token"),
            google_userinfo: url("/google/userinfo"),
            github_authorize: url("/github/authorize"),
            github_token: url("/github/token"),
            github_api: url("/github/api/"),
        }
    }
}

/// What a provider proved about a person.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProviderProfile {
    pub provider: Provider,
    /// Google `sub`, GitHub `id`: the identity key. Never the email.
    pub subject: String,
    /// Normalized, and present only when the provider vouches for it: Google `email_verified`, GitHub the
    /// `primary && verified` entry of `/user/emails`. Linking and sign-up need it.
    pub verified_email: Option<String>,
    /// For Connected accounts: the verified email, else the address or login the provider reported.
    pub email: Option<String>,
    /// Seeds the display name of a new account.
    pub display_name: String,
    /// OIDC only: the issuer that vouched for `subject`. A `sub` is unique only per issuer.
    #[serde(default)]
    pub issuer: Option<String>,
}

/// The provider step did not produce a profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderFailure {
    /// The person declined, or the provider sent an error to the callback.
    Denied,
    /// Unreachable, a non-2xx answer, a GitHub 200 with `error`, a profile we cannot read, or the provider was
    /// removed in the meantime.
    Unavailable,
}

/// Why the authorization step runs. A confirmation must not pass on a silent provider session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Freshness {
    Any,
    ForceLogin,
}

/// The parts of an authorization request that do not depend on the provider.
pub struct AuthorizationRequest<'a> {
    pub redirect_uri: &'a str,
    pub state: &'a str,
    pub pkce_challenge: &'a str,
    /// OIDC only: the ID token must carry it back.
    pub nonce: &'a str,
    pub freshness: Freshness,
}

/// A new PKCE verifier (RFC 7636): 32 random bytes, base64url.
#[must_use]
pub fn pkce_verifier() -> String {
    orbit_platform::generate_opaque_token()
}

/// `base64url(sha256(verifier))`, the S256 code challenge.
#[must_use]
pub fn pkce_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

/// Whether `value` has the shape of an S256 challenge.
#[must_use]
pub fn is_pkce_challenge(value: &str) -> bool {
    value.len() == 43
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

/// The redirect URIs a native client may ask for, compared exactly. No prefixes or patterns: a pattern is how an
/// open redirect hands a handoff code to someone else.
#[derive(Clone, Debug)]
pub struct NativeRedirects(Vec<String>);

impl NativeRedirects {
    #[must_use]
    pub fn new(extra: &[String]) -> Self {
        let mut allowed = vec![APP_REDIRECT.to_owned()];
        allowed.extend(extra.iter().cloned());
        Self(allowed)
    }

    #[must_use]
    pub fn allows(&self, candidate: &str) -> bool {
        self.0.iter().any(|allowed| allowed == candidate)
    }
}

impl Default for NativeRedirects {
    fn default() -> Self {
        Self::new(&[])
    }
}

/// The HTTP side: no redirects, short timeouts, rustls.
#[derive(Clone)]
pub struct ProviderClient {
    http: reqwest::Client,
    endpoints: ProviderEndpoints,
}

impl Default for ProviderClient {
    fn default() -> Self {
        Self::new(ProviderEndpoints::default())
    }
}

impl ProviderClient {
    #[must_use]
    pub fn new(endpoints: ProviderEndpoints) -> Self {
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(20))
            .user_agent("Orbit")
            .build()
            .expect("the provider HTTP client builds");
        Self { http, endpoints }
    }

    /// The URL the browser opens. Scopes: Google `openid email profile`; GitHub `read:user user:email`; OIDC
    /// `openid email profile` and the extra ones, at the endpoint its discovery document names.
    pub async fn authorization_url(
        &self,
        provider: Provider,
        credentials: &ProviderCredentials,
        request: &AuthorizationRequest<'_>,
    ) -> Result<Url, ProviderFailure> {
        let (mut url, scope) = match provider {
            Provider::Google => (
                self.endpoints.google_authorize.clone(),
                "openid email profile",
            ),
            Provider::Github => (
                self.endpoints.github_authorize.clone(),
                "read:user user:email",
            ),
            Provider::Oidc => return self.oidc_authorization_url(credentials, request).await,
        };
        {
            let mut query = url.query_pairs_mut();
            query
                .append_pair("client_id", &credentials.client_id)
                .append_pair("redirect_uri", request.redirect_uri)
                .append_pair("response_type", "code")
                .append_pair("scope", scope)
                .append_pair("state", request.state)
                .append_pair("code_challenge", request.pkce_challenge)
                .append_pair("code_challenge_method", "S256")
                .append_pair("prompt", "select_account");
            if provider == Provider::Google && request.freshness == Freshness::ForceLogin {
                query.append_pair("max_age", "0");
            }
        }
        Ok(url)
    }

    /// Code, then access token, then profile. Google: token endpoint, then userinfo. GitHub: token endpoint with
    /// `Accept: application/json` (errors come back as 200 with `error`), then `/user` and `/user/emails`.
    /// OIDC: see [`Self::oidc_profile`].
    pub async fn profile(
        &self,
        provider: Provider,
        credentials: &ProviderCredentials,
        redirect_uri: &str,
        code: &str,
        pkce_verifier: &str,
        check: &OidcCheck<'_>,
    ) -> Result<ProviderProfile, ProviderFailure> {
        let token_url = match provider {
            Provider::Google => &self.endpoints.google_token,
            Provider::Github => &self.endpoints.github_token,
            Provider::Oidc => {
                return self
                    .oidc_profile(credentials, redirect_uri, code, pkce_verifier, check)
                    .await;
            }
        };
        let token = self
            .http
            .post(token_url.clone())
            .header(reqwest::header::ACCEPT, "application/json")
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("redirect_uri", redirect_uri),
                ("client_id", credentials.client_id.as_str()),
                ("client_secret", credentials.client_secret.as_str()),
                ("code_verifier", pkce_verifier),
            ])
            .send()
            .await
            .map_err(|error| unavailable(provider, "token request", &error))?;
        let token: TokenResponse = read_json(provider, "token", token).await?;
        let access_token = token.access_token.ok_or_else(|| {
            tracing::warn!(provider = provider.as_str(), error = ?token.error, "provider refused the code");
            ProviderFailure::Unavailable
        })?;
        if provider == Provider::Google {
            self.google_profile(&access_token).await
        } else {
            self.github_profile(&access_token).await
        }
    }

    async fn google_profile(&self, access_token: &str) -> Result<ProviderProfile, ProviderFailure> {
        let provider = Provider::Google;
        let response = self
            .http
            .get(self.endpoints.google_userinfo.clone())
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(|error| unavailable(provider, "userinfo", &error))?;
        let user: GoogleUserInfo = read_json(provider, "userinfo", response).await?;
        if user.sub.is_empty() || user.sub.len() > 256 {
            return Err(ProviderFailure::Unavailable);
        }
        let email = user.email.filter(|email| !email.trim().is_empty());
        let verified_email = email
            .as_deref()
            .filter(|_| user.email_verified == Some(true))
            .map(orbit_platform::normalize_email);
        Ok(ProviderProfile {
            provider,
            subject: user.sub,
            display_name: display_name(user.name.as_deref(), email.as_deref()),
            email: verified_email.clone().or(email),
            verified_email,
            issuer: None,
        })
    }

    async fn github_profile(&self, access_token: &str) -> Result<ProviderProfile, ProviderFailure> {
        let provider = Provider::Github;
        let get = |path: &str| {
            let url = self
                .endpoints
                .github_api
                .join(path)
                .expect("relative GitHub API path");
            self.http
                .get(url)
                .bearer_auth(access_token)
                .header(reqwest::header::ACCEPT, "application/vnd.github+json")
                .header("X-GitHub-Api-Version", "2022-11-28")
                .send()
        };
        let response = get("user")
            .await
            .map_err(|error| unavailable(provider, "user", &error))?;
        let user: GithubUser = read_json(provider, "user", response).await?;
        let response = get("user/emails")
            .await
            .map_err(|error| unavailable(provider, "user emails", &error))?;
        let emails: Vec<GithubEmail> = read_json(provider, "user emails", response).await?;
        let verified_email = emails
            .iter()
            .find(|email| email.primary && email.verified)
            .map(|email| orbit_platform::normalize_email(&email.email));
        let name = user.name.as_deref().filter(|name| !name.trim().is_empty());
        Ok(ProviderProfile {
            provider,
            subject: user.id.to_string(),
            display_name: display_name(name.or(Some(user.login.as_str())), None),
            email: verified_email.clone().or(Some(user.login)),
            verified_email,
            issuer: None,
        })
    }

    /// Reads `{issuer}/.well-known/openid-configuration`. Its `issuer` must be the configured one, character for
    /// character, and its endpoints `https` (or `http` on a loopback host).
    pub async fn discover(&self, issuer: &str) -> Result<OidcDiscovery, DiscoveryError> {
        let url = format!(
            "{}/.well-known/openid-configuration",
            issuer.trim_end_matches('/')
        );
        let response = self
            .http
            .get(&url)
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(|error| {
                tracing::warn!(provider = "oidc", %error, "OIDC discovery failed");
                DiscoveryError::Unavailable(if error.is_timeout() {
                    "no answer in time".to_owned()
                } else {
                    "the server cannot be reached".to_owned()
                })
            })?;
        let status = response.status();
        if !status.is_success() {
            return Err(DiscoveryError::Unavailable(format!("HTTP {status}")));
        }
        let document: DiscoveryDocument = response
            .json()
            .await
            .map_err(|_| DiscoveryError::Unavailable("not a discovery document".to_owned()))?;
        if document.issuer != issuer {
            return Err(DiscoveryError::IssuerMismatch {
                reported: document.issuer.chars().take(512).collect(),
            });
        }
        let endpoint = |value: &str, field: &'static str| {
            Url::parse(value)
                .ok()
                .filter(allowed_endpoint)
                .ok_or(DiscoveryError::InsecureEndpoint(field))
        };
        let userinfo_endpoint = document
            .userinfo_endpoint
            .as_deref()
            .map(|value| endpoint(value, "userinfo_endpoint"))
            .transpose()?;
        let methods = document.token_endpoint_auth_methods_supported;
        let secret_in_body = methods.as_ref().is_some_and(|methods| {
            !methods.iter().any(|method| method == "client_secret_basic")
                && methods.iter().any(|method| method == "client_secret_post")
        });
        Ok(OidcDiscovery {
            authorization_endpoint: endpoint(
                &document.authorization_endpoint,
                "authorization_endpoint",
            )?,
            token_endpoint: endpoint(&document.token_endpoint, "token_endpoint")?,
            userinfo_endpoint,
            issuer: document.issuer,
            secret_in_body,
        })
    }

    async fn discover_for_sign_in(
        &self,
        settings: &OidcSettings,
    ) -> Result<OidcDiscovery, ProviderFailure> {
        self.discover(&settings.issuer).await.map_err(|error| {
            tracing::warn!(provider = "oidc", %error, "the OIDC provider cannot sign in");
            ProviderFailure::Unavailable
        })
    }

    /// The OIDC authorization URL: discovery, then the code flow with PKCE, a nonce and the scopes
    /// `openid email profile` plus the extra ones. A confirmation asks for `prompt=login` and `max_age=0`.
    async fn oidc_authorization_url(
        &self,
        credentials: &ProviderCredentials,
        request: &AuthorizationRequest<'_>,
    ) -> Result<Url, ProviderFailure> {
        let settings = credentials
            .oidc
            .as_ref()
            .ok_or(ProviderFailure::Unavailable)?;
        let discovery = self.discover_for_sign_in(settings).await?;
        let scope = if settings.scopes.is_empty() {
            OIDC_SCOPES.to_owned()
        } else {
            format!("{OIDC_SCOPES} {}", settings.scopes)
        };
        let mut url = discovery.authorization_endpoint;
        {
            let mut query = url.query_pairs_mut();
            query
                .append_pair("client_id", &credentials.client_id)
                .append_pair("redirect_uri", request.redirect_uri)
                .append_pair("response_type", "code")
                .append_pair("scope", &scope)
                .append_pair("state", request.state)
                .append_pair("nonce", request.nonce)
                .append_pair("code_challenge", request.pkce_challenge)
                .append_pair("code_challenge_method", "S256");
            if request.freshness == Freshness::ForceLogin {
                query
                    .append_pair("prompt", "login")
                    .append_pair("max_age", "0");
            }
        }
        Ok(url)
    }

    /// Code, then tokens, then profile, for an OIDC provider. The ID token from the token endpoint must name the
    /// configured issuer, this client, an unexpired time and the nonce of the start; the userinfo endpoint must
    /// report the same `sub`. The email and `email_verified` come from userinfo when it reports an email, else from
    /// the ID token.
    async fn oidc_profile(
        &self,
        credentials: &ProviderCredentials,
        redirect_uri: &str,
        code: &str,
        pkce_verifier: &str,
        check: &OidcCheck<'_>,
    ) -> Result<ProviderProfile, ProviderFailure> {
        let provider = Provider::Oidc;
        let settings = credentials
            .oidc
            .as_ref()
            .ok_or(ProviderFailure::Unavailable)?;
        let discovery = self.discover_for_sign_in(settings).await?;
        let mut form = vec![
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", redirect_uri),
            ("code_verifier", pkce_verifier),
        ];
        let mut request = self
            .http
            .post(discovery.token_endpoint.clone())
            .header(reqwest::header::ACCEPT, "application/json");
        if discovery.secret_in_body {
            form.push(("client_id", credentials.client_id.as_str()));
            form.push(("client_secret", credentials.client_secret.as_str()));
        } else {
            // RFC 6749 2.3.1: both parts are form-encoded before they go into the Basic header.
            let encode = |value: &str| {
                url::form_urlencoded::byte_serialize(value.as_bytes()).collect::<String>()
            };
            request = request.basic_auth(
                encode(&credentials.client_id),
                Some(encode(&credentials.client_secret)),
            );
            form.push(("client_id", credentials.client_id.as_str()));
        }
        let token = request
            .form(&form)
            .send()
            .await
            .map_err(|error| unavailable(provider, "token request", &error))?;
        let token: TokenResponse = read_json(provider, "token", token).await?;
        let (Some(access_token), Some(id_token)) = (token.access_token, token.id_token) else {
            tracing::warn!(provider = "oidc", error = ?token.error, "the provider sent no access token or ID token");
            return Err(ProviderFailure::Unavailable);
        };
        let claims = id_token_claims(&id_token).ok_or_else(|| {
            tracing::warn!(provider = "oidc", "the ID token cannot be read");
            ProviderFailure::Unavailable
        })?;
        check_id_token(
            &claims,
            &discovery.issuer,
            &credentials.client_id,
            check,
            TimestampMillis::now().as_millis() / 1_000,
        )
        .map_err(|reason| {
            tracing::warn!(provider = "oidc", reason, "the ID token was refused");
            ProviderFailure::Unavailable
        })?;
        let userinfo = match &discovery.userinfo_endpoint {
            Some(endpoint) => {
                let response = self
                    .http
                    .get(endpoint.clone())
                    .bearer_auth(&access_token)
                    .header(reqwest::header::ACCEPT, "application/json")
                    .send()
                    .await
                    .map_err(|error| unavailable(provider, "userinfo", &error))?;
                let userinfo: UserInfo = read_json(provider, "userinfo", response).await?;
                if userinfo.sub != claims.sub {
                    tracing::warn!(
                        provider = "oidc",
                        "userinfo reports another sub than the ID token"
                    );
                    return Err(ProviderFailure::Unavailable);
                }
                Some(userinfo.profile)
            }
            None => None,
        };
        let source = userinfo
            .as_ref()
            .filter(|userinfo| userinfo.email().is_some())
            .unwrap_or(&claims.profile);
        let email = source.email().map(str::to_owned);
        let verified_email = email
            .as_deref()
            .filter(|_| source.email_verified())
            .map(orbit_platform::normalize_email);
        let name = userinfo
            .as_ref()
            .and_then(OidcClaims::name)
            .or_else(|| claims.profile.name());
        Ok(ProviderProfile {
            provider,
            subject: claims.sub,
            display_name: display_name(name, email.as_deref()),
            email: verified_email.clone().or(email),
            verified_email,
            issuer: Some(discovery.issuer),
        })
    }
}

/// The claims of a compact JWS, without checking its signature (see [`IdTokenClaims`]).
fn id_token_claims(id_token: &str) -> Option<IdTokenClaims> {
    if id_token.len() > 16 * 1024 {
        return None;
    }
    let mut parts = id_token.split('.');
    let (Some(_header), Some(payload), Some(_signature), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return None;
    };
    let payload = URL_SAFE_NO_PAD.decode(payload.trim_end_matches('=')).ok()?;
    serde_json::from_slice(&payload).ok()
}

/// OpenID Connect Core 3.1.3.7: the issuer, the audience (and `azp` when there are several), the expiry, the nonce,
/// and `auth_time` after `max_age=0`. `now` is in seconds.
fn check_id_token(
    claims: &IdTokenClaims,
    issuer: &str,
    client_id: &str,
    check: &OidcCheck<'_>,
    now: i64,
) -> Result<(), &'static str> {
    if claims.iss != issuer {
        return Err("issuer");
    }
    if !claims.aud.contains(client_id) {
        return Err("audience");
    }
    if claims.aud.len() > 1 && claims.azp.as_deref() != Some(client_id) {
        return Err("authorized party");
    }
    if claims.exp + CLOCK_SKEW_SECONDS < now {
        return Err("expired");
    }
    if claims.nonce.as_deref() != Some(check.nonce) {
        return Err("nonce");
    }
    if let Some(since) = check.authenticated_since {
        match claims.auth_time {
            Some(auth_time) if auth_time + CLOCK_SKEW_SECONDS >= since => {}
            _ => return Err("auth_time"),
        }
    }
    if claims.sub.is_empty() || claims.sub.len() > 256 {
        return Err("sub");
    }
    Ok(())
}

fn unavailable(provider: Provider, step: &str, error: &reqwest::Error) -> ProviderFailure {
    tracing::warn!(provider = provider.as_str(), step, %error, "provider request failed");
    ProviderFailure::Unavailable
}

async fn read_json<T: serde::de::DeserializeOwned>(
    provider: Provider,
    step: &str,
    response: reqwest::Response,
) -> Result<T, ProviderFailure> {
    let status = response.status();
    if !status.is_success() {
        tracing::warn!(provider = provider.as_str(), step, %status, "provider answered with an error");
        return Err(ProviderFailure::Unavailable);
    }
    response
        .json()
        .await
        .map_err(|error| unavailable(provider, step, &error))
}

/// The name a new account starts with: the provider's name, else the email's local part, at most 100 characters.
fn display_name(name: Option<&str>, email: Option<&str>) -> String {
    let name = name
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .or_else(|| email.and_then(|email| email.split('@').next()))
        .filter(|name| !name.is_empty())
        .unwrap_or("Orbit user");
    name.chars().take(100).collect()
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: Option<String>,
    id_token: Option<String>,
    error: Option<String>,
}

#[derive(Deserialize)]
struct DiscoveryDocument {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    userinfo_endpoint: Option<String>,
    token_endpoint_auth_methods_supported: Option<Vec<String>>,
}

#[derive(Deserialize)]
struct UserInfo {
    sub: String,
    #[serde(flatten)]
    profile: OidcClaims,
}

#[derive(Deserialize)]
struct GoogleUserInfo {
    sub: String,
    email: Option<String>,
    email_verified: Option<bool>,
    name: Option<String>,
}

#[derive(Deserialize)]
struct GithubUser {
    id: u64,
    login: String,
    name: Option<String>,
}

#[derive(Deserialize)]
struct GithubEmail {
    email: String,
    primary: bool,
    verified: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkce_challenge_matches_the_rfc_7636_example() {
        assert_eq!(
            pkce_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
        assert!(is_pkce_challenge(
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        ));
        assert!(!is_pkce_challenge(
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-c"
        ));
        assert!(!is_pkce_challenge(
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw+cM"
        ));
    }

    #[test]
    fn native_redirects_match_exactly() {
        let redirects =
            NativeRedirects::new(&["exp://100.64.0.5:8082/--/auth/callback".to_owned()]);
        assert!(redirects.allows("orbit://auth/callback"));
        assert!(redirects.allows("exp://100.64.0.5:8082/--/auth/callback"));
        for refused in [
            "orbit://auth/callback/",
            "orbit://auth/callback?x=1",
            "orbit://evil",
            "https://evil.example/auth/callback",
            "exp://100.64.0.5:8082/--/auth/callback2",
            "exp://evil.example:8082/--/auth/callback",
        ] {
            assert!(!redirects.allows(refused), "{refused}");
        }
        assert!(!NativeRedirects::default().allows("exp://100.64.0.5:8082/--/auth/callback"));
    }

    #[test]
    fn new_accounts_get_a_short_non_empty_name() {
        assert_eq!(display_name(Some("  Ada Lovelace "), None), "Ada Lovelace");
        assert_eq!(display_name(Some(" "), Some("ada@example.com")), "ada");
        assert_eq!(display_name(None, None), "Orbit user");
        assert_eq!(display_name(Some(&"x".repeat(300)), None).len(), 100);
    }

    #[tokio::test]
    async fn the_authorization_url_carries_state_pkce_and_scope() {
        let client = ProviderClient::new(ProviderEndpoints::default());
        let credentials = ProviderCredentials {
            client_id: "id.apps.googleusercontent.com".to_owned(),
            client_secret: "secret".to_owned(),
            oidc: None,
        };
        let url = client
            .authorization_url(
                Provider::Google,
                &credentials,
                &AuthorizationRequest {
                    redirect_uri: "https://orbit.example/api/v1/auth/providers/google/callback",
                    state: "state-1",
                    pkce_challenge: "challenge-1",
                    nonce: "nonce-1",
                    freshness: Freshness::ForceLogin,
                },
            )
            .await
            .unwrap();
        assert_eq!(
            url.as_str(),
            "https://accounts.google.com/o/oauth2/v2/auth?client_id=id.apps.googleusercontent.com\
             &redirect_uri=https%3A%2F%2Forbit.example%2Fapi%2Fv1%2Fauth%2Fproviders%2Fgoogle%2Fcallback\
             &response_type=code&scope=openid+email+profile&state=state-1&code_challenge=challenge-1\
             &code_challenge_method=S256&prompt=select_account&max_age=0"
        );
    }
}
