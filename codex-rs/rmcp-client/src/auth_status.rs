use std::collections::HashMap;
use std::time::Duration;

use anyhow::Error;
use anyhow::Result;
use codex_protocol::protocol::McpAuthStatus;
use reqwest::Client;
use reqwest::StatusCode;
use reqwest::Url;
use reqwest::header::AUTHORIZATION;
use reqwest::header::HeaderMap;
use serde::Deserialize;
use tracing::debug;

use crate::OAuthCredentialsStoreMode;
use crate::oauth::has_oauth_tokens;
use crate::utils::apply_default_headers;
use crate::utils::build_default_headers;

const DISCOVERY_TIMEOUT: Duration = Duration::from_secs(5);
const OAUTH_DISCOVERY_HEADER: &str = "MCP-Protocol-Version";
const OAUTH_DISCOVERY_VERSION: &str = "2024-11-05";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamableHttpOAuthDiscovery {
    pub scopes_supported: Option<Vec<String>>,
}

/// Determine the authentication status for a streamable HTTP MCP server.
pub async fn determine_streamable_http_auth_status(
    server_name: &str,
    url: &str,
    bearer_token_env_var: Option<&str>,
    http_headers: Option<HashMap<String, String>>,
    env_http_headers: Option<HashMap<String, String>>,
    store_mode: OAuthCredentialsStoreMode,
) -> Result<McpAuthStatus> {
    if bearer_token_env_var.is_some() {
        return Ok(McpAuthStatus::BearerToken);
    }

    let default_headers = build_default_headers(http_headers, env_http_headers)?;
    if default_headers.contains_key(AUTHORIZATION) {
        return Ok(McpAuthStatus::BearerToken);
    }

    if has_oauth_tokens(server_name, url, store_mode)? {
        return Ok(McpAuthStatus::OAuth);
    }

    match discover_streamable_http_oauth_with_headers(url, &default_headers).await {
        Ok(Some(_)) => Ok(McpAuthStatus::NotLoggedIn),
        Ok(None) => Ok(McpAuthStatus::Unsupported),
        Err(error) => {
            debug!(
                "failed to detect OAuth support for MCP server `{server_name}` at {url}: {error:?}"
            );
            Ok(McpAuthStatus::Unsupported)
        }
    }
}

/// Attempt to determine whether a streamable HTTP MCP server advertises OAuth login.
pub async fn supports_oauth_login(url: &str) -> Result<bool> {
    Ok(discover_streamable_http_oauth(
        url, /*http_headers*/ None, /*env_http_headers*/ None,
    )
    .await?
    .is_some())
}

pub async fn discover_streamable_http_oauth(
    url: &str,
    http_headers: Option<HashMap<String, String>>,
    env_http_headers: Option<HashMap<String, String>>,
) -> Result<Option<StreamableHttpOAuthDiscovery>> {
    let default_headers = build_default_headers(http_headers, env_http_headers)?;
    discover_streamable_http_oauth_with_headers(url, &default_headers).await
}

async fn discover_streamable_http_oauth_with_headers(
    url: &str,
    default_headers: &HeaderMap,
) -> Result<Option<StreamableHttpOAuthDiscovery>> {
    let base_url = Url::parse(url)?;

    // Use no_proxy to avoid a bug in the system-configuration crate that
    // can result in a panic. See #8912.
    let builder = Client::builder().timeout(DISCOVERY_TIMEOUT).no_proxy();
    let client = apply_default_headers(builder, default_headers).build()?;

    let Some(authorization_server_metadata) =
        discover_authorization_server_metadata(&client, &base_url, url).await?
    else {
        return Ok(None);
    };

    let protected_resource_metadata =
        discover_protected_resource_metadata(&client, &base_url, url).await?;

    Ok(streamable_http_oauth_discovery_from_metadata(
        authorization_server_metadata,
        protected_resource_metadata,
    ))
}

async fn discover_authorization_server_metadata(
    client: &Client,
    base_url: &Url,
    original_url: &str,
) -> Result<Option<AuthorizationServerMetadata>> {
    let mut last_error: Option<Error> = None;
    for candidate_path in authorization_server_discovery_paths(base_url.path()) {
        let mut discovery_url = base_url.clone();
        discovery_url.set_path(&candidate_path);

        let response = match client
            .get(discovery_url.clone())
            .header(OAUTH_DISCOVERY_HEADER, OAUTH_DISCOVERY_VERSION)
            .send()
            .await
        {
            Ok(response) => response,
            Err(err) => {
                last_error = Some(err.into());
                continue;
            }
        };

        if response.status() != StatusCode::OK {
            continue;
        }

        let metadata = match response.json::<AuthorizationServerMetadata>().await {
            Ok(metadata) => metadata,
            Err(err) => {
                last_error = Some(err.into());
                continue;
            }
        };

        if metadata.authorization_endpoint.is_some() && metadata.token_endpoint.is_some() {
            return Ok(Some(metadata));
        }
    }

    if let Some(err) = last_error {
        debug!("OAuth discovery requests failed for {original_url}: {err:?}");
    }

    Ok(None)
}

   #[derive(Debug, Deserialize)]
struct AuthorizationServerMetadata {
    #[serde(default)]
    authorization_endpoint: Option<String>,
    #[serde(default)]
    token_endpoint: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ProtectedResourceMetadata {
    #[serde(default)]
    scopes_supported: Option<Vec<String>>,
}

async fn discover_protected_resource_metadata(
    client: &Client,
    base_url: &Url,
    original_url: &str,
) -> Result<Option<ProtectedResourceMetadata>> {
    let mut last_error: Option<Error> = None;
    for candidate_path in protected_resource_metadata_paths(base_url.path()) {
        let mut discovery_url = base_url.clone();
        discovery_url.set_path(&candidate_path);

        let response = match client
            .get(discovery_url.clone())
            .header(OAUTH_DISCOVERY_HEADER, OAUTH_DISCOVERY_VERSION)
            .send()
            .await
        {
            Ok(response) => response,
            Err(err) => {
                last_error = Some(err.into());
                continue;
            }
        };

        if response.status() != StatusCode::OK {
            continue;
        }

        let metadata = match response.json::<ProtectedResourceMetadata>().await {
            Ok(metadata) => metadata,
            Err(err) => {
                last_error = Some(err.into());
                continue;
            }
        };

        return Ok(Some(metadata));
    }

    if let Some(err) = last_error {
        debug!("Protected resource metadata requests failed for {original_url}: {err:?}");
    }

    Ok(None)
}

fn streamable_http_oauth_discovery_from_metadata(
    authorization_server_metadata: AuthorizationServerMetadata,
    protected_resource_metadata: Option<ProtectedResourceMetadata>,
) -> Option<StreamableHttpOAuthDiscovery> {
    if authorization_server_metadata
        .authorization_endpoint
        .is_none()
        || authorization_server_metadata.token_endpoint.is_none()
    {
        return None;
    }

    Some(StreamableHttpOAuthDiscovery {
        scopes_supported: protected_resource_metadata
            .and_then(|metadata| normalize_scopes(metadata.scopes_supported)),
    })
}

fn normalize_scopes(scopes_supported: Option<Vec<String>>) -> Option<Vec<String>> {
    let scopes_supported = scopes_supported?;

    let mut normalized = Vec::new();
    for scope in scopes_supported {
        let scope = scope.trim();
        if scope.is_empty() {
            continue;
        }
        let scope = scope.to_string();
        if !normalized.contains(&scope) {
            normalized.push(scope);
        }
    }

    if normalized.is_empty() {
        None
    } else {
        Some(normalized)
    }
}

/// Implements RFC 8414 section 3.1 for discovering well-known oauth endpoints.
/// This is a requirement for MCP servers to support OAuth.
/// https://datatracker.ietf.org/doc/html/rfc8414#section-3.1
/// https://github.com/modelcontextprotocol/rust-sdk/blob/main/crates/rmcp/src/transport/auth.rs#L182
fn authorization_server_discovery_paths(base_path: &str) -> Vec<String> {
    let trimmed = base_path.trim_start_matches('/').trim_end_matches('/');
    let canonical = "/.well-known/oauth-authorization-server".to_string();

    if trimmed.is_empty() {
        return vec![canonical];
    }

    let mut candidates = Vec::new();
    let mut push_unique = |candidate: String| {
        if !candidates.contains(&candidate) {
            candidates.push(candidate);
        }
    };

    push_unique(format!("{canonical}/{trimmed}"));
    push_unique(format!("/{trimmed}/.well-known/oauth-authorization-server"));
    push_unique(canonical);

    candidates
}

fn protected_resource_metadata_paths(base_path: &str) -> Vec<String> {
    let trimmed = base_path.trim_start_matches('/').trim_end_matches('/');
    let canonical = "/.well-known/oauth-protected-resource".to_string();

    if trimmed.is_empty() {
        return vec![canonical];
    }

    vec![format!("{canonical}/{trimmed}"), canonical]
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Json;
    use axum::Router;
    use axum::routing::get;
    use pretty_assertions::assert_eq;
    use serial_test::serial;
    use std::collections::HashMap;
    use std::ffi::OsString;
    use tokio::task::JoinHandle;

    struct TestServer {
        url: String,
        handle: JoinHandle<()>,
    }

    impl Drop for TestServer {
        fn drop(&mut self) {
            self.handle.abort();
        }
    }

    async fn spawn_oauth_discovery_server(metadata: serde_json::Value) -> TestServer {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let address = listener.local_addr().expect("listener should have address");
        let app = Router::new().route(
            "/.well-known/oauth-authorization-server/mcp",
            get({
                let metadata = metadata.clone();
                move || {
                    let metadata = metadata.clone();
                    async move { Json(metadata) }
                }
            }),
        );
        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("server should run");
        });

        TestServer {
            url: format!("http://{address}/mcp"),
            handle,
        }
    }

    async fn spawn_oauth_discovery_server_with_protected_resource_metadata(
        authorization_server_metadata: serde_json::Value,
        protected_resource_metadata: serde_json::Value,
    ) -> TestServer {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let address = listener.local_addr().expect("listener should have address");
        let app = Router::new()
            .route(
                "/.well-known/oauth-authorization-server/mcp",
                get({
                    let metadata = authorization_server_metadata.clone();
                    move || {
                        let metadata = metadata.clone();
                        async move { Json(metadata) }
                    }
                }),
            )
            .route(
                "/.well-known/oauth-protected-resource/mcp",
                get({
                    let metadata = protected_resource_metadata.clone();
                    move || {
                        let metadata = metadata.clone();
                        async move { Json(metadata) }
                    }
                }),
            );
        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("server should run");
        });

        TestServer {
            url: format!("http://{address}/mcp"),
            handle,
        }
    }

    struct EnvVarGuard {
        key: String,
        original: Option<OsString>,
    }

    impl EnvVarGuard {
        fn set(key: &str, value: &str) -> Self {
            let original = std::env::var_os(key);
            unsafe {
                std::env::set_var(key, value);
            }
            Self {
                key: key.to_string(),
                original,
            }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            if let Some(value) = &self.original {
                unsafe {
                    std::env::set_var(&self.key, value);
                }
            } else {
                unsafe {
                    std::env::remove_var(&self.key);
                }
            }
        }
    }

    #[tokio::test]
    async fn determine_auth_status_uses_bearer_token_when_authorization_header_present() {
        let status = determine_streamable_http_auth_status(
            "server",
            "not-a-url",
            None,
            Some(HashMap::from([(
                "Authorization".to_string(),
                "Bearer token".to_string(),
            )])),
            None,
            OAuthCredentialsStoreMode::Keyring,
        )
        .await
        .expect("status should compute");

        assert_eq!(status, McpAuthStatus::BearerToken);
    }

    #[tokio::test]
    #[serial(auth_status_env)]
    async fn determine_auth_status_uses_bearer_token_when_env_authorization_header_present() {
        let _guard = EnvVarGuard::set("CODEX_RMCP_CLIENT_AUTH_STATUS_TEST_TOKEN", "Bearer token");
        let status = determine_streamable_http_auth_status(
            "server",
            "not-a-url",
            None,
            None,
            Some(HashMap::from([(
                "Authorization".to_string(),
                "CODEX_RMCP_CLIENT_AUTH_STATUS_TEST_TOKEN".to_string(),
            )])),
            OAuthCredentialsStoreMode::Keyring,
        )
        .await
        .expect("status should compute");

        assert_eq!(status, McpAuthStatus::BearerToken);
    }

    #[tokio::test]
    async fn discover_streamable_http_oauth_returns_normalized_scopes() {
        let server = spawn_oauth_discovery_server_with_protected_resource_metadata(
            serde_json::json!({
                "authorization_endpoint": "https://example.com/authorize",
                "token_endpoint": "https://example.com/token",
            }),
            serde_json::json!({
                "authorization_servers": ["https://auth.example.com"],
                "scopes_supported": ["profile", " email ", "profile", "", "   "],
            }),
        )
        .await;

        let discovery = discover_streamable_http_oauth(&server.url, None, None)
            .await
            .expect("discovery should succeed")
            .expect("oauth support should be detected");

        assert_eq!(
            discovery.scopes_supported,
            Some(vec!["profile".to_string(), "email".to_string()])
        );
    }

    #[tokio::test]
    async fn discover_streamable_http_oauth_prefers_protected_resource_scopes() {
        let server = spawn_oauth_discovery_server_with_protected_resource_metadata(
            serde_json::json!({
                "authorization_endpoint": "https://auth.example.com/authorize",
                "token_endpoint": "https://auth.example.com/token",
                "scopes_supported": ["wrong-scope"],
            }),
            serde_json::json!({
                "authorization_servers": ["https://auth.example.com"],
                "scopes_supported": ["profile", " email ", "profile", "", "   "],
            }),
        )
        .await;

        let discovery = discover_streamable_http_oauth(&server.url, None, None)
            .await
            .expect("discovery should succeed")
            .expect("oauth support should be detected");

        assert_eq!(
            discovery.scopes_supported,
            Some(vec!["profile".to_string(), "email".to_string()])
        );
    }

    #[tokio::test]
    async fn discover_streamable_http_oauth_ignores_empty_scopes() {
        let server = spawn_oauth_discovery_server_with_protected_resource_metadata(
            serde_json::json!({
                "authorization_endpoint": "https://example.com/authorize",
                "token_endpoint": "https://example.com/token",
                "scopes_supported": ["wrong-scope"],
            }),
            serde_json::json!({
                "authorization_servers": ["https://auth.example.com"],
                "scopes_supported": ["", "   "],
            }),
        )
        .await;

        let discovery = discover_streamable_http_oauth(&server.url, None, None)
            .await
            .expect("discovery should succeed")
            .expect("oauth support should be detected");

        assert_eq!(discovery.scopes_supported, None);
    }

    #[tokio::test]
    async fn supports_oauth_login_does_not_require_scopes_supported() {
        let server = spawn_oauth_discovery_server(serde_json::json!({
            "authorization_endpoint": "https://example.com/authorize",
            "token_endpoint": "https://example.com/token",
        }))
        .await;

        let supported = supports_oauth_login(&server.url)
            .await
            .expect("support check should succeed");

        assert!(supported);
    }

    #[test]
    fn streamable_http_oauth_discovery_prefers_protected_resource_scopes_without_fallback() {
        let discovery = streamable_http_oauth_discovery_from_metadata(
            AuthorizationServerMetadata {
                authorization_endpoint: Some("https://auth.example.com/authorize".to_string()),
                token_endpoint: Some("https://auth.example.com/token".to_string()),
            },
            Some(ProtectedResourceMetadata {
                scopes_supported: Some(vec![
                    "profile".to_string(),
                    " email ".to_string(),
                    "profile".to_string(),
                    "".to_string(),
                ]),
            }),
        )
        .expect("oauth support should be detected");

        assert_eq!(
            discovery.scopes_supported,
            Some(vec!["profile".to_string(), "email".to_string()])
        );
    }

    #[test]
    fn streamable_http_oauth_discovery_omits_scopes_when_protected_resource_metadata_has_none() {
        let discovery = streamable_http_oauth_discovery_from_metadata(
            AuthorizationServerMetadata {
                authorization_endpoint: Some("https://auth.example.com/authorize".to_string()),
                token_endpoint: Some("https://auth.example.com/token".to_string()),
            },
            Some(ProtectedResourceMetadata {
                scopes_supported: Some(vec!["".to_string(), "   ".to_string()]),
            }),
        )
        .expect("oauth support should be detected");

        assert_eq!(discovery.scopes_supported, None);
    }

    #[test]
    fn protected_resource_metadata_paths_try_endpoint_path_before_root() {
        assert_eq!(
            protected_resource_metadata_paths("/public/mcp"),
            vec![
                "/.well-known/oauth-protected-resource/public/mcp".to_string(),
                "/.well-known/oauth-protected-resource".to_string(),
            ]
        );
    }
}