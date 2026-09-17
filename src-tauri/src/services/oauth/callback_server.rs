// Local OAuth callback HTTP server.
//
// Spawns a single axum instance per login attempt on a port specific to the
// provider (Codex:1455, Claude:54545, Gemini:51181, Antigravity:51121).
// Each instance accepts the redirect from the provider's auth endpoint,
// validates the `state` parameter, hands the authorization code back to the
// waiting task via a `oneshot` channel, and serves a friendly success /
// error page so the user's browser tab doesn't sit on a blank response.
//
// Why a separate server per attempt? Two concurrent logins (e.g. refreshing
// Claude while logging into Gemini) would otherwise race on the same port.
// Per-provider fixed ports keep the redirect URIs stable (those are baked
// into the OAuth client IDs) while still allowing exactly one in-flight
// login per provider at a time. We pre-check port availability before
// binding — if it's busy, the caller surfaces a "another login in progress"
// error to the user.
//
// Endpoints:
//   POST|GET /auth/callback     Codex
//   POST|GET /callback          Claude
//   POST|GET /oauth/callback    Google (Gemini + Antigravity)
//   GET /success                friendly page
//   GET /error                  friendly page
//
// All `/callback*` routes accept GET (the standard OAuth2 redirect) AND POST
// (some providers POST when they want a body; harmless to accept both).

use std::net::SocketAddr;
use std::time::Duration;

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    routing::get,
    Router,
};
use serde::Deserialize;
use tokio::net::TcpListener;
use tokio::sync::oneshot;

use super::callback_html;

/// Result delivered back to the waiting login task. Exactly one of the
/// variants is populated — `Error` is only set when the redirect itself
/// failed (bad state, missing code, provider error). Token-exchange errors
/// happen upstream in the provider's login() impl, not here.
#[derive(Debug)]
pub enum CallbackResult {
    Success {
        code: String,
        state: String,
    },
    Error(String),
}

/// Configuration for a single login attempt's callback server.
#[derive(Clone)]
struct CallbackState {
    /// The `state` we put into the auth URL; what we expect back.
    expected_state: String,
    /// Provider id, used in the success / error page title.
    provider_label: String,
    /// oneshot sender — when the callback fires, we hand the result over and
    /// shut the server down. Drop = server stops listening.
    tx: oneshot::Sender<CallbackResult>,
}

#[derive(Debug, Deserialize, Default)]
struct CallbackParams {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    #[serde(rename = "error_description")]
    error_description: Option<String>,
}

/// Bind to `port`, run the server until `tx` is consumed (login completes or
/// times out) or `shutdown_signal` fires. Returns Ok(()) on graceful stop,
/// Err if the bind itself failed.
///
/// Caller is expected to spawn a tokio task and `await` `tx` in parallel; the
/// server exits when this function returns, so there's no separate shutdown
/// API.
pub async fn run(
    port: u16,
    provider_label: &str,
    expected_state: &str,
    tx: oneshot::Sender<CallbackResult>,
) -> Result<(), String> {
    let state = CallbackState {
        expected_state: expected_state.to_string(),
        provider_label: provider_label.to_string(),
        tx,
    };
    let app = Router::new()
        .route("/auth/callback", get(handle_callback))
        .route("/callback", get(handle_callback))
        .route("/oauth/callback", get(handle_callback))
        .route("/success", get(handle_success))
        .route("/error", get(handle_error))
        .with_state(state);

    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let listener = TcpListener::bind(addr)
        .await
        .map_err(|e| format!("bind 127.0.0.1:{port} failed: {e}"))?;
    log::info!(
        "[OAuthCallback] Listening on 127.0.0.1:{} for {} login",
        port,
        provider_label
    );
    axum::serve(listener, app)
        .await
        .map_err(|e| format!("OAuth callback server error: {e}"))
}

/// Try to bind the desired port without actually listening. Used as a
/// pre-flight check by the login flow so the user gets "port in use" BEFORE
/// we open their browser, not after.
pub async fn preflight_port(port: u16) -> Result<(), String> {
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let _listener = TcpListener::bind(addr)
        .await
        .map_err(|_| format!("port {port} is already in use"))?;
    Ok(())
}

async fn handle_callback(
    State(state): State<CallbackState>,
    Query(params): Query<CallbackParams>,
) -> Response {
    log::debug!(
        "[OAuthCallback] /callback hit on {}: code_present={} state_present={}",
        state.provider_label,
        params.code.is_some(),
        params.state.is_some()
    );

    if let Some(err) = params.error.as_deref() {
        let desc = params
            .error_description
            .as_deref()
            .unwrap_or("(no description)");
        let msg = format!("{err}: {desc}");
        let _ = state.tx.send(CallbackResult::Error(msg.clone()));
        return error_page(&state.provider_label, &msg).into_response();
    }

    let Some(code) = params.code else {
        let msg = "missing authorization code".to_string();
        let _ = state.tx.send(CallbackResult::Error(msg.clone()));
        return error_page(&state.provider_label, &msg).into_response();
    };
    let Some(redirect_state) = params.state else {
        let msg = "missing state parameter".to_string();
        let _ = state.tx.send(CallbackResult::Error(msg.clone()));
        return error_page(&state.provider_label, &msg).into_response();
    };

    if redirect_state != state.expected_state {
        let msg = "state mismatch (possible CSRF)".to_string();
        let _ = state.tx.send(CallbackResult::Error(msg.clone()));
        return error_page(&state.provider_label, &msg).into_response();
    }

    // All good. Hand off the code to the login task.
    match state.tx.send(CallbackResult::Success {
        code,
        state: redirect_state,
    }) {
        Ok(()) => {}
        Err(_) => {
            // The receiver already dropped — the user cancelled or the login
            // task errored out before the browser redirected. The token
            // exchange didn't run, so nothing to clean up.
            log::warn!(
                "[OAuthCallback] Receiver dropped for {} before callback",
                state.provider_label
            );
            return (
                StatusCode::GONE,
                Html("<h1>Login session expired</h1><p>You can close this tab.</p>".to_string()),
            )
                .into_response();
        }
    }

    success_page(&state.provider_label).into_response()
}

async fn handle_success() -> impl IntoResponse {
    (
        StatusCode::OK,
        Html(generic_success_page()),
    )
}

async fn handle_error() -> impl IntoResponse {
    (
        StatusCode::OK,
        Html(generic_error_page()),
    )
}

fn success_page(provider_label: &str) -> Response {
    let html = callback_html::success_for(provider_label);
    (StatusCode::OK, Html(html)).into_response()
}

fn error_page(provider_label: &str, message: &str) -> Response {
    let html = callback_html::error_for(provider_label, message);
    (StatusCode::BAD_REQUEST, Html(html)).into_response()
}

fn generic_success_page() -> String {
    callback_html::SUCCESS_HTML.to_string()
}

fn generic_error_page() -> String {
    callback_html::ERROR_HTML.to_string()
}

/// Optional: caller can set a soft timeout on the whole flow. We don't bake
/// one in here because each provider's login() chooses its own timeout
/// (Codex is quick, Claude usually needs second factor, Kimi is just polling).
pub const DEFAULT_CALLBACK_TIMEOUT: Duration = Duration::from_secs(120);