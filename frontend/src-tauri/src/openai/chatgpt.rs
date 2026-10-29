use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use once_cell::sync::Lazy;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tauri::State;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::timeout,
};
use url::Url;
use uuid::Uuid;

use crate::{database::repositories::setting::SettingsRepository, state::AppState};

const AUTHORIZE_URL: &str = "https://auth.openai.com/api/accounts/authorize";
const TOKEN_URL: &str = "https://auth.openai.com/api/accounts/oauth/token";
const RESOURCE: &str = "https://api.openai.com/v1";
const CLIENT_ID: &str = "dynamic_agent_client";
const CALLBACK_PORT: u16 = 1455;
const CALLBACK_PATH: &str = "/auth/callback";
const REDIRECT_URI: &str = "http://127.0.0.1:1455/auth/callback";
const DIRECT_TOKEN_SCOPE: &str = "chatgpt.tokens.use.direct";
const SCOPE: &str = "openid profile email offline_access resource.invoke chatgpt.tokens.use.direct";
const LOGIN_TIMEOUT: Duration = Duration::from_secs(300);
const REFRESH_MARGIN_MS: u128 = 180_000;
const KEYRING_SERVICE: &str = "com.meetily.app";
const KEYRING_USER: &str = "openai-chatgpt";
static TOKEN_REFRESH_LOCK: Lazy<tokio::sync::Mutex<()>> = Lazy::new(|| tokio::sync::Mutex::new(()));

#[derive(Serialize, Deserialize)]
pub(crate) struct ChatGPTCredential {
    access_token: String,
    refresh_token: String,
    expires_at_ms: u128,
    client_id: String,
    device_id: String,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    refresh_token: String,
    scope: String,
    expires_in: u64,
    id_token: Option<String>,
}

struct AuthorizationCode {
    code: String,
    client_id: String,
}

fn random_urlsafe() -> String {
    let mut bytes = [0; 32];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn pkce_pair() -> (String, String) {
    let verifier = random_urlsafe();
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    (verifier, challenge)
}

fn build_authorization_url(
    device_id: &str,
    state: &str,
    nonce: &str,
    challenge: &str,
) -> Result<String, String> {
    let host_id =
        Uuid::parse_str(device_id).map_err(|_| "Invalid ChatGPT installation ID".to_string())?;
    let mut url = Url::parse(AUTHORIZE_URL).map_err(|e| e.to_string())?;
    url.query_pairs_mut()
        .append_pair("client_id", CLIENT_ID)
        .append_pair("agent_name_hint", "Meetily")
        .append_pair("ext_agent_host_id", &format!("urn:uuid:{host_id}"))
        .append_pair("response_type", "code")
        .append_pair("redirect_uri", REDIRECT_URI)
        .append_pair("resource", RESOURCE)
        .append_pair("scope", SCOPE)
        .append_pair("state", state)
        .append_pair("code_challenge", challenge)
        .append_pair("code_challenge_method", "S256")
        .append_pair("nonce", nonce);
    Ok(url.into())
}

fn credential_from_response(
    token: TokenResponse,
    client_id: String,
    device_id: String,
) -> Result<ChatGPTCredential, String> {
    if token.access_token.trim().is_empty()
        || token.refresh_token.trim().is_empty()
        || token.expires_in == 0
        || !token
            .scope
            .split_whitespace()
            .any(|scope| scope == DIRECT_TOKEN_SCOPE)
    {
        return Err("OpenAI did not grant the required ChatGPT subscription access".to_string());
    }
    Ok(ChatGPTCredential {
        access_token: token.access_token,
        refresh_token: token.refresh_token,
        expires_at_ms: now_ms().saturating_add(token.expires_in as u128 * 1000),
        client_id,
        device_id,
    })
}

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

async fn exchange_token(form: &[(&str, &str)]) -> Result<TokenResponse, String> {
    let response = reqwest::Client::new()
        .post(TOKEN_URL)
        .form(form)
        .timeout(Duration::from_secs(20))
        .send()
        .await
        .map_err(|_| "Could not reach OpenAI to complete ChatGPT sign-in".to_string())?;
    if !response.status().is_success() {
        return Err(format!(
            "OpenAI sign-in failed (HTTP {})",
            response.status()
        ));
    }
    response
        .json::<TokenResponse>()
        .await
        .map_err(|_| "OpenAI returned an invalid sign-in response".to_string())
}

async fn wait_for_callback(
    listener: TcpListener,
    expected_state: &str,
) -> Result<AuthorizationCode, String> {
    timeout(LOGIN_TIMEOUT, async move {
        loop {
            let (mut stream, _) = listener
                .accept()
                .await
                .map_err(|_| "Could not receive the ChatGPT sign-in callback".to_string())?;
            match read_callback(&mut stream, expected_state).await {
                Ok(result) => return Ok(result),
                Err(error)
                    if error == "Unexpected ChatGPT sign-in callback path"
                        || error == "ChatGPT sign-in state validation failed" =>
                {
                    continue;
                }
                Err(error) => return Err(error),
            }
        }
    })
    .await
    .map_err(|_| "ChatGPT sign-in timed out; try connecting again".to_string())?
}

async fn read_callback(
    stream: &mut TcpStream,
    expected_state: &str,
) -> Result<AuthorizationCode, String> {
    let mut buffer = [0; 8192];
    let bytes_read = stream
        .read(&mut buffer)
        .await
        .map_err(|_| "Could not read the ChatGPT sign-in callback".to_string())?;
    let request = std::str::from_utf8(&buffer[..bytes_read])
        .map_err(|_| "Invalid ChatGPT sign-in callback".to_string())?;
    let target = request
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .filter(|target| target.starts_with('/') && !target.starts_with("//"))
        .ok_or_else(|| "Invalid ChatGPT sign-in callback".to_string())?;
    let callback_url = Url::parse(&format!("http://127.0.0.1{target}"))
        .map_err(|_| "Invalid ChatGPT sign-in callback".to_string())?;

    if callback_url.path() != CALLBACK_PATH {
        send_callback_page(stream, "404 Not Found", "Sign-in callback not found.").await;
        return Err("Unexpected ChatGPT sign-in callback path".to_string());
    }
    if callback_url.query_pairs().any(|(key, _)| key == "error") {
        send_callback_page(stream, "400 Bad Request", "ChatGPT sign-in was cancelled.").await;
        return Err("ChatGPT sign-in was cancelled".to_string());
    }
    let pairs = callback_url.query_pairs().into_owned().collect::<Vec<_>>();
    let parameter = |name: &str| {
        pairs
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.clone())
    };
    if parameter("state").as_deref() != Some(expected_state) {
        send_callback_page(stream, "400 Bad Request", "Sign-in state did not match.").await;
        return Err("ChatGPT sign-in state validation failed".to_string());
    }
    let code = parameter("code")
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "OpenAI callback did not include an authorization code".to_string())?;
    let client_id = parameter("client_id")
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "OpenAI callback did not include a client ID".to_string())?;
    send_callback_page(
        stream,
        "200 OK",
        "ChatGPT connected. You can close this browser tab and return to Meetily.",
    )
    .await;
    Ok(AuthorizationCode { code, client_id })
}

async fn send_callback_page(stream: &mut TcpStream, status: &str, message: &str) {
    let body = format!(
        "<!doctype html><html><meta charset=\"utf-8\"><title>Meetily</title><body>{message}</body></html>"
    );
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes()).await;
}

async fn exchange_authorization_code(
    authorization: AuthorizationCode,
    verifier: &str,
    device_id: &str,
) -> Result<ChatGPTCredential, String> {
    let token = exchange_token(&[
        ("grant_type", "authorization_code"),
        ("client_id", &authorization.client_id),
        ("code", &authorization.code),
        ("code_verifier", verifier),
        ("redirect_uri", REDIRECT_URI),
        ("resource", RESOURCE),
    ])
    .await?;
    if token
        .id_token
        .as_deref()
        .unwrap_or_default()
        .trim()
        .is_empty()
    {
        return Err("OpenAI sign-in response was missing its identity token".to_string());
    }
    credential_from_response(token, authorization.client_id, device_id.to_string())
}

async fn refresh_credential(credential: &ChatGPTCredential) -> Result<ChatGPTCredential, String> {
    let token = exchange_token(&[
        ("grant_type", "refresh_token"),
        ("client_id", &credential.client_id),
        ("refresh_token", &credential.refresh_token),
        ("resource", RESOURCE),
    ])
    .await?;
    credential_from_response(
        token,
        credential.client_id.clone(),
        credential.device_id.clone(),
    )
}

async fn save_credential(credential: &ChatGPTCredential) -> Result<(), String> {
    let serialized = serde_json::to_string(credential)
        .map_err(|_| "Could not store ChatGPT sign-in".to_string())?;
    tokio::task::spawn_blocking(move || {
        let entry = keyring::Entry::new(KEYRING_SERVICE, KEYRING_USER)
            .map_err(|_| "System credential store is unavailable".to_string())?;
        entry.set_password(&serialized).map_err(|_| {
            "Could not store ChatGPT sign-in in the system credential store".to_string()
        })
    })
    .await
    .map_err(|_| "System credential store operation failed".to_string())?
}

async fn read_credential() -> Result<Option<ChatGPTCredential>, String> {
    let serialized = tokio::task::spawn_blocking(|| {
        let entry = keyring::Entry::new(KEYRING_SERVICE, KEYRING_USER)
            .map_err(|_| "System credential store is unavailable".to_string())?;
        match entry.get_password() {
            Ok(value) => Ok(Some(value)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(_) => {
                Err("Could not read ChatGPT sign-in from the system credential store".to_string())
            }
        }
    })
    .await
    .map_err(|_| "System credential store operation failed".to_string())??;
    serialized
        .map(|value| {
            serde_json::from_str(&value).map_err(|_| {
                "Stored ChatGPT sign-in is invalid; reconnect your account".to_string()
            })
        })
        .transpose()
}

pub(crate) async fn get_access_token() -> Result<String, String> {
    let credential = read_credential()
        .await?
        .ok_or_else(|| "Sign in with ChatGPT in Meetily's summary settings first".to_string())?;
    if credential.expires_at_ms > now_ms().saturating_add(REFRESH_MARGIN_MS) {
        return Ok(credential.access_token);
    }

    let _refresh_guard = TOKEN_REFRESH_LOCK.lock().await;
    let credential = read_credential()
        .await?
        .ok_or_else(|| "Sign in with ChatGPT in Meetily's summary settings first".to_string())?;
    if credential.expires_at_ms > now_ms().saturating_add(REFRESH_MARGIN_MS) {
        return Ok(credential.access_token);
    }
    let refreshed = refresh_credential(&credential)
        .await
        .map_err(|_| "ChatGPT sign-in expired; reconnect your account in Meetily".to_string())?;
    let access_token = refreshed.access_token.clone();
    save_credential(&refreshed).await?;
    Ok(access_token)
}

pub(crate) async fn is_connected() -> Result<bool, String> {
    Ok(read_credential().await?.is_some())
}

pub(crate) async fn delete_credential() -> Result<(), String> {
    tokio::task::spawn_blocking(|| {
        let entry = keyring::Entry::new(KEYRING_SERVICE, KEYRING_USER)
            .map_err(|_| "System credential store is unavailable".to_string())?;
        match entry.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(_) => {
                Err("Could not remove ChatGPT sign-in from the system credential store".to_string())
            }
        }
    })
    .await
    .map_err(|_| "System credential store operation failed".to_string())?
}

#[tauri::command]
pub async fn api_connect_openai_chatgpt(state: State<'_, AppState>) -> Result<(), String> {
    let pool = state.db_manager.pool();
    let device_id = match SettingsRepository::get_openai_chatgpt_device_id(pool)
        .await
        .map_err(|_| "Could not read Meetily installation ID".to_string())?
    {
        Some(device_id) if Uuid::parse_str(&device_id).is_ok() => device_id,
        _ => {
            let device_id = Uuid::new_v4().to_string();
            SettingsRepository::save_openai_chatgpt_device_id(pool, &device_id)
                .await
                .map_err(|_| "Could not save Meetily installation ID".to_string())?;
            device_id
        }
    };

    let listener = TcpListener::bind(("127.0.0.1", CALLBACK_PORT))
        .await
        .map_err(|_| "ChatGPT sign-in callback port 1455 is already in use".to_string())?;
    let state = random_urlsafe();
    let nonce = random_urlsafe();
    let (verifier, challenge) = pkce_pair();
    let authorization_url = build_authorization_url(&device_id, &state, &nonce, &challenge)?;
    crate::api::api::open_external_url(authorization_url).await?;

    let authorization = wait_for_callback(listener, &state).await?;
    let credential = exchange_authorization_code(authorization, &verifier, &device_id).await?;
    save_credential(&credential).await
}

#[tauri::command]
pub async fn api_openai_chatgpt_connected() -> Result<bool, String> {
    is_connected().await
}

#[tauri::command]
pub async fn api_disconnect_openai_chatgpt() -> Result<(), String> {
    delete_credential().await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authorization_url_uses_pkce_chatgpt_scope_and_loopback_callback() {
        let url = Url::parse(
            &build_authorization_url(
                "123e4567-e89b-12d3-a456-426614174000",
                "state-value",
                "nonce-value",
                "challenge-value",
            )
            .unwrap(),
        )
        .unwrap();
        let query = url
            .query_pairs()
            .into_owned()
            .collect::<std::collections::HashMap<_, _>>();
        assert_eq!(query.get("response_type").map(String::as_str), Some("code"));
        assert_eq!(
            query.get("code_challenge_method").map(String::as_str),
            Some("S256")
        );
        assert_eq!(query.get("state").map(String::as_str), Some("state-value"));
        assert!(query["scope"]
            .split_whitespace()
            .any(|scope| scope == DIRECT_TOKEN_SCOPE));
        assert_eq!(
            query.get("redirect_uri").map(String::as_str),
            Some(REDIRECT_URI)
        );
    }

    #[test]
    fn rejects_token_response_without_direct_chatgpt_scope() {
        let token = TokenResponse {
            access_token: "access".into(),
            refresh_token: "refresh".into(),
            scope: "openid profile".into(),
            expires_in: 3600,
            id_token: Some("identity".into()),
        };
        assert!(credential_from_response(
            token,
            "client".into(),
            "123e4567-e89b-12d3-a456-426614174000".into()
        )
        .is_err());
    }
}
