use axum::{
    extract::{Query, Request, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, Uri},
    middleware::{self, Next},
    response::{
        sse::{Event, KeepAlive, Sse},
        IntoResponse, Response,
    },
    routing::{get, post},
    Json, Router,
};
use futures_util::stream;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::HashMap, convert::Infallible, time::Duration};
use tauri::{AppHandle, Emitter, Listener};
use tokio::sync::{oneshot, Mutex};
use uuid::Uuid;

const LOCAL_ADDR: &str = "127.0.0.1:8453";
const COMMAND_EVENT: &str = "remote-ui-invoke";
const MAX_REQUEST_BYTES: usize = 10 * 1024 * 1024;
const COMMAND_TIMEOUT: Duration = Duration::from_secs(15 * 60);

const REMOTE_EVENTS: &[&str] = &[
    "audio-levels",
    "builtin-ai-download-progress",
    "chunk-drop-warning",
    "mic-device-switched",
    "mic-recovery-exhausted",
    "mic-swap-failed",
    "mic-unavailable",
    "model-config-updated",
    "model-download-complete",
    "parakeet-model-download-complete",
    "recording-paused",
    "recording-resumed",
    "recording-started",
    "recording-starting",
    "recording-stop-complete",
    "recording-stopped",
    "speech-detected",
    "transcript-error",
    "transcription-complete",
    "transcription-error",
    "transcript-update",
];
const REMOTE_EMITS: &[&str] = &["model-config-updated"];

#[derive(Clone, Default)]
pub(crate) struct RemoteBridgeState {
    app: Option<AppHandle>,
    pending: std::sync::Arc<Mutex<HashMap<String, oneshot::Sender<Result<Value, String>>>>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct InvokeRequest {
    command: String,
    #[serde(default = "empty_args")]
    args: Value,
}

fn empty_args() -> Value {
    Value::Object(serde_json::Map::new())
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct InvokeEvent {
    request_id: String,
    command: String,
    args: Value,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct InvokeReply {
    request_id: String,
    success: bool,
    result: Option<Value>,
    error: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EventEnvelope {
    event: String,
    id: u64,
    payload: Value,
}

#[derive(Deserialize)]
struct EventQuery {
    name: String,
}

#[derive(Deserialize)]
struct EmitRequest {
    name: String,
    payload: Value,
}

#[derive(Serialize)]
struct ErrorBody {
    error: String,
}

pub(crate) fn start(app: AppHandle, state: RemoteBridgeState) {
    tauri::async_runtime::spawn(async move {
        let listener = match tokio::net::TcpListener::bind(LOCAL_ADDR).await {
            Ok(listener) => listener,
            Err(error) => {
                log::error!("Could not start the tailnet-only Meetily UI service: {error}");
                return;
            }
        };

        let state = RemoteBridgeState {
            app: Some(app),
            pending: state.pending,
        };
        let router = Router::new()
            .route("/api/invoke", post(invoke))
            .route("/api/emit", post(emit_event))
            .route("/api/events", get(events))
            .fallback(serve_asset)
            .with_state(state)
            .layer(axum::extract::DefaultBodyLimit::max(MAX_REQUEST_BYTES))
            .layer(middleware::from_fn(authorize_request));

        log::info!("Meetily remote UI service listening on {LOCAL_ADDR}");
        if let Err(error) = axum::serve(listener, router).await {
            log::error!("Meetily remote UI service stopped: {error}");
        }
    });
}

#[tauri::command]
pub(crate) async fn remote_ui_reply(
    state: tauri::State<'_, RemoteBridgeState>,
    reply: InvokeReply,
) -> Result<(), String> {
    let sender = state
        .pending
        .lock()
        .await
        .remove(&reply.request_id)
        .ok_or_else(|| "Remote command request expired".to_string())?;
    let result = if reply.success {
        Ok(reply.result.unwrap_or(Value::Null))
    } else {
        Err(reply
            .error
            .unwrap_or_else(|| "Meetily command failed".to_string()))
    };
    sender
        .send(result)
        .map_err(|_| "Remote command caller disconnected".to_string())
}

async fn authorize_request(request: Request, next: Next) -> Response {
    let headers = request.headers();
    if !has_tailscale_identity(
        headers
            .get("tailscale-user-login")
            .and_then(|value| value.to_str().ok()),
    ) {
        return error_response(StatusCode::FORBIDDEN, "Tailscale identity required");
    }

    let path = request.uri().path();
    let requires_origin = path == "/api/events"
        || (path.starts_with("/api/")
            && request.method() != Method::GET
            && request.method() != Method::HEAD);
    if requires_origin {
        let origin = headers.get("origin").and_then(|value| value.to_str().ok());
        let host = headers
            .get("x-forwarded-host")
            .or_else(|| headers.get("host"))
            .and_then(|value| value.to_str().ok());
        if !origin
            .zip(host)
            .is_some_and(|(origin, host)| same_origin_https(origin, host))
        {
            return error_response(StatusCode::FORBIDDEN, "Same-origin HTTPS request required");
        }
    }

    let mut response = next.run(request).await;
    response.headers_mut().insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    response
        .headers_mut()
        .insert("referrer-policy", HeaderValue::from_static("same-origin"));
    response
        .headers_mut()
        .insert("x-frame-options", HeaderValue::from_static("DENY"));
    response.headers_mut().insert(
        "permissions-policy",
        HeaderValue::from_static("camera=(), geolocation=(), microphone=()"),
    );
    response.headers_mut().insert(
        "content-security-policy",
        HeaderValue::from_static("default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; media-src 'self' blob:; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"),
    );
    response
}

async fn invoke(
    State(state): State<RemoteBridgeState>,
    headers: HeaderMap,
    Json(request): Json<InvokeRequest>,
) -> Response {
    if headers
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .is_none_or(|value| !value.to_ascii_lowercase().starts_with("application/json"))
    {
        return error_response(StatusCode::UNSUPPORTED_MEDIA_TYPE, "JSON required");
    }
    if !remote_command_allowed(&request.command) {
        return error_response(
            StatusCode::FORBIDDEN,
            "Command is not enabled for remote use",
        );
    }

    let Some(app) = state.app.as_ref() else {
        return error_response(StatusCode::SERVICE_UNAVAILABLE, "Meetily is not ready");
    };
    let request_id = Uuid::new_v4().to_string();
    let (sender, receiver) = oneshot::channel();
    state
        .pending
        .lock()
        .await
        .insert(request_id.clone(), sender);

    let event = InvokeEvent {
        request_id: request_id.clone(),
        command: request.command.clone(),
        args: request.args,
    };
    if let Err(error) = app.emit_to("main", COMMAND_EVENT, event) {
        state.pending.lock().await.remove(&request_id);
        log::warn!("Failed to dispatch remote Meetily command: {error}");
        return error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "Meetily window is not ready",
        );
    }

    match tokio::time::timeout(COMMAND_TIMEOUT, receiver).await {
        Ok(Ok(Ok(result))) => {
            Json(sanitize_remote_result(&request.command, result)).into_response()
        }
        Ok(Ok(Err(error))) => error_response(StatusCode::BAD_REQUEST, &error),
        Ok(Err(_)) => error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "Meetily command ended unexpectedly",
        ),
        Err(_) => {
            state.pending.lock().await.remove(&request_id);
            error_response(StatusCode::GATEWAY_TIMEOUT, "Meetily command timed out")
        }
    }
}

async fn emit_event(
    State(state): State<RemoteBridgeState>,
    Json(request): Json<EmitRequest>,
) -> Response {
    if !remote_event_allowed(&request.name) {
        return error_response(StatusCode::FORBIDDEN, "Event is not enabled for remote use");
    }
    let Some(app) = state.app.as_ref() else {
        return error_response(StatusCode::SERVICE_UNAVAILABLE, "Meetily is not ready");
    };
    match app.emit(&request.name, request.payload) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => {
            log::warn!("Failed to emit remote Meetily event: {error}");
            error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "Meetily event could not be delivered",
            )
        }
    }
}

async fn events(
    State(state): State<RemoteBridgeState>,
    Query(query): Query<EventQuery>,
) -> Response {
    if !REMOTE_EVENTS.contains(&query.name.as_str()) {
        return error_response(StatusCode::FORBIDDEN, "Event is not enabled for remote use");
    }
    let Some(app) = state.app.as_ref().cloned() else {
        return error_response(StatusCode::SERVICE_UNAVAILABLE, "Meetily is not ready");
    };

    let event_name = query.name;
    let (sender, receiver) = tokio::sync::mpsc::channel::<Event>(16);
    let event_for_callback = event_name.clone();
    let callback_sender = sender.clone();
    let event_id = app.listen(&event_name, move |event| {
        let mut payload = serde_json::from_str(event.payload())
            .unwrap_or_else(|_| Value::String(event.payload().to_string()));
        redact_sensitive_fields(&mut payload);
        let envelope = EventEnvelope {
            event: event_for_callback.clone(),
            id: 0,
            payload,
        };
        if let Ok(data) = serde_json::to_string(&envelope) {
            let _ = callback_sender.try_send(Event::default().data(data));
        }
    });

    let app_for_cleanup = app.clone();
    let cleanup_sender = sender.clone();
    tauri::async_runtime::spawn(async move {
        cleanup_sender.closed().await;
        app_for_cleanup.unlisten(event_id);
    });

    let stream = stream::unfold(receiver, |mut receiver| async move {
        receiver
            .recv()
            .await
            .map(|event| (Ok::<Event, Infallible>(event), receiver))
    });
    Sse::new(stream)
        .keep_alive(KeepAlive::default())
        .into_response()
}

async fn serve_asset(State(state): State<RemoteBridgeState>, request: Request) -> Response {
    if request.method() != Method::GET && request.method() != Method::HEAD {
        return error_response(StatusCode::NOT_FOUND, "Not found");
    }
    let Some(app) = state.app.as_ref() else {
        return error_response(StatusCode::SERVICE_UNAVAILABLE, "Meetily is not ready");
    };
    let Some(path) = asset_path(request.uri()) else {
        return error_response(StatusCode::NOT_FOUND, "Not found");
    };
    let asset = asset_candidates(&path)
        .into_iter()
        .find_map(|candidate| app.asset_resolver().get(candidate));
    let Some(asset) = asset else {
        return error_response(StatusCode::NOT_FOUND, "Not found");
    };

    let mut response = Response::new(if request.method() == Method::HEAD {
        axum::body::Body::empty()
    } else {
        axum::body::Body::from(asset.bytes)
    });
    *response.status_mut() = StatusCode::OK;
    response.headers_mut().insert(
        "content-type",
        HeaderValue::from_str(&asset.mime_type)
            .unwrap_or_else(|_| HeaderValue::from_static("application/octet-stream")),
    );
    response
        .headers_mut()
        .insert("cache-control", HeaderValue::from_static("no-cache"));
    response
}

fn asset_path(uri: &Uri) -> Option<String> {
    let path = uri.path().strip_prefix('/').unwrap_or(uri.path());
    if path.contains('%') || path.contains('\\') {
        return None;
    }
    if path.is_empty() {
        return Some("index.html".to_string());
    }
    let components = std::path::Path::new(path).components().collect::<Vec<_>>();
    if components.is_empty()
        || components
            .iter()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        return None;
    }
    Some(path.to_string())
}

fn asset_candidates(path: &str) -> Vec<String> {
    let path = path.trim_end_matches('/');
    let mut candidates = vec![path.to_string()];
    if std::path::Path::new(path).extension().is_none() {
        candidates.push(format!("{path}.html"));
        candidates.push(format!("{path}/index.html"));
    }
    candidates
}

fn error_response(status: StatusCode, message: &str) -> Response {
    (
        status,
        Json(ErrorBody {
            error: message.to_string(),
        }),
    )
        .into_response()
}

fn sanitize_remote_result(command: &str, mut result: Value) -> Value {
    if matches!(command, "api_get_api_key" | "api_get_transcript_api_key") {
        return Value::String(String::new());
    }
    redact_sensitive_fields(&mut result);
    result
}

fn redact_sensitive_fields(value: &mut Value) {
    match value {
        Value::Object(fields) => {
            for (name, value) in fields {
                let name = name.to_ascii_lowercase().replace('-', "_");
                if name.contains("api_key")
                    || name.contains("apikey")
                    || name.contains("access_token")
                    || name.contains("refresh_token")
                    || name.ends_with("accesstoken")
                    || name.ends_with("refreshtoken")
                    || name == "token"
                    || name.ends_with("_token")
                    || name.ends_with("token")
                    || name == "secret"
                    || name.ends_with("_secret")
                    || name.ends_with("secret")
                {
                    *value = Value::String(String::new());
                } else {
                    redact_sensitive_fields(value);
                }
            }
        }
        Value::Array(items) => items.iter_mut().for_each(redact_sensitive_fields),
        _ => {}
    }
}

fn has_tailscale_identity(login: Option<&str>) -> bool {
    login.is_some_and(|value| {
        let value = value.trim();
        !value.is_empty() && !value.contains(',')
    })
}

fn same_origin_https(origin: &str, host: &str) -> bool {
    if host.contains(',') || host.contains('/') || host.contains('\\') {
        return false;
    }
    let Ok(origin) = url::Url::parse(origin) else {
        return false;
    };
    let Ok(request_host) = url::Url::parse(&format!("https://{host}")) else {
        return false;
    };

    origin.scheme() == "https"
        && origin.username().is_empty()
        && origin.password().is_none()
        && matches!(origin.path(), "" | "/")
        && origin.query().is_none()
        && origin.fragment().is_none()
        && origin.host_str() == request_host.host_str()
        && origin.port_or_known_default() == request_host.port_or_known_default()
}

fn remote_event_allowed(event: &str) -> bool {
    REMOTE_EMITS.contains(&event)
}

fn remote_command_allowed(command: &str) -> bool {
    matches!(
        command,
        "api_cancel_summary"
            | "api_delete_meeting"
            | "api_disconnect_openai_chatgpt"
            | "api_get_api_key"
            | "api_get_auto_generate_setting"
            | "api_get_custom_openai_config"
            | "api_get_meeting"
            | "api_get_meeting_detected_summary_language"
            | "api_get_meeting_metadata"
            | "api_get_meeting_summary_language"
            | "api_get_meeting_transcripts"
            | "api_get_meetings"
            | "api_get_model_config"
            | "api_get_summary"
            | "api_get_transcript_api_key"
            | "api_get_transcript_config"
            | "api_list_templates"
            | "api_openai_chatgpt_connected"
            | "api_process_transcript"
            | "api_save_custom_openai_config"
            | "api_save_meeting_summary"
            | "api_save_meeting_detected_summary_language"
            | "api_save_meeting_summary_language"
            | "api_save_meeting_title"
            | "api_save_model_config"
            | "api_save_transcript"
            | "api_save_transcript_config"
            | "api_search_transcripts"
            | "api_test_custom_openai_connection"
            | "api_detect_transcript_summary_language"
            | "builtin_ai_cancel_download"
            | "builtin_ai_delete_model"
            | "builtin_ai_download_model"
            | "builtin_ai_get_available_summary_model"
            | "builtin_ai_get_models_directory"
            | "builtin_ai_get_model_info"
            | "builtin_ai_get_recommended_model"
            | "builtin_ai_is_model_ready"
            | "builtin_ai_list_models"
            | "cancel_import_command"
            | "cancel_retranscription_command"
            | "check_first_launch"
            | "complete_onboarding"
            | "delete_ollama_model"
            | "get_active_audio_output"
            | "get_anthropic_models"
            | "get_audio_backend_info"
            | "get_audio_devices"
            | "get_current_audio_backend"
            | "get_database_directory"
            | "get_default_recordings_folder_path"
            | "get_meeting_folder_path"
            | "get_groq_models"
            | "get_notification_settings"
            | "get_ollama_models"
            | "get_openai_models"
            | "get_openrouter_models"
            | "get_onboarding_status"
            | "get_recording_meeting_name"
            | "get_recording_preferences"
            | "get_recording_state"
            | "get_transcription_status"
            | "get_transcript_history"
            | "is_recording"
            | "parakeet_cancel_download"
            | "parakeet_delete_corrupted_model"
            | "parakeet_download_model"
            | "parakeet_get_available_models"
            | "parakeet_get_current_model"
            | "parakeet_get_models_directory"
            | "parakeet_has_available_models"
            | "parakeet_init"
            | "parakeet_is_model_loaded"
            | "parakeet_load_model"
            | "parakeet_retry_download"
            | "parakeet_validate_model_ready"
            | "pause_recording"
            | "plugin:app|version"
            | "pull_ollama_model"
            | "resume_recording"
            | "save_onboarding_status_cmd"
            | "set_audio_backend"
            | "set_language_preference"
            | "set_notification_settings"
            | "set_recording_preferences"
            | "start_audio_level_monitoring"
            | "start_recording"
            | "start_recording_with_devices_and_meeting"
            | "stop_audio_level_monitoring"
            | "stop_recording"
            | "whisper_cancel_download"
            | "whisper_delete_corrupted_model"
            | "whisper_download_model"
            | "whisper_get_available_models"
            | "whisper_get_models_directory"
            | "whisper_get_current_model"
            | "whisper_has_available_models"
            | "whisper_init"
            | "whisper_is_model_loaded"
            | "whisper_load_model"
            | "whisper_validate_model_ready"
    )
}

#[cfg(test)]
mod tests {
    use super::{
        asset_candidates, asset_path, has_tailscale_identity, redact_sensitive_fields,
        remote_command_allowed, remote_event_allowed, same_origin_https, sanitize_remote_result,
    };
    use axum::http::Uri;
    use serde_json::json;

    #[test]
    fn tailnet_identity_must_be_present_and_nonempty() {
        assert!(has_tailscale_identity(Some("tony@example.com")));
        assert!(!has_tailscale_identity(None));
        assert!(!has_tailscale_identity(Some("  ")));
        assert!(!has_tailscale_identity(Some("user-a,user-b")));
    }

    #[test]
    fn mutating_requests_require_the_same_https_origin_and_host() {
        assert!(same_origin_https(
            "https://archtony.tail4f65b2.ts.net:8452",
            "archtony.tail4f65b2.ts.net:8452"
        ));
        assert!(!same_origin_https(
            "http://archtony.tail4f65b2.ts.net:8452",
            "archtony.tail4f65b2.ts.net:8452"
        ));
        assert!(!same_origin_https(
            "https://attacker.example",
            "archtony.tail4f65b2.ts.net:8452"
        ));
        assert!(!same_origin_https(
            "not an origin",
            "archtony.tail4f65b2.ts.net:8452"
        ));
        assert!(!same_origin_https(
            "https://archtony.tail4f65b2.ts.net:8451",
            "archtony.tail4f65b2.ts.net:8452"
        ));
    }

    #[test]
    fn only_explicitly_reviewed_commands_are_remote_callable() {
        assert!(remote_command_allowed("api_get_meetings"));
        assert!(remote_command_allowed("start_recording"));
        assert!(remote_command_allowed("api_save_model_config"));
        assert!(remote_command_allowed("plugin:app|version"));
        assert!(!remote_command_allowed("remote_ui_reply"));
        assert!(!remote_command_allowed("read_audio_file"));
        assert!(!remote_command_allowed("open_external_url"));
        assert!(!remote_command_allowed("api_connect_openai_chatgpt"));
        assert!(!remote_command_allowed("select_and_validate_audio_command"));
        assert!(!remote_command_allowed("plugin:fs|read_file"));
        assert!(!remote_command_allowed("unknown_command"));
        assert!(remote_event_allowed("model-config-updated"));
        assert!(!remote_event_allowed("unknown-event"));
    }

    #[test]
    fn static_asset_routes_reject_traversal_and_encoded_paths() {
        assert_eq!(
            asset_path(&Uri::from_static("/")),
            Some("index.html".into())
        );
        assert_eq!(
            asset_candidates("settings"),
            vec!["settings", "settings.html", "settings/index.html"]
        );
        assert_eq!(
            asset_path(&Uri::from_static("/_next/static/app.js")),
            Some("_next/static/app.js".into())
        );
        assert_eq!(asset_path(&Uri::from_static("/%2e%2e/secrets")), None);
        assert_eq!(asset_path(&Uri::from_static("/../secrets")), None);
        assert_eq!(asset_path(&Uri::from_static("/a\\..\\secrets")), None);
    }

    #[test]
    fn remote_responses_never_return_secret_fields() {
        let mut value = json!({
            "apiKey": "secret",
            "chatgptOAuthAccessToken": "token",
            "clientSecret": "secret",
            "nested": { "refresh_token": "refresh", "model": "gpt-6-luna" }
        });
        redact_sensitive_fields(&mut value);
        assert_eq!(
            value,
            json!({
                "apiKey": "",
                "chatgptOAuthAccessToken": "",
                "clientSecret": "",
                "nested": { "refresh_token": "", "model": "gpt-6-luna" }
            })
        );
        assert_eq!(
            sanitize_remote_result("api_get_api_key", json!("secret")),
            json!("")
        );
    }
}
