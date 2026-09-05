//! Native Local AI for RipleyOS.
//!
//! The hosted renderer gets a deliberately narrow surface: two fixed, revision-
//! pinned GGUF models; download/status/load/complete/remove/clear. It cannot pass a
//! URL, executable, or filesystem path. On macOS llama.cpp runs through Metal,
//! avoiding WKWebView's missing WebGPU support and keeping the model resident
//! between turns.

use std::{
    fs,
    num::NonZeroU32,
    path::{Path, PathBuf},
    sync::Mutex,
    time::{Duration, Instant},
};

use encoding_rs::UTF_8;
use llama_cpp_2::{
    context::params::LlamaContextParams,
    llama_backend::LlamaBackend,
    llama_batch::LlamaBatch,
    model::{params::LlamaModelParams, AddBos, LlamaChatMessage, LlamaModel},
    sampling::LlamaSampler,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tauri::{AppHandle, Emitter, Manager, State};
use tauri_plugin_dialog::{DialogExt, MessageDialogButtons};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const FREE_ID: &str = "Qwen3.5-2B-q4f16_1-MLC";
const PRO_ID: &str = "Qwen3.5-4B-q4f16_1-MLC";
const CONTEXT_TOKENS: u32 = 4096;

struct ModelSpec {
    id: &'static str,
    filename: &'static str,
    url: &'static str,
    bytes: u64,
    sha256: &'static str,
}

const MODELS: &[ModelSpec] = &[
    ModelSpec {
        id: FREE_ID,
        filename: "qwen3.5-2b-q4_k_m.gguf",
        url: "https://huggingface.co/bartowski/Qwen_Qwen3.5-2B-GGUF/resolve/aa8fd585135c95b4e77a2aa2323d538026abb722/Qwen_Qwen3.5-2B-Q4_K_M.gguf",
        bytes: 1_315_634_944,
        sha256: "1e277e5d06f17a145fc0d6b1c152a0bcc6323ac2f87f1bacdbb85c71c8660e24",
    },
    ModelSpec {
        id: PRO_ID,
        filename: "qwen3.5-4b-q4_k_m.gguf",
        url: "https://huggingface.co/bartowski/Qwen_Qwen3.5-4B-GGUF/resolve/3516418eb75fd2cdf56058f112b403ff47020775/Qwen_Qwen3.5-4B-Q4_K_M.gguf",
        bytes: 2_856_936_480,
        sha256: "2c08bf55fdde0b2e4bd52fa7dc6d49150e83eac997910cf014b7221c172a4b20",
    },
];

fn spec(id: &str) -> Result<&'static ModelSpec, String> {
    MODELS
        .iter()
        .find(|model| model.id == id)
        .ok_or_else(|| "unknown Local AI model id".to_string())
}

fn model_dir(app: &AppHandle) -> Result<PathBuf, String> {
    let path = app
        .path()
        .app_data_dir()
        .map_err(|e| format!("no app data directory: {e}"))?
        .join("local-ai");
    fs::create_dir_all(&path).map_err(|e| format!("create Local AI directory: {e}"))?;
    Ok(path)
}

fn model_path(app: &AppHandle, model: &ModelSpec) -> Result<PathBuf, String> {
    Ok(model_dir(app)?.join(model.filename))
}

fn installed(path: &Path, model: &ModelSpec) -> bool {
    fs::metadata(path)
        .map(|meta| meta.is_file() && meta.len() == model.bytes)
        .unwrap_or(false)
}

struct NativeRuntime {
    // Drop the model before the process-wide backend.
    model: Option<LlamaModel>,
    model_id: Option<String>,
    backend: LlamaBackend,
}

pub struct NativeLocalAiState {
    runtime: Mutex<NativeRuntime>,
    download: tokio::sync::Mutex<()>,
}

impl NativeLocalAiState {
    pub fn new() -> Result<Self, String> {
        let mut backend = LlamaBackend::init().map_err(|e| format!("initialize llama.cpp: {e}"))?;
        backend.void_logs();
        Ok(Self {
            runtime: Mutex::new(NativeRuntime {
                model: None,
                model_id: None,
                backend,
            }),
            download: tokio::sync::Mutex::new(()),
        })
    }
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NativeLocalAiStatus {
    model_id: String,
    installed: bool,
    loaded: bool,
    bytes: u64,
    downloaded_bytes: u64,
    downloading: bool,
    runtime: String,
    accelerated: bool,
}

fn runtime_label(backend: &LlamaBackend) -> (String, bool) {
    #[cfg(target_os = "macos")]
    {
        let accelerated = backend.supports_gpu_offload();
        (
            if accelerated {
                "llama.cpp · Metal"
            } else {
                "llama.cpp · CPU"
            }
            .to_string(),
            accelerated,
        )
    }
    #[cfg(not(target_os = "macos"))]
    {
        ("llama.cpp · CPU".to_string(), false)
    }
}

#[tauri::command]
pub async fn local_ai_status(
    app: AppHandle,
    state: State<'_, NativeLocalAiState>,
    model_id: String,
) -> Result<NativeLocalAiStatus, String> {
    let model = spec(&model_id)?;
    let path = model_path(&app, model)?;
    let downloading = state.download.try_lock().is_err();
    // The runtime mutex is held for the whole of a load or generation. Take it
    // on the blocking pool — parking an async worker for seconds would starve
    // the IPC executor when the UI polls status during a turn.
    let handle = app.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let state = handle.state::<NativeLocalAiState>();
        let runtime = state
            .runtime
            .lock()
            .map_err(|_| "Local AI runtime lock poisoned".to_string())?;
        let (label, accelerated) = runtime_label(&runtime.backend);
        let is_installed = installed(&path, model);
        let downloaded_bytes = if is_installed {
            model.bytes
        } else {
            fs::metadata(path.with_extension("gguf.part"))
                .map(|meta| meta.len().min(model.bytes))
                .unwrap_or(0)
        };
        Ok(NativeLocalAiStatus {
            model_id,
            installed: is_installed,
            loaded: runtime.model_id.as_deref() == Some(model.id) && runtime.model.is_some(),
            bytes: model.bytes,
            downloaded_bytes,
            downloading,
            runtime: label,
            accelerated,
        })
    })
    .await
    .map_err(|e| format!("native status task failed: {e}"))?
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct DownloadProgress {
    model_id: String,
    received_bytes: u64,
    total_bytes: u64,
    phase: String,
    text: String,
}

fn emit_progress(
    app: &AppHandle,
    model: &ModelSpec,
    received: u64,
    phase: &str,
    text: impl Into<String>,
) {
    let _ = app.emit(
        "local-ai-progress",
        DownloadProgress {
            model_id: model.id.to_string(),
            received_bytes: received,
            total_bytes: model.bytes,
            phase: phase.to_string(),
            text: text.into(),
        },
    );
}

async fn download_client(app: &AppHandle, allow_clearnet: bool) -> Result<reqwest::Client, String> {
    let mode = crate::wallet::scanner::read_routing_mode(app);
    let mut builder = reqwest::Client::builder()
        .user_agent(concat!("ripley-terminal/", env!("CARGO_PKG_VERSION")))
        .connect_timeout(Duration::from_secs(30))
        .timeout(Duration::from_secs(60 * 60))
        // Large Hugging Face/Xet responses have occasionally ended with an h2
        // body decoder error. HTTP/1.1 plus Range retries is slower to connect
        // but much more resilient for multi-gigabyte model artifacts.
        .http1_only();
    match mode.as_str() {
        "tor" if !allow_clearnet => {
            return Err(
                "Native model download needs explicit permission to use clearnet while Tor routing is active."
                    .into(),
            );
        }
        "custom" => {
            let proxy = crate::wallet::scanner::read_proxy_address(app);
            if proxy.trim().is_empty() {
                return Err("Custom routing is selected but no proxy is configured.".into());
            }
            builder = builder.proxy(reqwest::Proxy::all(&proxy).map_err(|e| e.to_string())?);
        }
        _ => {}
    }
    builder.build().map_err(|e| e.to_string())
}

fn parse_content_range(value: &str) -> Option<(u64, u64, u64)> {
    let (range, total) = value.strip_prefix("bytes ")?.split_once('/')?;
    let (start, end) = range.split_once('-')?;
    let start = start.parse().ok()?;
    let end = end.parse().ok()?;
    let total = total.parse().ok()?;
    (start <= end && end < total).then_some((start, end, total))
}

fn validate_download_response(
    response: &reqwest::Response,
    offset: u64,
    expected_total: u64,
) -> Result<(), String> {
    if offset == 0 {
        if response.status() != reqwest::StatusCode::OK {
            return Err(format!(
                "model server returned {} for a full download",
                response.status()
            ));
        }
        if let Some(length) = response.content_length() {
            if length != expected_total {
                return Err(format!(
                    "model size mismatch before download: expected {expected_total}, got {length}"
                ));
            }
        }
        return Ok(());
    }

    if response.status() != reqwest::StatusCode::PARTIAL_CONTENT {
        return Err(format!(
            "model server did not honor resume at byte {offset} (returned {})",
            response.status()
        ));
    }
    let header = response
        .headers()
        .get(reqwest::header::CONTENT_RANGE)
        .and_then(|value| value.to_str().ok())
        .and_then(parse_content_range)
        .ok_or_else(|| "model server returned an invalid Content-Range".to_string())?;
    if header.0 != offset || header.2 != expected_total {
        return Err(format!(
            "model resume mismatch: requested byte {offset} of {expected_total}, got bytes {}-{}/{}",
            header.0, header.1, header.2
        ));
    }
    if let Some(length) = response.content_length() {
        let expected_length = header.1 - header.0 + 1;
        if length != expected_length {
            return Err(format!(
                "model resume length mismatch: expected {expected_length}, got {length}"
            ));
        }
    }
    Ok(())
}

fn detailed_reqwest_error(error: &reqwest::Error) -> String {
    use std::error::Error;

    let mut message = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        let text = cause.to_string();
        if !message.contains(&text) {
            message.push_str(": ");
            message.push_str(&text);
        }
        source = cause.source();
    }
    message
}

async fn confirm_tor_clearnet_download(
    app: &AppHandle,
    allow_clearnet: bool,
) -> Result<(), String> {
    if crate::wallet::scanner::read_routing_mode(app) != "tor" {
        return Ok(());
    }
    if !allow_clearnet {
        return Err(
            "Native model download needs explicit permission to use clearnet while Tor routing is active."
                .into(),
        );
    }
    // The hosted renderer is deliberately untrusted. Its boolean is only a
    // request to show this shell-owned dialog; it can never authorize the
    // privacy downgrade by itself.
    let handle = app.clone();
    let approved = tauri::async_runtime::spawn_blocking(move || {
        handle
            .dialog()
            .message(
                "RipleyOS is using Tor, but the native Local AI model downloader cannot use the bundled Tor transport yet.\n\nDownloading now connects directly to Hugging Face over clearnet and reveals your IP. Prompts and inference still remain on this device.",
            )
            .title("Allow direct Local AI download?")
            .buttons(MessageDialogButtons::OkCancelCustom(
                "Download over clearnet".into(),
                "Cancel".into(),
            ))
            .blocking_show()
    })
    .await
    .map_err(|e| format!("native download confirmation failed: {e}"))?;
    if approved {
        Ok(())
    } else {
        Err("Native model download cancelled.".into())
    }
}

#[tauri::command]
pub async fn local_ai_download(
    app: AppHandle,
    state: State<'_, NativeLocalAiState>,
    model_id: String,
    allow_clearnet: Option<bool>,
) -> Result<NativeLocalAiStatus, String> {
    let model = spec(&model_id)?;
    let _download_guard = state.download.lock().await;
    let target = model_path(&app, model)?;
    if installed(&target, model) {
        drop(_download_guard);
        return local_ai_status(app, state, model_id).await;
    }

    confirm_tor_clearnet_download(&app, allow_clearnet.unwrap_or(false)).await?;
    let part = target.with_extension("gguf.part");
    let client = download_client(&app, allow_clearnet.unwrap_or(false)).await?;
    let mut received = tokio::fs::metadata(&part)
        .await
        .map(|meta| meta.len())
        .unwrap_or(0);
    if received > model.bytes {
        tokio::fs::remove_file(&part)
            .await
            .map_err(|e| format!("discard oversized partial model: {e}"))?;
        received = 0;
    }
    let mut digest = Sha256::new();
    if received > 0 {
        let mut existing = tokio::fs::File::open(&part)
            .await
            .map_err(|e| format!("open partial model: {e}"))?;
        let mut buffer = vec![0_u8; 1024 * 1024];
        loop {
            let count = existing
                .read(&mut buffer)
                .await
                .map_err(|e| format!("read partial model: {e}"))?;
            if count == 0 {
                break;
            }
            digest.update(&buffer[..count]);
        }
    }
    emit_progress(
        &app,
        model,
        received,
        "downloading",
        if received == 0 {
            "Starting native model download…".to_string()
        } else {
            format!("Resuming {}…", model.filename)
        },
    );
    let mut file = tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&part)
        .await
        .map_err(|e| format!("create partial model: {e}"))?;
    let mut last_emit = Instant::now();
    let mut reconnects = 0_u32;
    const MAX_RECONNECTS: u32 = 12;
    while received < model.bytes {
        let mut request = client.get(model.url);
        if received > 0 {
            request = request.header(reqwest::header::RANGE, format!("bytes={received}-"));
        }
        let mut response = match request.send().await {
            Ok(response) => response,
            Err(error) => {
                reconnects += 1;
                if reconnects > MAX_RECONNECTS {
                    return Err(format!(
                        "download model failed after {MAX_RECONNECTS} reconnects: {}. The partial download was preserved.",
                        detailed_reqwest_error(&error)
                    ));
                }
                emit_progress(
                    &app,
                    model,
                    received,
                    "downloading",
                    format!("Connection interrupted. Resuming… ({reconnects}/{MAX_RECONNECTS})"),
                );
                tokio::time::sleep(Duration::from_millis(
                    500 * 2_u64.pow(reconnects.min(4) - 1),
                ))
                .await;
                continue;
            }
        };
        validate_download_response(&response, received, model.bytes)?;

        let mut stream_error = None;
        loop {
            match response.chunk().await {
                Ok(Some(chunk)) => {
                    received = received
                        .checked_add(chunk.len() as u64)
                        .ok_or_else(|| "model size overflow".to_string())?;
                    if received > model.bytes {
                        let _ = tokio::fs::remove_file(&part).await;
                        return Err("downloaded model exceeded its pinned size".into());
                    }
                    digest.update(&chunk);
                    file.write_all(&chunk)
                        .await
                        .map_err(|e| format!("write model: {e}"))?;
                    if last_emit.elapsed() >= Duration::from_millis(250) {
                        emit_progress(
                            &app,
                            model,
                            received,
                            "downloading",
                            format!("Downloading {}…", model.filename),
                        );
                        last_emit = Instant::now();
                    }
                }
                Ok(None) => break,
                Err(error) => {
                    stream_error = Some(detailed_reqwest_error(&error));
                    break;
                }
            }
        }
        if received == model.bytes {
            break;
        }

        file.flush()
            .await
            .map_err(|e| format!("flush partial model: {e}"))?;
        reconnects += 1;
        if reconnects > MAX_RECONNECTS {
            return Err(format!(
                "download model failed after {MAX_RECONNECTS} reconnects: {}. The partial download was preserved.",
                stream_error.unwrap_or_else(|| "server ended the response early".to_string())
            ));
        }
        emit_progress(
            &app,
            model,
            received,
            "downloading",
            format!("Connection interrupted. Resuming… ({reconnects}/{MAX_RECONNECTS})"),
        );
        tokio::time::sleep(Duration::from_millis(
            500 * 2_u64.pow(reconnects.min(4) - 1),
        ))
        .await;
    }
    file.flush()
        .await
        .map_err(|e| format!("flush model: {e}"))?;
    drop(file);

    let actual_hash = hex::encode(digest.finalize());
    if received != model.bytes || actual_hash != model.sha256 {
        let _ = tokio::fs::remove_file(&part).await;
        return Err(format!(
            "download verification failed (expected {} bytes and {}, got {} bytes and {})",
            model.bytes, model.sha256, received, actual_hash
        ));
    }
    tokio::fs::rename(&part, &target)
        .await
        .map_err(|e| format!("install model: {e}"))?;
    emit_progress(
        &app,
        model,
        received,
        "loading",
        "Verified. Loading with llama.cpp…",
    );
    local_ai_load_inner(app.clone(), model_id.clone()).await?;
    emit_progress(&app, model, received, "ready", "Native Local AI ready.");
    drop(_download_guard);
    local_ai_status(app, state, model_id).await
}

fn ensure_loaded(
    app: &AppHandle,
    runtime: &mut NativeRuntime,
    model: &ModelSpec,
) -> Result<(), String> {
    if runtime.model_id.as_deref() == Some(model.id) && runtime.model.is_some() {
        return Ok(());
    }
    let path = model_path(app, model)?;
    if !installed(&path, model) {
        return Err("The native Local AI model is not downloaded.".into());
    }
    runtime.model = None;
    runtime.model_id = None;
    let mut params = LlamaModelParams::default().with_use_mmap(true);
    if runtime.backend.supports_gpu_offload() {
        params = params.with_n_gpu_layers(1000);
    }
    let loaded = LlamaModel::load_from_file(&runtime.backend, &path, &params)
        .map_err(|e| format!("load native model: {e}"))?;
    runtime.model = Some(loaded);
    runtime.model_id = Some(model.id.to_string());
    Ok(())
}

async fn local_ai_load_inner(app: AppHandle, model_id: String) -> Result<(), String> {
    let model = spec(&model_id)?;
    tauri::async_runtime::spawn_blocking(move || {
        let state = app.state::<NativeLocalAiState>();
        let mut runtime = state
            .runtime
            .lock()
            .map_err(|_| "Local AI runtime lock poisoned".to_string())?;
        ensure_loaded(&app, &mut runtime, model)
    })
    .await
    .map_err(|e| format!("native model load task failed: {e}"))?
}

#[tauri::command]
pub async fn local_ai_load(app: AppHandle, model_id: String) -> Result<(), String> {
    local_ai_load_inner(app, model_id).await
}

#[derive(Deserialize)]
pub struct NativeChatMessage {
    role: String,
    content: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NativeCompletion {
    content: String,
    prompt_tokens: u32,
    completion_tokens: u32,
    prefill_tokens_per_second: f64,
    decode_tokens_per_second: f64,
    total_ms: f64,
}

fn complete_json_end(text: &str) -> bool {
    let Some(start) = text.find('{') else {
        return false;
    };
    let mut depth = 0_i32;
    let mut quoted = false;
    let mut escaped = false;
    for ch in text[start..].chars() {
        if quoted {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                quoted = false;
            }
            continue;
        }
        match ch {
            '"' => quoted = true,
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return true;
                }
            }
            _ => {}
        }
    }
    false
}

fn generate(
    app: &AppHandle,
    runtime: &mut NativeRuntime,
    model: &ModelSpec,
    messages: Vec<NativeChatMessage>,
    max_tokens: u32,
) -> Result<NativeCompletion, String> {
    ensure_loaded(app, runtime, model)?;
    let loaded = runtime.model.as_ref().ok_or("native model is not loaded")?;
    let chat = messages
        .into_iter()
        .take(24)
        .map(|m| {
            let role = match m.role.as_str() {
                "system" | "assistant" | "tool" => m.role,
                _ => "user".to_string(),
            };
            let content: String = m.content.chars().take(24_000).collect();
            LlamaChatMessage::new(role, content).map_err(|e| e.to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let template = loaded
        .chat_template(None)
        .map_err(|e| format!("read model chat template: {e}"))?;
    let prompt = loaded
        .apply_chat_template(&template, &chat, true)
        .map_err(|e| format!("apply model chat template: {e}"))?;
    let tokens = loaded
        .str_to_token(&prompt, AddBos::Never)
        .map_err(|e| format!("tokenize prompt: {e}"))?;
    let max_tokens = max_tokens.clamp(16, 512);
    if tokens.len() + max_tokens as usize >= CONTEXT_TOKENS as usize {
        return Err(format!(
            "Local AI prompt is too long ({} tokens for a {} token native context).",
            tokens.len(),
            CONTEXT_TOKENS
        ));
    }

    let context_params = LlamaContextParams::default()
        .with_n_ctx(NonZeroU32::new(CONTEXT_TOKENS))
        .with_n_batch(CONTEXT_TOKENS);
    let mut context = loaded
        .new_context(&runtime.backend, context_params)
        .map_err(|e| format!("create native inference context: {e}"))?;
    let mut batch = LlamaBatch::new(tokens.len().max(1), 1);
    batch
        .add_sequence(&tokens, 0, false)
        .map_err(|e| format!("prepare native prompt: {e}"))?;
    let started = Instant::now();
    let prefill_started = Instant::now();
    context
        .decode(&mut batch)
        .map_err(|e| format!("prefill native prompt: {e}"))?;
    let prefill_seconds = prefill_started.elapsed().as_secs_f64().max(0.000_001);

    let mut sampler = LlamaSampler::chain_simple([
        LlamaSampler::penalties(64, 1.0, 0.3, 0.0),
        LlamaSampler::top_k(40),
        LlamaSampler::top_p(0.9, 1),
        LlamaSampler::temp(0.2),
        LlamaSampler::dist(u32::MAX),
    ]);
    let mut decoder = UTF_8.new_decoder();
    let mut output = String::new();
    let mut position = tokens.len() as i32;
    let decode_started = Instant::now();
    let mut completion_tokens = 0_u32;
    for _ in 0..max_tokens {
        let token = sampler.sample(&context, batch.n_tokens() - 1);
        sampler.accept(token);
        if loaded.is_eog_token(token) {
            break;
        }
        output.push_str(
            &loaded
                .token_to_piece(token, &mut decoder, true, None)
                .map_err(|e| format!("decode native token: {e}"))?,
        );
        completion_tokens += 1;
        if complete_json_end(&output) {
            break;
        }
        batch.clear();
        batch
            .add(token, position, &[0], true)
            .map_err(|e| format!("prepare native token: {e}"))?;
        position += 1;
        context
            .decode(&mut batch)
            .map_err(|e| format!("generate native token: {e}"))?;
    }
    if output.trim().is_empty() {
        return Err("Native Local AI returned an empty response.".into());
    }
    let decode_seconds = decode_started.elapsed().as_secs_f64().max(0.000_001);
    Ok(NativeCompletion {
        content: output,
        prompt_tokens: tokens.len() as u32,
        completion_tokens,
        prefill_tokens_per_second: tokens.len() as f64 / prefill_seconds,
        decode_tokens_per_second: completion_tokens as f64 / decode_seconds,
        total_ms: started.elapsed().as_secs_f64() * 1000.0,
    })
}

#[tauri::command]
pub async fn local_ai_complete(
    app: AppHandle,
    model_id: String,
    messages: Vec<NativeChatMessage>,
    max_tokens: u32,
) -> Result<NativeCompletion, String> {
    let model = spec(&model_id)?;
    tauri::async_runtime::spawn_blocking(move || {
        let state = app.state::<NativeLocalAiState>();
        let mut runtime = state
            .runtime
            .lock()
            .map_err(|_| "Local AI runtime lock poisoned".to_string())?;
        generate(&app, &mut runtime, model, messages, max_tokens)
    })
    .await
    .map_err(|e| format!("native inference task failed: {e}"))?
}

fn unload(runtime: &mut NativeRuntime, id: Option<&str>) {
    if id.is_none() || runtime.model_id.as_deref() == id {
        runtime.model = None;
        runtime.model_id = None;
    }
}

#[tauri::command]
pub async fn local_ai_remove(
    app: AppHandle,
    state: State<'_, NativeLocalAiState>,
    model_id: String,
) -> Result<(), String> {
    let model = spec(&model_id)?;
    let _download_guard = state.download.lock().await;
    // Blocking pool: acquiring the runtime mutex may wait behind a whole
    // generation, and file removal is sync I/O either way.
    let handle = app.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let state = handle.state::<NativeLocalAiState>();
        {
            let mut runtime = state
                .runtime
                .lock()
                .map_err(|_| "Local AI runtime lock poisoned".to_string())?;
            unload(&mut runtime, Some(model.id));
        }
        let path = model_path(&handle, model)?;
        let part = path.with_extension("gguf.part");
        if path.exists() {
            fs::remove_file(&path).map_err(|e| format!("remove native model: {e}"))?;
        }
        let _ = fs::remove_file(part);
        Ok(())
    })
    .await
    .map_err(|e| format!("native remove task failed: {e}"))?
}

#[tauri::command]
pub async fn local_ai_clear_all(
    app: AppHandle,
    state: State<'_, NativeLocalAiState>,
) -> Result<(), String> {
    let _download_guard = state.download.lock().await;
    let handle = app.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let state = handle.state::<NativeLocalAiState>();
        {
            let mut runtime = state
                .runtime
                .lock()
                .map_err(|_| "Local AI runtime lock poisoned".to_string())?;
            unload(&mut runtime, None);
        }
        for model in MODELS {
            let path = model_path(&handle, model)?;
            if path.exists() {
                fs::remove_file(&path).map_err(|e| format!("remove native model: {e}"))?;
            }
            let _ = fs::remove_file(path.with_extension("gguf.part"));
        }
        Ok(())
    })
    .await
    .map_err(|e| format!("native clear task failed: {e}"))?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_is_revision_and_hash_pinned() {
        for model in MODELS {
            assert!(!model.url.contains("/resolve/main/"));
            assert_eq!(model.sha256.len(), 64);
            assert!(model.bytes > 1_000_000_000);
        }
    }

    #[test]
    fn json_completion_ignores_braces_inside_strings() {
        assert!(!complete_json_end(r#"{"say":"{still open}""#));
        assert!(complete_json_end(
            r#"prefix {"say":"{done}","steps":[]} suffix"#
        ));
    }

    #[test]
    fn parses_valid_content_ranges() {
        assert_eq!(
            parse_content_range("bytes 11119423-2856936479/2856936480"),
            Some((11_119_423, 2_856_936_479, 2_856_936_480))
        );
        assert_eq!(parse_content_range("bytes */2856936480"), None);
        assert_eq!(parse_content_range("bytes 8-7/10"), None);
        assert_eq!(parse_content_range("items 0-9/10"), None);
    }
}
