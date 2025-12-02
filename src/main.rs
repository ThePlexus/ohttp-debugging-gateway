use std::{io::Cursor, str};

use axum::{
    Router,
    body::{Body, to_bytes},
    extract::{Request, State},
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header::CONTENT_TYPE},
    middleware::Next,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use bhttp::{FieldSection, Message, Mode, StatusCode as BhttpStatus};
use bytes::Bytes;
use clap::Parser;
use futures::{AsyncReadExt, AsyncWrite, AsyncWriteExt, StreamExt, io::Cursor as FuturesCursor};
use hex::encode as hex_encode;
use http::{Method, header};
use log::{LevelFilter, debug, info, warn};
use ohttp::{
    KeyConfig, SymmetricSuite,
    hpke::{Aead, Kdf, Kem},
};
use reqwest::Client;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tokio_util::{compat::TokioAsyncWriteCompatExt, io::ReaderStream};

#[derive(Clone)]
struct AppState {
    server: ohttp::Server,
    encoded_config: Vec<u8>,
    client: Client,
    chunk_logs: bool,
    debug_payload: bool,
}

#[derive(Debug, Error)]
enum GatewayError {
    #[error("failed to parse OHTTP envelope: {0}")]
    Ohttp(#[from] ohttp::Error),
    #[error("invalid BHTTP message: {0}")]
    Bhttp(#[from] bhttp::Error),
    #[error("inner message is not an HTTP request")]
    NotARequest,
    #[error("missing host header in inner request")]
    MissingHost,
    #[error("invalid UTF-8 in control data")]
    Utf8(#[from] str::Utf8Error),
    #[error("invalid HTTP method: {0}")]
    Method(#[from] http::method::InvalidMethod),
    #[error("invalid header name: {0}")]
    HeaderName(#[from] http::header::InvalidHeaderName),
    #[error("invalid header value: {0}")]
    HeaderValue(#[from] http::header::InvalidHeaderValue),
    #[error("upstream request failed: {0}")]
    Upstream(#[from] reqwest::Error),
    #[error("stream IO error: {0}")]
    Io(#[from] std::io::Error),
}

impl GatewayError {
    fn status(&self) -> StatusCode {
        match self {
            Self::Ohttp(_) | Self::Bhttp(_) | Self::NotARequest | Self::MissingHost => {
                StatusCode::BAD_REQUEST
            }
            Self::Utf8(_) | Self::Method(_) | Self::HeaderName(_) | Self::HeaderValue(_) => {
                StatusCode::BAD_REQUEST
            }
            Self::Upstream(_) => StatusCode::BAD_GATEWAY,
            Self::Io(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

#[derive(Parser, Debug)]
#[command(name = "ohttp-gateway", about = "Test-only OHTTP gateway")]
struct Opts {
    /// Host/IP to listen on
    #[arg(short = 'H', long = "host", default_value = "127.0.0.1")]
    listen_host: String,
    /// Port to listen on
    #[arg(short = 'p', long = "port", default_value_t = 8080)]
    listen_port: u16,
    /// Enable verbose logging (debug level)
    #[arg(short = 'd', long = "debug")]
    debug: bool,
    /// Log chunk send/receive timing for streaming responses
    #[arg(long = "debug-chunks")]
    debug_chunks: bool,
    /// Enable HPKE key schedule debug logging (requires --debug to see)
    #[arg(long = "debug-hpke")]
    debug_hpke: bool,
    /// Log decrypted inner HTTP request/response bodies (use with caution)
    #[arg(long = "debug-payload")]
    debug_payload: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let opts = Opts::parse();
    let mut logger = env_logger::Builder::from_env(env_logger::Env::default());
    logger.filter_level(if opts.debug {
        LevelFilter::Debug
    } else {
        LevelFilter::Info
    });
    logger.init();
    if opts.debug_hpke {
        unsafe {
            std::env::set_var("HPKE_DEBUG", "1");
        }
    }

    let (server, encoded_config) = build_server()?;
    let client = Client::builder().build()?;
    let state = AppState {
        server,
        encoded_config,
        client,
        chunk_logs: opts.debug_chunks,
        debug_payload: opts.debug_payload,
    };

    let app = Router::new()
        .route("/ohttp", post(handle_ohttp))
        .route("/ohttp-keys", get(handle_keys).post(handle_keys))
        .layer(axum::middleware::from_fn(log_requests))
        .with_state(state);

    let bind_addr = format!("{}:{}", opts.listen_host, opts.listen_port);
    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
    info!("OHTTP gateway listening on {}", bind_addr);
    axum::serve(listener, app).await?;
    Ok(())
}

fn build_server() -> Result<(ohttp::Server, Vec<u8>), ohttp::Error> {
    let key_config = KeyConfig::new(
        1,
        Kem::X25519Sha256,
        vec![SymmetricSuite::new(Kdf::HkdfSha256, Aead::Aes128Gcm)],
    )?;
    let encoded = key_config.encode()?;
    let server = ohttp::Server::new(key_config)?;
    Ok((server, encoded))
}

async fn handle_keys(State(state): State<AppState>) -> impl IntoResponse {
    let mut headers = HeaderMap::new();
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/ohttp-keys"),
    );
    info!("/ohttp-keys served");
    (headers, state.encoded_config.clone())
}

async fn handle_ohttp(State(state): State<AppState>, req: Request) -> Response {
    let outer_method = req.method().clone();
    let outer_uri = req.uri().clone();
    let outer_headers = req.headers().clone();
    let Ok(body) = to_bytes(req.into_body(), usize::MAX).await else {
        return (StatusCode::BAD_REQUEST, "failed to read body").into_response();
    };
    debug!(
        "outer request: {} {} headers=[{}] header_count={} body_len={} bytes",
        outer_method,
        outer_uri,
        format_headers(&outer_headers),
        outer_headers.len(),
        body.len()
    );
    if body.is_empty() {
        return (StatusCode::BAD_REQUEST, "empty body").into_response();
    }

    match process_ohttp(&state, body).await {
        Ok(response) => response,
        Err(err) => {
            warn!("failed to process OHTTP request: {}", err);
            let status = err.status();
            let headers = HeaderMap::new();
            debug!(
                "outer response: status={} headers=[{}] header_count={} body_len=0 bytes",
                status,
                format_headers(&headers),
                headers.len()
            );
            (status, err.to_string()).into_response()
        }
    }
}

async fn process_ohttp(state: &AppState, body: Bytes) -> Result<Response, GatewayError> {
    // Try chunked OHTTP first so chunked clients get a chunked response.
    if let Some(response) = try_chunked(state, &body).await? {
        return Ok(response);
    }

    // First try the non-streaming format.
    match state.server.decapsulate(&body) {
        Ok((plaintext, response_ctx)) => {
            debug!(
                "decoded standard OHTTP request: inner plaintext {} bytes, hex={}",
                plaintext.len(),
                hex_trunc(&plaintext, 128)
            );
            if state.debug_payload {
                let mut cursor = Cursor::new(&plaintext);
                if let Ok(msg) = Message::read_bhttp(&mut cursor) {
                    debug!("payload request: {:?}", format_message_summary(&msg));
                }
            }
            let upstream_response = forward_plaintext(state, &plaintext).await?;
            let ciphertext = response_ctx.encapsulate(&upstream_response)?;
            let response = Response::builder()
                .status(StatusCode::OK)
                .header(CONTENT_TYPE, HeaderValue::from_static("message/ohttp-res"))
                .body(Body::from(ciphertext))
                .unwrap();
            return Ok(response);
        }
        Err(e) => {
            debug!("standard decapsulation failed: {}", e);
            log_encap_debug(state.server.config(), &body);
        }
    }

    Err(GatewayError::Ohttp(ohttp::Error::Unsupported))
}

async fn forward_plaintext(state: &AppState, plaintext: &[u8]) -> Result<Vec<u8>, GatewayError> {
    let message = decode_message(plaintext)?;
    if state.debug_payload {
        debug!("payload request: {:?}", format_message_summary(&message));
    }
    forward_plaintext_message(state, &message).await
}

fn decode_message(plaintext: &[u8]) -> Result<Message, GatewayError> {
    let mut cursor = Cursor::new(plaintext);
    let message = Message::read_bhttp(&mut cursor)?;
    Ok(message)
}

async fn forward_plaintext_message(
    state: &AppState,
    message: &Message,
) -> Result<Vec<u8>, GatewayError> {
    let control = message.control();
    if !control.is_request() {
        return Err(GatewayError::NotARequest);
    }

    let method = Method::from_bytes(control.method().ok_or(GatewayError::NotARequest)?)?;
    let scheme = control.scheme().unwrap_or(b"https");
    let path = control.path().unwrap_or(b"/");
    let host_bytes = message
        .header()
        .get(b"host")
        .or_else(|| control.authority())
        .ok_or(GatewayError::MissingHost)?;
    let host = str::from_utf8(host_bytes)?;
    let path_str = str::from_utf8(path)?;
    let scheme_str = str::from_utf8(scheme)?;

    let url = format!(
        "{scheme}://{host}{path}",
        scheme = scheme_str,
        host = host,
        path = path_str
    );
    let body_len = message.content().len();
    let header_count = message.header().fields().len();
    debug!(
        "inner request: {} {} host={} scheme={} headers=[{}] header_count={} body_len={} bytes",
        method,
        path_str,
        host,
        scheme_str,
        format_fields(message.header()),
        header_count,
        body_len
    );
    info!("forwarding {} {} to upstream {}", method, path_str, url);
    let mut req = state.client.request(method, url);

    for field in message.header().fields().iter() {
        if field.name() == b"host" || field.name() == b"content-length" {
            continue;
        }
        let name = HeaderName::from_bytes(field.name())?;
        let value = HeaderValue::from_bytes(field.value())?;
        req = req.header(name, value);
    }

    req = req.body(message.content().to_vec());
    let resp = req.send().await?;
    build_bhttp_response(resp, state.debug_payload).await
}

async fn build_bhttp_response(
    resp: reqwest::Response,
    debug_payload: bool,
) -> Result<Vec<u8>, GatewayError> {
    let status = resp.status();
    let headers = resp.headers().clone();
    let body = resp.bytes().await?;
    let mut message = Message::response(BhttpStatus::try_from(status.as_u16()).unwrap());
    debug!(
        "upstream response (standard): status={} headers=[{}] header_count={} body_len={} bytes",
        status,
        format_headers(&headers),
        headers.len(),
        body.len()
    );

    for (name, value) in headers.iter() {
        // Skip transfer-encoding; content length is implicit in the BHTTP body.
        if name == header::TRANSFER_ENCODING {
            continue;
        }
        message.put_header(name.as_str().as_bytes(), value.as_bytes());
    }

    message.put_header("content-length", body.len().to_string().as_bytes().to_vec());
    message.write_content(&body);

    let mut buf = Vec::new();
    message.write_bhttp(Mode::KnownLength, &mut buf)?;
    debug!(
        "inner response: status={} headers=[{}] header_count={} body_len={} bytes plain_total={} bytes",
        status,
        format_fields(message.header()),
        message.header().fields().len(),
        body.len(),
        buf.len()
    );
    if debug_payload {
        debug!(
            "payload response: status={} body_preview={}",
            status,
            preview_body(&body, 200)
        );
    }
    debug!(
        "decrypted inner response ready: {} bytes (plaintext BHTTP)",
        buf.len()
    );
    Ok(buf)
}

async fn log_requests(req: Request, next: Next) -> Response {
    let method = req.method().clone();
    let uri = req.uri().clone();
    let res = next.run(req).await;
    info!("{} {} -> {}", method, uri, res.status());
    res
}

fn log_encap_debug(config: &KeyConfig, body: &[u8]) {
    if body.len() < 7 {
        debug!(
            "encap debug: body too short to read header ({} bytes)",
            body.len()
        );
        return;
    }
    let key_id = body[0];
    let kem = u16::from_be_bytes([body[1], body[2]]);
    let kdf = u16::from_be_bytes([body[3], body[4]]);
    let aead = u16::from_be_bytes([body[5], body[6]]);
    let enc_len = body.len().saturating_sub(7);
    let expected = config
        .select(SymmetricSuite::new(Kdf::HkdfSha256, Aead::Aes128Gcm))
        .ok();
    if let Some(hpke) = expected {
        debug!(
            "encap debug: key_id={} kem={} kdf={} aead={} enc_section_len={} total_body={} expected_enc_len={} aead_key_len={} aead_nonce_len={} aead_tag_len={}",
            key_id,
            kem,
            kdf,
            aead,
            enc_len,
            body.len(),
            hpke.kem().n_enc(),
            hpke.aead().n_k(),
            hpke.aead().n_n(),
            hpke.aead().n_t()
        );
        let info_std = build_info_bytes(b"message/bhttp request", key_id, kem, kdf, aead);
        let info_chunk = build_info_bytes(b"message/bhttp chunked request", key_id, kem, kdf, aead);
        debug!(
            "encap debug: info_std_hex={} info_chunk_hex={}",
            hex_encode(info_std),
            hex_encode(info_chunk)
        );
    } else {
        debug!(
            "encap debug: key_id={} kem={} kdf={} aead={} enc_section_len={} total_body={} (failed to compute expected config)",
            key_id,
            kem,
            kdf,
            aead,
            enc_len,
            body.len()
        );
    }
    debug!("encap body hex={}", hex_trunc(body, 512));
}

fn build_info_bytes(label: &[u8], key_id: u8, kem: u16, kdf: u16, aead: u16) -> Vec<u8> {
    let mut info = Vec::with_capacity(label.len() + 1 + 7);
    info.extend_from_slice(label);
    info.push(0);
    info.push(key_id);
    info.extend_from_slice(&kem.to_be_bytes());
    info.extend_from_slice(&kdf.to_be_bytes());
    info.extend_from_slice(&aead.to_be_bytes());
    info
}

fn hex_trunc(data: &[u8], max: usize) -> String {
    let shown = data.len().min(max);
    let hex = hex_encode(&data[..shown]);
    if data.len() > max {
        format!("{}...(+{} bytes)", hex, data.len() - max)
    } else {
        hex
    }
}

fn format_headers(headers: &HeaderMap) -> String {
    headers
        .iter()
        .map(|(k, v)| format!("{}: {}", k.as_str(), v.to_str().unwrap_or("<binary>")))
        .collect::<Vec<_>>()
        .join(", ")
}

fn format_fields(fields: &FieldSection) -> String {
    fields
        .fields()
        .iter()
        .map(|f| {
            format!(
                "{}: {}",
                String::from_utf8_lossy(f.name()),
                String::from_utf8_lossy(f.value())
            )
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn format_message_summary(msg: &Message) -> String {
    let ctrl = msg.control();
    if ctrl.is_request() {
        format!(
            "request method={} path={} headers={} body_len={}",
            String::from_utf8_lossy(ctrl.method().unwrap_or(b"")),
            String::from_utf8_lossy(ctrl.path().unwrap_or(b"")),
            format_fields(msg.header()),
            msg.content().len()
        )
    } else {
        format!(
            "response status={:?} headers={} body_len={}",
            ctrl.status(),
            format_fields(msg.header()),
            msg.content().len()
        )
    }
}

fn preview_body(body: &[u8], max: usize) -> String {
    let shown = body.len().min(max);
    let snippet = &body[..shown];
    match std::str::from_utf8(snippet) {
        Ok(text) => {
            if body.len() > max {
                format!("{}...(+{} bytes)", text, body.len() - max)
            } else {
                text.to_string()
            }
        }
        Err(_) => format!("{:02x?}", snippet),
    }
}

async fn try_chunked(state: &AppState, body: &[u8]) -> Result<Option<Response>, GatewayError> {
    let mut plaintext = Vec::new();
    let mut request_stream = state
        .server
        .clone()
        .decapsulate_stream(FuturesCursor::new(body.to_vec()));
    if let Err(e) = request_stream.read_to_end(&mut plaintext).await {
        debug!("chunked decode failed: {}", e);
        log_encap_debug(state.server.config(), body);
        return Ok(None);
    }

    debug!(
        "decoded chunked OHTTP request: inner plaintext {} bytes",
        plaintext.len()
    );
    let message = match decode_message(&plaintext) {
        Ok(m) => m,
        Err(e) => {
            debug!(
                "chunked BHTTP parse failed: {} (hex={})",
                e,
                hex_trunc(&plaintext, 128)
            );
            return Err(e);
        }
    };
    // Create a streaming body back to the client.
    let (client_read, client_write) = tokio::io::duplex(16 * 1024);
    let mut server_response = request_stream.response(client_write.compat_write())?;
    let state_clone = state.clone();
    tokio::spawn(async move {
        if let Err(e) = stream_upstream_response(&state_clone, &message, &mut server_response).await
        {
            warn!("streaming upstream failed: {e}");
        }
        if let Err(e) = server_response.close().await {
            warn!("closing server response failed: {e}");
        }
    });

    let stream = ReaderStream::new(client_read);
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("message/ohttp-res"));
    let body = Body::from_stream(stream);
    let response = Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, HeaderValue::from_static("message/ohttp-res"))
        .body(body)
        .unwrap();
    Ok(Some(response))
}

async fn stream_upstream_response<W: AsyncWrite + Unpin>(
    state: &AppState,
    message: &Message,
    writer: &mut W,
) -> Result<(), GatewayError> {
    let control = message.control();
    if !control.is_request() {
        return Err(GatewayError::NotARequest);
    }

    let method = Method::from_bytes(control.method().ok_or(GatewayError::NotARequest)?)?;
    let scheme = control.scheme().unwrap_or(b"https");
    let path = control.path().unwrap_or(b"/");
    let host_bytes = message
        .header()
        .get(b"host")
        .or_else(|| control.authority())
        .ok_or(GatewayError::MissingHost)?;
    let host = str::from_utf8(host_bytes)?;
    let path_str = str::from_utf8(path)?;
    let scheme_str = str::from_utf8(scheme)?;

    let url = format!(
        "{scheme}://{host}{path}",
        scheme = scheme_str,
        host = host,
        path = path_str
    );
    let body_len = message.content().len();
    let header_count = message.header().fields().len();
    debug!(
        "inner request (stream): {} {} host={} scheme={} headers=[{}] header_count={} body_len={} bytes",
        method,
        path_str,
        host,
        scheme_str,
        format_fields(message.header()),
        header_count,
        body_len
    );
    info!("forwarding {} {} to upstream {}", method, path_str, url);

    let mut req = state.client.request(method, url);
    for field in message.header().fields().iter() {
        if field.name() == b"host" || field.name() == b"content-length" {
            continue;
        }
        let name = HeaderName::from_bytes(field.name())?;
        let value = HeaderValue::from_bytes(field.value())?;
        req = req.header(name, value);
    }
    req = req.body(message.content().to_vec());
    let resp = req.send().await?;

    let status = resp.status();
    debug!(
        "upstream response (stream): status={} headers=[{}] header_count={}",
        status,
        format_headers(resp.headers()),
        resp.headers().len()
    );
    let mut bhttp_headers = FieldSection::default();
    for (name, value) in resp.headers().iter() {
        if name == header::TRANSFER_ENCODING {
            continue;
        }
        bhttp_headers.put(name.as_str().as_bytes().to_vec(), value.as_bytes().to_vec());
    }

    // Build the BHTTP indeterminate-length prefix.
    let mut prefix = Vec::new();
    write_varint(3, &mut prefix); // response, indeterminate length
    write_varint(status.as_u16().into(), &mut prefix); // control data (status)
    bhttp_headers
        .write_bhttp(Mode::IndeterminateLength, &mut prefix)
        .map_err(GatewayError::Bhttp)?;
    writer.write_all(&prefix).await?;

    let mut stream = resp.bytes_stream();
    let mut chunk_idx: usize = 0;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        chunk_idx += 1;
        if state.chunk_logs {
            info!(
                "[{}] upstream chunk {} received ({} bytes)",
                now_ts(),
                chunk_idx,
                chunk.len()
            );
        }
        let len_start = prefix.len();
        write_varint(chunk.len().try_into().unwrap_or(0), &mut prefix);
        writer.write_all(&prefix[len_start..]).await?;
        writer.write_all(&chunk).await?;
        if state.chunk_logs {
            info!(
                "[{}] downstream chunk {} sent to client ({} bytes)",
                now_ts(),
                chunk_idx,
                chunk.len()
            );
        }
    }

    // Final zero-length chunk and empty trailer.
    prefix.clear();
    write_varint(0, &mut prefix);
    writer.write_all(&prefix).await?;
    let empty = FieldSection::default();
    let mut trailer_buf = Vec::new();
    empty
        .write_bhttp(Mode::IndeterminateLength, &mut trailer_buf)
        .map_err(GatewayError::Bhttp)?;
    writer.write_all(&trailer_buf).await?;
    if state.chunk_logs {
        info!(
            "[{}] downstream chunked stream completed ({} chunks)",
            now_ts(),
            chunk_idx
        );
    }
    Ok(())
}

fn now_ts() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}.{:03}", now.as_secs(), now.subsec_millis())
}

fn write_varint(n: u64, buf: &mut Vec<u8>) {
    if n < (1 << 6) {
        buf.push(n as u8);
    } else if n < (1 << 14) {
        let v = (n | (0b01 << 14)) as u16;
        buf.extend_from_slice(&v.to_be_bytes());
    } else if n < (1 << 30) {
        let v = (n | (0b10 << 30)) as u32;
        buf.extend_from_slice(&v.to_be_bytes());
    } else {
        let v = n | (0b11 << 62);
        buf.extend_from_slice(&v.to_be_bytes());
    }
}
