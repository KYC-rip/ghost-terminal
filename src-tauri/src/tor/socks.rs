//! Minimal SOCKS5 proxy over the shared arti `TorClient`. arti-client has no
//! built-in proxy (that lives in the `arti` binary / `arti-socksproxy`), so we
//! speak SOCKS5 CONNECT ourselves and tunnel each stream through
//! `TorClient::connect`. Purpose: let the native ROS browser webview
//! (`WebviewWindowBuilder::proxy_url`) route over Tor when the user's routing
//! mode is "tor" — the same Tor circuits the rest of the shell uses.
//!
//! Scope: CONNECT only (what a webview needs). No auth (loopback-bound). Each
//! connection fetches the CURRENT client, so a Tor reconnect is picked up live.

use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::Arc;
use tokio::io::{copy_bidirectional, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;

use super::TorInner;

static SOCKS_PORT: AtomicU16 = AtomicU16::new(0);
static STARTED: AtomicBool = AtomicBool::new(false);

/// The loopback port the Tor SOCKS proxy listens on (0 until started).
pub fn socks_port() -> u16 {
    SOCKS_PORT.load(Ordering::SeqCst)
}

/// Start the SOCKS5 listener once (idempotent). Safe to call on every Tor
/// (re)connect — only the first call binds; later calls are no-ops.
pub async fn ensure(inner: Arc<RwLock<TorInner>>) -> Result<u16, String> {
    if STARTED.swap(true, Ordering::SeqCst) {
        return Ok(SOCKS_PORT.load(Ordering::SeqCst));
    }
    let listener = match TcpListener::bind(("127.0.0.1", 0u16)).await {
        Ok(l) => l,
        Err(e) => {
            STARTED.store(false, Ordering::SeqCst);
            return Err(format!("socks bind failed: {e}"));
        }
    };
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();
    SOCKS_PORT.store(port, Ordering::SeqCst);
    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((sock, _)) => {
                    let inner = inner.clone();
                    tokio::spawn(async move {
                        if let Err(e) = serve(sock, inner).await {
                            log::debug!("[tor-socks] conn ended: {e}");
                        }
                    });
                }
                Err(e) => {
                    log::warn!("[tor-socks] accept failed: {e}");
                    break;
                }
            }
        }
    });
    log::info!("[tor-socks] SOCKS5 proxy listening on 127.0.0.1:{port}");
    Ok(port)
}

async fn serve(mut sock: TcpStream, inner: Arc<RwLock<TorInner>>) -> Result<(), String> {
    // Greeting: VER, NMETHODS, METHODS[]
    let mut hdr = [0u8; 2];
    sock.read_exact(&mut hdr).await.map_err(|e| e.to_string())?;
    if hdr[0] != 0x05 {
        return Err("not socks5".into());
    }
    let mut methods = vec![0u8; hdr[1] as usize];
    sock.read_exact(&mut methods)
        .await
        .map_err(|e| e.to_string())?;
    sock.write_all(&[0x05, 0x00])
        .await
        .map_err(|e| e.to_string())?; // NO AUTH

    // Request: VER, CMD, RSV, ATYP, ADDR, PORT
    let mut req = [0u8; 4];
    sock.read_exact(&mut req).await.map_err(|e| e.to_string())?;
    if req[1] != 0x01 {
        // Only CONNECT — reply "command not supported".
        let _ = sock
            .write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await;
        return Err("only CONNECT supported".into());
    }
    let host = match req[3] {
        0x01 => {
            let mut a = [0u8; 4];
            sock.read_exact(&mut a).await.map_err(|e| e.to_string())?;
            format!("{}.{}.{}.{}", a[0], a[1], a[2], a[3])
        }
        0x03 => {
            let mut n = [0u8; 1];
            sock.read_exact(&mut n).await.map_err(|e| e.to_string())?;
            let mut d = vec![0u8; n[0] as usize];
            sock.read_exact(&mut d).await.map_err(|e| e.to_string())?;
            String::from_utf8_lossy(&d).into_owned()
        }
        0x04 => {
            let mut a = [0u8; 16];
            sock.read_exact(&mut a).await.map_err(|e| e.to_string())?;
            std::net::Ipv6Addr::from(a).to_string()
        }
        _ => {
            let _ = sock
                .write_all(&[0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await;
            return Err("bad ATYP".into());
        }
    };
    let mut pb = [0u8; 2];
    sock.read_exact(&mut pb).await.map_err(|e| e.to_string())?;
    let port = u16::from_be_bytes(pb);

    // Dial through the current Tor client (exit for clearnet, onion for .onion).
    let client = inner.read().await.client.clone();
    let client = match client {
        Some(c) => c,
        None => {
            let _ = sock
                .write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await; // net unreachable
            return Err("Tor not connected".into());
        }
    };
    let mut stream = match client.connect((host.as_str(), port)).await {
        Ok(s) => s,
        Err(e) => {
            let _ = sock
                .write_all(&[0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await; // host unreachable
            return Err(format!("Tor connect {host}:{port} failed: {e}"));
        }
    };
    // Success — bound addr 0.0.0.0:0 (clients ignore it for CONNECT).
    sock.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await
        .map_err(|e| e.to_string())?;

    copy_bidirectional(&mut sock, &mut stream)
        .await
        .map_err(|e| e.to_string())?;
    Ok(())
}
