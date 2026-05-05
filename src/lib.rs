//! Native bindings for [Iroh](https://www.iroh.computer/) — closes #425.
//!
//! Iroh is a Rust library for direct peer-to-peer QUIC
//! connections, with hole punching + relay fallback. The
//! wrapper exposes a TypeScript surface for opening an endpoint,
//! reading the local node id, and gracefully shutting down.
//!
//! # Status
//!
//! - v0.5.544: bind / nodeId / close (the original MVP cut).
//! - v0.5.554: connect / acceptOne / openBi / acceptBi / streamWrite
//!   / streamFinish / streamReadToEnd / connClose. ALPN is hardcoded
//!   to `b"perry-iroh/0"` — every server registers it at bind time
//!   (auto-injected on this branch), every client connects with it.
//!   This is enough to run a request-response peer-to-peer demo
//!   end-to-end: server `bind() -> acceptOne() -> acceptBi() ->
//!   streamReadToEnd() + streamWrite() + streamFinish()`, client
//!   `bind() -> connect(serverNodeId) -> openBi() -> streamWrite() +
//!   streamFinish() + streamReadToEnd()`.
//!
//! Followups: per-call ALPN strings (we hardcode the v0 ALPN for
//! now), connection-event callbacks (closure invocation already
//! shipped in v0.5.542 — we just don't expose an `on()` surface
//! yet), broadcast-style fan-out across connections.
//!
//! # Why MVP scope
//!
//! Iroh is a substantial QUIC + hole-punching stack. The user-
//! visible Rust API is small (Endpoint::bind, connect, open_bi,
//! …) but a faithful TS-side API needs careful design — what's
//! a "connection" on the JS side, how do streams map to
//! Promises vs. AsyncIterables, who owns lifetime when a peer
//! disconnects, etc. Ship MVP now to satisfy #425 and validate
//! perry-ffi covers the basic surface; the richer API design
//! is a separate followup.

use perry_ffi::{
    alloc_string, drop_handle, read_string, register_handle, spawn_blocking, take_handle,
    with_handle, Handle, JsPromise, JsString, JsValue, Promise, StringHeader,
};

use iroh::{
    endpoint::{presets, Connection, RecvStream, SendStream},
    Endpoint,
};
use std::str::FromStr;
use tokio::sync::Mutex as TokioMutex;

/// All client/server pairs use the same hardcoded ALPN for v0; per-
/// call ALPN bytes are a deferred design decision (see #425 status).
const PERRY_IROH_ALPN: &[u8] = b"perry-iroh/0";

/// Wrapper struct so the registry's downcast resolves uniquely.
pub struct IrohEndpoint {
    pub endpoint: Endpoint,
}

/// Server- or client-side handshake-completed connection.
pub struct IrohConnection {
    pub conn: Connection,
}

/// A bi-directional stream pair. `send` and `recv` are wrapped
/// in async-aware mutexes since `write_all` / `read_to_end` /
/// `finish` all take `&mut self`, and the same stream handle may
/// be touched from multiple awaits in user code (we never call
/// across awaits ourselves, but holding a tokio Mutex makes the
/// pattern future-proof).
pub struct IrohBiStream {
    pub send: TokioMutex<SendStream>,
    pub recv: TokioMutex<RecvStream>,
}

unsafe fn read_str(ptr: *const StringHeader) -> Option<String> {
    let handle = JsString::from_raw(ptr as *mut StringHeader);
    read_string(handle).map(String::from)
}

/// `iroh.bind() -> Promise<Handle>` — bind a fresh QUIC endpoint
/// using Iroh's `N0` relay preset (sane defaults: discovery via
/// the n0 number-DNS, n0 relay servers for hole-punch fallback).
/// Registers the v0 ALPN (`perry-iroh/0`) so the same endpoint can
/// also accept incoming connections from clients calling
/// `js_iroh_connect`. Resolves with an opaque integer handle.
#[no_mangle]
pub extern "C" fn js_iroh_bind() -> *mut Promise {
    let promise = JsPromise::new();
    let raw = promise.as_raw();

    spawn_blocking(move || {
        let result = tokio::runtime::Handle::current().block_on(async move {
            Endpoint::builder(presets::N0)
                .alpns(vec![PERRY_IROH_ALPN.to_vec()])
                .bind()
                .await
        });
        match result {
            Ok(endpoint) => {
                let handle = register_handle(IrohEndpoint { endpoint });
                promise.resolve(JsValue::from_number(handle as f64));
            }
            Err(e) => promise.reject_string(&format!("iroh bind: {}", e)),
        }
    });
    raw
}

/// `iroh.nodeId(handle) -> Promise<string>` — return the local
/// node's stable identifier (a hex-encoded Ed25519 public key).
/// This is what users share so peers can connect to them.
#[no_mangle]
pub extern "C" fn js_iroh_node_id(ep_handle: Handle) -> *mut Promise {
    let promise = JsPromise::new();
    let raw = promise.as_raw();

    spawn_blocking(move || {
        let result = with_handle::<IrohEndpoint, _, _>(ep_handle, |h| {
            tokio::runtime::Handle::current().block_on(async {
                // Wait for the endpoint to come online before
                // reading addr (it might not have a relay address
                // yet on a cold start).
                h.endpoint.online().await;
                h.endpoint.addr().id.to_string()
            })
        });
        match result {
            Some(id) => promise.resolve_string(&id),
            None => promise.reject_string("iroh: invalid endpoint handle"),
        }
    });
    raw
}

/// `iroh.close(handle) -> Promise<void>` — close the endpoint
/// gracefully. Drops the handle from the registry.
#[no_mangle]
pub extern "C" fn js_iroh_close(ep_handle: Handle) -> *mut Promise {
    let promise = JsPromise::new();
    let raw = promise.as_raw();

    spawn_blocking(move || {
        // Take the handle (consumes it) so we own the Endpoint
        // and can call `close().await`.
        let endpoint = perry_ffi::take_handle::<IrohEndpoint>(ep_handle);
        match endpoint {
            Some(h) => {
                tokio::runtime::Handle::current().block_on(async move {
                    h.endpoint.close().await;
                });
                promise.resolve_undefined();
            }
            None => {
                // Handle didn't exist — treat as no-op success
                // (idempotent close).
                drop_handle(ep_handle);
                promise.resolve_undefined();
            }
        }
    });
    raw
}

/// `iroh.connect(endpointHandle, nodeIdString) -> Promise<connHandle>` —
/// open an outgoing connection to a peer addressed by its
/// hex/base32 EndpointId. Uses the hardcoded v0 ALPN.
///
/// # Safety
///
/// `node_id_ptr` must be null or a Perry-runtime `StringHeader`.
#[no_mangle]
pub unsafe extern "C" fn js_iroh_connect(
    ep_handle: Handle,
    node_id_ptr: *const StringHeader,
) -> *mut Promise {
    let promise = JsPromise::new();
    let raw = promise.as_raw();

    let Some(node_id_str) = read_str(node_id_ptr) else {
        promise.reject_string("iroh connect: invalid node id string");
        return raw;
    };

    spawn_blocking(move || {
        let endpoint_id = match iroh::EndpointId::from_str(node_id_str.trim()) {
            Ok(id) => id,
            Err(e) => {
                promise.reject_string(&format!("iroh connect: bad node id: {}", e));
                return;
            }
        };
        let outcome = with_handle::<IrohEndpoint, _, _>(ep_handle, |h| {
            tokio::runtime::Handle::current().block_on(async move {
                h.endpoint.connect(endpoint_id, PERRY_IROH_ALPN).await
            })
        });
        match outcome {
            Some(Ok(conn)) => {
                let handle = register_handle(IrohConnection { conn });
                promise.resolve(JsValue::from_number(handle as f64));
            }
            Some(Err(e)) => promise.reject_string(&format!("iroh connect: {}", e)),
            None => promise.reject_string("iroh connect: invalid endpoint handle"),
        }
    });
    raw
}

/// `iroh.acceptOne(endpointHandle) -> Promise<connHandle>` — wait
/// for the next incoming peer connection on this endpoint, finish
/// the handshake, and return a connection handle. Resolves with a
/// rejection if the endpoint is closed before a peer arrives.
#[no_mangle]
pub extern "C" fn js_iroh_accept_one(ep_handle: Handle) -> *mut Promise {
    let promise = JsPromise::new();
    let raw = promise.as_raw();

    spawn_blocking(move || {
        let outcome = with_handle::<IrohEndpoint, _, _>(ep_handle, |h| {
            tokio::runtime::Handle::current().block_on(async {
                let Some(incoming) = h.endpoint.accept().await else {
                    return Err::<Connection, String>(
                        "endpoint closed before a peer connected".into(),
                    );
                };
                incoming.await.map_err(|e| format!("iroh accept: {}", e))
            })
        });
        match outcome {
            Some(Ok(conn)) => {
                let handle = register_handle(IrohConnection { conn });
                promise.resolve(JsValue::from_number(handle as f64));
            }
            Some(Err(e)) => promise.reject_string(&format!("iroh acceptOne: {}", e)),
            None => promise.reject_string("iroh acceptOne: invalid endpoint handle"),
        }
    });
    raw
}

/// `iroh.openBi(connHandle) -> Promise<biStreamHandle>` — open a
/// bi-directional stream from the local end. The peer must call
/// `acceptBi` to pick it up.
#[no_mangle]
pub extern "C" fn js_iroh_open_bi(conn_handle: Handle) -> *mut Promise {
    let promise = JsPromise::new();
    let raw = promise.as_raw();

    spawn_blocking(move || {
        let outcome = with_handle::<IrohConnection, _, _>(conn_handle, |h| {
            tokio::runtime::Handle::current().block_on(async {
                h.conn
                    .open_bi()
                    .await
                    .map_err(|e| format!("openBi: {}", e))
            })
        });
        match outcome {
            Some(Ok((send, recv))) => {
                let handle = register_handle(IrohBiStream {
                    send: TokioMutex::new(send),
                    recv: TokioMutex::new(recv),
                });
                promise.resolve(JsValue::from_number(handle as f64));
            }
            Some(Err(e)) => promise.reject_string(&format!("iroh openBi: {}", e)),
            None => promise.reject_string("iroh openBi: invalid connection handle"),
        }
    });
    raw
}

/// `iroh.acceptBi(connHandle) -> Promise<biStreamHandle>` — accept
/// the next bi-directional stream the peer opens.
#[no_mangle]
pub extern "C" fn js_iroh_accept_bi(conn_handle: Handle) -> *mut Promise {
    let promise = JsPromise::new();
    let raw = promise.as_raw();

    spawn_blocking(move || {
        let outcome = with_handle::<IrohConnection, _, _>(conn_handle, |h| {
            tokio::runtime::Handle::current().block_on(async {
                h.conn
                    .accept_bi()
                    .await
                    .map_err(|e| format!("acceptBi: {}", e))
            })
        });
        match outcome {
            Some(Ok((send, recv))) => {
                let handle = register_handle(IrohBiStream {
                    send: TokioMutex::new(send),
                    recv: TokioMutex::new(recv),
                });
                promise.resolve(JsValue::from_number(handle as f64));
            }
            Some(Err(e)) => promise.reject_string(&format!("iroh acceptBi: {}", e)),
            None => promise.reject_string("iroh acceptBi: invalid connection handle"),
        }
    });
    raw
}

/// `iroh.streamWrite(biStreamHandle, dataString) -> Promise<undefined>` —
/// write a UTF-8 string to the send half of the stream.
///
/// # Safety
///
/// `data_ptr` must be null or a Perry-runtime `StringHeader`.
#[no_mangle]
pub unsafe extern "C" fn js_iroh_stream_write(
    stream_handle: Handle,
    data_ptr: *const StringHeader,
) -> *mut Promise {
    let promise = JsPromise::new();
    let raw = promise.as_raw();
    let Some(data) = read_str(data_ptr) else {
        promise.reject_string("iroh streamWrite: invalid data string");
        return raw;
    };

    spawn_blocking(move || {
        let outcome = with_handle::<IrohBiStream, _, _>(stream_handle, |h| {
            tokio::runtime::Handle::current().block_on(async {
                let mut send = h.send.lock().await;
                send.write_all(data.as_bytes())
                    .await
                    .map_err(|e| format!("streamWrite: {}", e))
            })
        });
        match outcome {
            Some(Ok(())) => promise.resolve_undefined(),
            Some(Err(e)) => promise.reject_string(&format!("iroh streamWrite: {}", e)),
            None => promise.reject_string("iroh streamWrite: invalid stream handle"),
        }
    });
    raw
}

/// `iroh.streamFinish(biStreamHandle) -> Promise<undefined>` — close
/// the send side of the stream so the peer's `streamReadToEnd`
/// resolves.
#[no_mangle]
pub extern "C" fn js_iroh_stream_finish(stream_handle: Handle) -> *mut Promise {
    let promise = JsPromise::new();
    let raw = promise.as_raw();

    spawn_blocking(move || {
        let outcome = with_handle::<IrohBiStream, _, _>(stream_handle, |h| {
            tokio::runtime::Handle::current().block_on(async {
                let mut send = h.send.lock().await;
                send.finish().map_err(|e| format!("streamFinish: {}", e))
            })
        });
        match outcome {
            Some(Ok(())) => promise.resolve_undefined(),
            Some(Err(e)) => promise.reject_string(&format!("iroh streamFinish: {}", e)),
            None => promise.reject_string("iroh streamFinish: invalid stream handle"),
        }
    });
    raw
}

/// `iroh.streamReadToEnd(biStreamHandle, maxBytes) -> Promise<string>` —
/// read up to `maxBytes` from the recv side of the stream, then
/// resolve with the bytes as a UTF-8 string. Errors if the peer's
/// payload exceeds `maxBytes`.
#[no_mangle]
pub extern "C" fn js_iroh_stream_read_to_end(
    stream_handle: Handle,
    max_bytes: f64,
) -> *mut Promise {
    let promise = JsPromise::new();
    let raw = promise.as_raw();
    let cap = max_bytes.max(0.0) as usize;

    spawn_blocking(move || {
        let outcome = with_handle::<IrohBiStream, _, _>(stream_handle, |h| {
            tokio::runtime::Handle::current().block_on(async {
                let mut recv = h.recv.lock().await;
                recv.read_to_end(cap)
                    .await
                    .map_err(|e| format!("streamReadToEnd: {}", e))
            })
        });
        match outcome {
            Some(Ok(bytes)) => match String::from_utf8(bytes) {
                Ok(s) => {
                    let js = alloc_string(&s);
                    promise.resolve(JsValue::from_string_ptr(js.as_raw()));
                }
                Err(e) => promise.reject_string(&format!(
                    "iroh streamReadToEnd: payload was not valid UTF-8: {}",
                    e
                )),
            },
            Some(Err(e)) => promise.reject_string(&format!("iroh streamReadToEnd: {}", e)),
            None => promise.reject_string("iroh streamReadToEnd: invalid stream handle"),
        }
    });
    raw
}

/// `iroh.connClose(connHandle) -> Promise<undefined>` — close a
/// peer connection with a clean QUIC shutdown frame. Idempotent —
/// closing an already-dropped handle resolves successfully.
#[no_mangle]
pub extern "C" fn js_iroh_conn_close(conn_handle: Handle) -> *mut Promise {
    let promise = JsPromise::new();
    let raw = promise.as_raw();

    spawn_blocking(move || {
        let conn = take_handle::<IrohConnection>(conn_handle);
        match conn {
            Some(h) => {
                tokio::runtime::Handle::current().block_on(async move {
                    h.conn.close(0u32.into(), b"bye");
                    h.conn.closed().await;
                });
                promise.resolve_undefined();
            }
            None => {
                drop_handle(conn_handle);
                promise.resolve_undefined();
            }
        }
    });
    raw
}

#[cfg(test)]
mod tests {
    // End-to-end iroh tests need a live tokio runtime + network
    // access (n0 relay + hole-punching infrastructure). Out of
    // scope for unit testing — the wrapper just plumbs through
    // the iroh crate's public methods, which have their own
    // upstream test coverage. Smoke testing happens via
    // TS integration in release builds.
    //
    // The pattern used here (handle registry + spawn_blocking +
    // tokio::Handle::current().block_on) mirrors
    // perry-ext-tursodb (#424) — both are validated end-to-end
    // through the same path.
}
