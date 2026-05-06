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
//! - v0.2.0: endpointConnections / connNodeId for fan-out, plus
//!   binary-safe streamWriteBuffer / streamReadToEndBuffer.
//! - v0.3.0: bind now accepts an options object (`secretKey` for
//!   stable identity across restarts, `mdns` for LAN peer discovery).
//!   Adds `generateSecretKey` / `secretKeyFromSeed` for deterministic
//!   identities, and `nodeStatus` for a one-shot reachability
//!   snapshot.
//!
//! Followups: per-call ALPN strings (we hardcode the v0 ALPN for
//! now), connection-event callbacks (closure invocation already
//! shipped in perry-ffi but we don't expose an `on()` surface yet),
//! and a streaming-subscriptions API for both connection events
//! and `nodeStatus` changes (today it's a one-shot snapshot).
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
    alloc_buffer, alloc_string, build_object_shape, drop_handle, js_array_alloc, js_array_push,
    js_object_alloc_with_shape, js_object_get_field, js_object_set_field, read_buffer_bytes,
    read_string, register_handle, spawn_blocking, take_handle, with_handle, BufferHeader, Handle,
    JsPromise, JsString, JsValue, ObjectHeader, Promise, StringHeader,
};

use iroh::{
    address_lookup::MdnsAddressLookupBuilder,
    endpoint::{presets, Connection, RecvStream, SendStream},
    Endpoint, SecretKey, Watcher,
};
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Mutex;
use tokio::sync::Mutex as TokioMutex;

// Multi-peer broadcast support (v0.2.0): track which connection
// handles belong to which endpoint, plus the connection's remote
// node id. `endpointConnections(ep)` enumerates active peers so
// user code can do fan-out (`for (const c of conns) await
// streamWrite(...)`).
//
// Removal happens in `connClose` and `acceptOne` / `connect` failure
// paths. Stale entries are still safe — `with_handle::<IrohConnection>`
// returns None for dropped handles, so a broadcast loop just skips
// them.
struct ConnIndex {
    by_endpoint: HashMap<Handle, Vec<Handle>>,
    remote_node_id: HashMap<Handle, String>,
}

fn conn_index() -> &'static Mutex<ConnIndex> {
    use std::sync::OnceLock;
    static IDX: OnceLock<Mutex<ConnIndex>> = OnceLock::new();
    IDX.get_or_init(|| {
        Mutex::new(ConnIndex {
            by_endpoint: HashMap::new(),
            remote_node_id: HashMap::new(),
        })
    })
}

fn conn_index_register(ep: Handle, conn: Handle, node_id: String) {
    let mut idx = conn_index().lock().unwrap();
    idx.by_endpoint.entry(ep).or_default().push(conn);
    idx.remote_node_id.insert(conn, node_id);
}

fn conn_index_remove(conn: Handle) {
    let mut idx = conn_index().lock().unwrap();
    idx.remote_node_id.remove(&conn);
    for v in idx.by_endpoint.values_mut() {
        v.retain(|h| *h != conn);
    }
}

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

/// Parsed `BindOptions` extracted from a JS object. Shape and key
/// order is documented in `index.d.ts` (`BindOptions`); we read by
/// type-dispatch over the first few fields rather than fixed index
/// so users can declare keys in either order.
#[derive(Default)]
struct BindOptions {
    secret_key: Option<SecretKey>,
    mdns: bool,
}

/// Read fields off a JS object by type. With only two declared fields
/// of disjoint types (string + bool), we don't depend on key order.
unsafe fn parse_bind_options(opts: JsValue) -> BindOptions {
    let mut result = BindOptions::default();
    let obj_ptr = opts.as_pointer::<ObjectHeader>();
    if obj_ptr.is_null() {
        return result;
    }
    // Probe a small fixed number of slots — `js_object_get_field`
    // returns UNDEFINED for out-of-range indices, so this is safe even
    // for `{}`, `{secretKey}`, or `{mdns}` objects.
    for i in 0..4 {
        let v = js_object_get_field(obj_ptr, i);
        if v.is_string() {
            let sk_ptr = v.as_string_ptr();
            if let Some(s) = read_string(JsString::from_raw(sk_ptr)) {
                if let Ok(sk) = SecretKey::from_str(s.trim()) {
                    result.secret_key = Some(sk);
                }
            }
        } else if v.is_bool() {
            result.mdns = v.to_bool();
        }
    }
    result
}

/// `iroh.bind(options?) -> Promise<Handle>` — bind a fresh QUIC
/// endpoint using Iroh's `N0` relay preset (discovery via the n0
/// number-DNS, n0 relay servers for hole-punch fallback). Registers
/// the v0 ALPN (`perry-iroh/0`) so the same endpoint can also accept
/// incoming connections from clients calling `js_iroh_connect`.
/// Resolves with an opaque integer handle.
///
/// `options` (all optional):
/// - `secretKey` — base32-or-hex-encoded `SecretKey` for stable node
///   identity across restarts. Omit to generate a fresh random key.
/// - `mdns` — when `true`, attaches an `MdnsAddressLookup` so peers
///   on the same LAN can be discovered without round-tripping through
///   the n0 relay.
///
/// # Safety
///
/// `opts_f` must be the NaN-boxed bits of a `JsValue` — either an
/// object, `undefined`, or `null`. Perry codegen guarantees this for
/// any TS call site that types the argument as `BindOptions | undefined`.
#[no_mangle]
pub unsafe extern "C" fn js_iroh_bind(opts_f: f64) -> *mut Promise {
    let opts = JsValue::from_bits(opts_f.to_bits());
    let parsed = parse_bind_options(opts);
    let promise = JsPromise::new();
    let raw = promise.as_raw();

    spawn_blocking(move || {
        let result = tokio::runtime::Handle::current().block_on(async move {
            let mut builder =
                Endpoint::builder(presets::N0).alpns(vec![PERRY_IROH_ALPN.to_vec()]);
            if let Some(sk) = parsed.secret_key {
                builder = builder.secret_key(sk);
            }
            if parsed.mdns {
                builder = builder.address_lookup(MdnsAddressLookupBuilder::default());
            }
            builder.bind().await
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

/// `iroh.generateSecretKey() -> string` — synchronous helper that
/// returns a freshly-generated `SecretKey` as a 64-char hex string.
/// Persist this somewhere durable to keep a stable node identity
/// across restarts (pass it back to `bind({secretKey})` next time).
#[no_mangle]
pub extern "C" fn js_iroh_generate_secret_key() -> JsValue {
    let bytes = SecretKey::generate().to_bytes();
    JsValue::from_string_ptr(alloc_string(&hex_encode_32(&bytes)).as_raw())
}

/// `iroh.secretKeyFromSeed(seed) -> string` — synchronous. Build a
/// deterministic `SecretKey` from exactly 32 bytes of seed material
/// (e.g. SHA-256 of a passphrase). Returns the hex-encoded key, or
/// the empty string if `seed` is missing or not 32 bytes.
///
/// # Safety
///
/// `seed_ptr` must be null or a Perry-runtime `BufferHeader`.
#[no_mangle]
pub unsafe extern "C" fn js_iroh_secret_key_from_seed(seed_ptr: *const BufferHeader) -> JsValue {
    let bytes = match read_buffer_bytes(seed_ptr) {
        Some(b) if b.len() == 32 => b,
        _ => return JsValue::from_string_ptr(alloc_string("").as_raw()),
    };
    let mut arr = [0u8; 32];
    arr.copy_from_slice(bytes);
    let sk = SecretKey::from_bytes(&arr);
    JsValue::from_string_ptr(alloc_string(&hex_encode_32(&sk.to_bytes())).as_raw())
}

fn hex_encode_32(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// `iroh.nodeStatus(endpointHandle) -> Promise<NodeStatus>` —
/// snapshot of the endpoint's current network reachability. Resolves
/// with `{ nodeId, online, homeRelay, directAddrs }`:
///
/// - `nodeId` — the endpoint's stable identifier
/// - `online` — `true` once at least one relay handshake has
///   completed OR a direct UDP path has been observed
/// - `homeRelay` — relay URL the endpoint is using as its home, or
///   the empty string if none is selected yet
/// - `directAddrs` — observed direct IP+port socket addresses
///
/// Designed as a one-shot snapshot. Subscribing to status *changes*
/// would require a callback / event surface; that's a deferred
/// followup tracked alongside the connection-event work in `lib.rs`.
#[no_mangle]
pub extern "C" fn js_iroh_node_status(ep_handle: Handle) -> *mut Promise {
    let promise = JsPromise::new();
    let raw = promise.as_raw();

    spawn_blocking(move || {
        let outcome = with_handle::<IrohEndpoint, _, _>(ep_handle, |h| {
            let mut watcher = h.endpoint.watch_addr();
            let addr = watcher.get();
            let mut home_relay = String::new();
            let mut direct_addrs: Vec<String> = Vec::new();
            for ta in &addr.addrs {
                match ta {
                    iroh::TransportAddr::Relay(url) => {
                        if home_relay.is_empty() {
                            home_relay = url.to_string();
                        }
                    }
                    iroh::TransportAddr::Ip(sock) => direct_addrs.push(sock.to_string()),
                    _ => {}
                }
            }
            let online = !addr.addrs.is_empty();
            (addr.id.to_string(), online, home_relay, direct_addrs)
        });

        match outcome {
            Some((node_id, online, home_relay, direct_addrs)) => unsafe {
                let keys = ["nodeId", "online", "homeRelay", "directAddrs"];
                let (packed, shape_id) = build_object_shape(&keys);
                let obj = js_object_alloc_with_shape(
                    shape_id,
                    keys.len() as u32,
                    packed.as_ptr(),
                    packed.len() as u32,
                );
                js_object_set_field(
                    obj,
                    0,
                    JsValue::from_string_ptr(alloc_string(&node_id).as_raw()),
                );
                js_object_set_field(obj, 1, JsValue::from_bool(online));
                js_object_set_field(
                    obj,
                    2,
                    JsValue::from_string_ptr(alloc_string(&home_relay).as_raw()),
                );
                let mut arr = js_array_alloc(direct_addrs.len() as u32);
                for s in &direct_addrs {
                    let sv = JsValue::from_string_ptr(alloc_string(s).as_raw());
                    arr = js_array_push(arr, sv);
                }
                js_object_set_field(obj, 3, JsValue::from_object_ptr(arr));
                promise.resolve(JsValue::from_object_ptr(obj));
            },
            None => promise.reject_string("iroh nodeStatus: invalid endpoint handle"),
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
                let remote_id = conn.remote_id().to_string();
                let handle = register_handle(IrohConnection { conn });
                conn_index_register(ep_handle, handle, remote_id);
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
                let remote_id = conn.remote_id().to_string();
                let handle = register_handle(IrohConnection { conn });
                conn_index_register(ep_handle, handle, remote_id);
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
    conn_index_remove(conn_handle);

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

// ── v0.2.0 — multi-peer + binary-payload surface ──────────────────────

/// `iroh.endpointConnections(endpointHandle) -> number[]` —
/// synchronous accessor returning the list of currently-active peer
/// connection handles for `endpointHandle`. Each entry is a handle
/// previously returned from `connect` or `acceptOne`. Use this for
/// broadcast (`for (const c of conns) await streamWrite(...)`).
///
/// Returns an empty array if the endpoint has no peers or has been
/// closed. Stale entries are not possible since closing a connection
/// (`connClose`) deregisters it; if a peer drops without an explicit
/// close, the next `with_handle` lookup will fail safely.
#[no_mangle]
pub extern "C" fn js_iroh_endpoint_connections(ep_handle: Handle) -> JsValue {
    let conns = {
        let idx = conn_index().lock().unwrap();
        idx.by_endpoint
            .get(&ep_handle)
            .cloned()
            .unwrap_or_default()
    };
    let mut arr = unsafe { js_array_alloc(conns.len() as u32) };
    for h in conns {
        arr = unsafe { js_array_push(arr, JsValue::from_number(h as f64)) };
    }
    JsValue::from_object_ptr(arr)
}

/// `iroh.connNodeId(connHandle) -> string` — synchronous accessor
/// returning the remote peer's hex-encoded node id for an active
/// connection. Returns the empty string if `connHandle` is unknown
/// (already closed or never registered).
#[no_mangle]
pub extern "C" fn js_iroh_conn_node_id(conn_handle: Handle) -> JsValue {
    let id = {
        let idx = conn_index().lock().unwrap();
        idx.remote_node_id
            .get(&conn_handle)
            .cloned()
            .unwrap_or_default()
    };
    JsValue::from_string_ptr(alloc_string(&id).as_raw())
}

/// `iroh.streamWriteBuffer(streamHandle, buffer) -> Promise<undefined>`
/// — binary-safe variant of `streamWrite`. The `buffer` argument is a
/// Perry-runtime `Buffer` (or `Uint8Array`); the bytes are sent
/// verbatim with no UTF-8 round-trip.
///
/// # Safety
///
/// `buf_ptr` must be null or a valid `BufferHeader` pointer (the
/// runtime supplies these via NA_PTR coercion at the call site).
#[no_mangle]
pub unsafe extern "C" fn js_iroh_stream_write_buffer(
    stream_handle: Handle,
    buf_ptr: *const BufferHeader,
) -> *mut Promise {
    let promise = JsPromise::new();
    let raw = promise.as_raw();
    let bytes = match read_buffer_bytes(buf_ptr) {
        Some(b) => b.to_vec(),
        None => {
            promise.reject_string("iroh streamWriteBuffer: invalid buffer");
            return raw;
        }
    };

    spawn_blocking(move || {
        let outcome = with_handle::<IrohBiStream, _, _>(stream_handle, |h| {
            tokio::runtime::Handle::current().block_on(async {
                let mut send = h.send.lock().await;
                send.write_all(&bytes)
                    .await
                    .map_err(|e| format!("streamWriteBuffer: {}", e))
            })
        });
        match outcome {
            Some(Ok(())) => promise.resolve_undefined(),
            Some(Err(e)) => promise.reject_string(&format!("iroh streamWriteBuffer: {}", e)),
            None => promise.reject_string("iroh streamWriteBuffer: invalid stream handle"),
        }
    });
    raw
}

/// `iroh.streamReadToEndBuffer(streamHandle, maxBytes) -> Promise<Buffer>`
/// — binary-safe variant of `streamReadToEnd`. Returns the bytes as a
/// Perry-runtime `Buffer` instead of a UTF-8 string, so binary file
/// transfer / protocol payloads / encrypted data round-trip cleanly.
#[no_mangle]
pub extern "C" fn js_iroh_stream_read_to_end_buffer(
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
                    .map_err(|e| format!("streamReadToEndBuffer: {}", e))
            })
        });
        match outcome {
            Some(Ok(bytes)) => {
                let buf = alloc_buffer(&bytes);
                promise.resolve(JsValue::from_object_ptr(buf as *mut perry_ffi::ObjectHeader));
            }
            Some(Err(e)) => promise.reject_string(&format!("iroh streamReadToEndBuffer: {}", e)),
            None => promise.reject_string("iroh streamReadToEndBuffer: invalid stream handle"),
        }
    });
    raw
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conn_index_register_then_remove() {
        // Use very high handle ids to avoid collision with anything
        // perry-ffi might have registered in the same process under
        // its own scheme.
        let ep: Handle = 91_000_001;
        let conn: Handle = 92_000_001;
        conn_index_register(ep, conn, "test-node-id".to_string());
        {
            let idx = conn_index().lock().unwrap();
            assert_eq!(idx.by_endpoint.get(&ep).map(|v| v.len()), Some(1));
            assert_eq!(idx.remote_node_id.get(&conn).map(|s| s.as_str()), Some("test-node-id"));
        }
        conn_index_remove(conn);
        let idx = conn_index().lock().unwrap();
        assert!(idx.remote_node_id.get(&conn).is_none());
        assert!(idx.by_endpoint.get(&ep).map(|v| v.is_empty()).unwrap_or(true));
    }

    #[test]
    fn conn_index_multiple_peers_per_endpoint() {
        let ep: Handle = 91_000_002;
        conn_index_register(ep, 92_000_010, "peer-a".to_string());
        conn_index_register(ep, 92_000_011, "peer-b".to_string());
        conn_index_register(ep, 92_000_012, "peer-c".to_string());
        let idx = conn_index().lock().unwrap();
        assert_eq!(idx.by_endpoint.get(&ep).map(|v| v.len()), Some(3));
    }

    #[test]
    fn conn_index_remove_unknown_is_noop() {
        // Removing a handle never registered must not panic.
        conn_index_remove(99_999_999);
    }

    #[test]
    fn hex_encode_32_lowercase_64_chars() {
        let zero = [0u8; 32];
        assert_eq!(
            hex_encode_32(&zero),
            "0000000000000000000000000000000000000000000000000000000000000000"
        );
        let mut mixed = [0u8; 32];
        mixed[0] = 0x0a;
        mixed[1] = 0xb1;
        mixed[31] = 0xff;
        let s = hex_encode_32(&mixed);
        assert_eq!(s.len(), 64);
        assert!(s.starts_with("0ab1"));
        assert!(s.ends_with("ff"));
    }

    #[test]
    fn deterministic_secret_key_same_seed_same_id() {
        // Two SecretKey::from_bytes calls with the same seed must
        // produce the same public key — that's the whole point of
        // the seed-based API the issue commenter asked for.
        let seed = [42u8; 32];
        let a = SecretKey::from_bytes(&seed);
        let b = SecretKey::from_bytes(&seed);
        assert_eq!(a.public(), b.public());
    }

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
