# @perryts/iroh

Native bindings for [Iroh](https://www.iroh.computer/) — direct peer-to-peer QUIC connections with hole punching + relay fallback — for the [Perry TypeScript-to-native compiler](https://github.com/PerryTS/perry).

Closes [PerryTS/perry#425](https://github.com/PerryTS/perry/issues/425).

## What this is

A Perry "native library" package: a Rust crate exporting `extern "C"` symbols that the Perry compiler links into your TypeScript program. From your TypeScript code you import `iroh` like any npm package; under the hood every method call resolves to a direct call into the bundled staticlib — no Node addon, no IPC, no JSON marshalling.

This package contains:

- `src/lib.rs` — the Rust crate that wraps `iroh` and exposes `js_iroh_*` `extern "C"` symbols
- `src/index.d.ts` — the TypeScript surface (`iroh` module declaration) Perry resolves at compile time
- `Cargo.toml` — staticlib build config consumed by the Perry linker
- `package.json` — includes the `perry.nativeLibrary` manifest block

## Install

```sh
bun add @perryts/iroh
# or
npm install @perryts/iroh
```

The package's `package.json` declares a `perry.nativeLibrary` block (see the [manifest spec](https://github.com/PerryTS/perry/blob/main/docs/src/native-libraries/manifest-v1.md)) which Perry's compiler reads at link time to discover the staticlib + `extern "C"` symbols. No post-install build step — Perry compiles the Rust crate as part of your project's build.

## Quick start

A request/response peer-to-peer round trip. The server binds, prints its node id (share that out-of-band), waits for one peer, reads a message, and echoes it back. The client binds its own endpoint, dials the server's node id, sends a message, and reads the reply.

### Server

```typescript
import * as iroh from "iroh";

const ep = await iroh.bind();
const myId = await iroh.nodeId(ep);
console.log("share this with the peer:", myId);

const conn = await iroh.acceptOne(ep);
const stream = await iroh.acceptBi(conn);
const msg = await iroh.streamReadToEnd(stream, 65_536);
await iroh.streamWrite(stream, `echo: ${msg}`);
await iroh.streamFinish(stream);
await iroh.connClose(conn);
await iroh.close(ep);
```

### Client

```typescript
import * as iroh from "iroh";

const ep = await iroh.bind();
const conn = await iroh.connect(ep, "<server-node-id-from-server-stdout>");
const stream = await iroh.openBi(conn);
await iroh.streamWrite(stream, "hello, peer!");
await iroh.streamFinish(stream);
const reply = await iroh.streamReadToEnd(stream, 65_536);
console.log(reply);
await iroh.connClose(conn);
await iroh.close(ep);
```

## The handshake flow

Iroh uses three layers of object — endpoint, connection, bi-directional stream — and you call them in roughly mirrored sequences on each side. The server side reads, the client side writes; whichever side calls `streamFinish` first signals "no more bytes from me" so the other side's `streamReadToEnd` resolves.

| Step | Server | Client |
|---|---|---|
| 1 | `bind()` → endpoint | `bind()` → endpoint |
| 2 | `nodeId(ep)` → publish out-of-band | `connect(ep, nodeId)` → connection |
| 3 | `acceptOne(ep)` → connection | `openBi(conn)` → stream |
| 4 | `acceptBi(conn)` → stream | `streamWrite` + `streamFinish` |
| 5 | `streamReadToEnd` | `streamReadToEnd` |
| 6 | `streamWrite` + `streamFinish` | `connClose` + `close` |
| 7 | `connClose` + `close` | — |

`bind` uses Iroh's `N0` preset: discovery via the n0 number-DNS, n0 relay servers for hole-punch fallback. v0.3 adds optional `secretKey` (stable identity across restarts) and `mdns` (LAN peer discovery) knobs — see [`bind(options?)`](#bindoptions) below.

## API reference

### `bind(options?)`

```typescript
interface BindOptions {
  secretKey?: string;  // hex- or base32-encoded SecretKey for stable identity
  mdns?: boolean;      // enable LAN peer discovery via mDNS-like swarm discovery
}

function bind(options?: BindOptions): Promise<EndpointHandle>
```

Bind a fresh QUIC endpoint. Registers the v0 ALPN (`perry-iroh/0`) so this same endpoint can both dial peers and accept incoming connections from clients running this library.

```typescript
// No options — fresh random identity, n0 relay/DNS only.
const ep = await iroh.bind();

// Stable identity across restarts.
const sk = process.env.IROH_SECRET ?? iroh.generateSecretKey();
// (persist `sk` somewhere, e.g. write it to .env)
const ep2 = await iroh.bind({ secretKey: sk });

// LAN discovery on top of the relay.
const ep3 = await iroh.bind({ secretKey: sk, mdns: true });
```

### `nodeId(endpoint)`

```typescript
function nodeId(endpoint: EndpointHandle): Promise<string>
```

Return the local node's stable identifier (a hex-encoded Ed25519 public key). Share this with peers so they can dial you. Awaits the endpoint coming online before reading the address — safe to call right after `bind()`.

```typescript
const myId = await iroh.nodeId(ep);
// e.g. "f49a76...c1b4e2"
```

### `connect(endpoint, nodeId)`

```typescript
function connect(endpoint: EndpointHandle, nodeId: string): Promise<ConnHandle>
```

Open an outgoing connection to a peer addressed by its node id (the value of the peer's `nodeId(ep)`). Resolves once the QUIC handshake completes. Uses the hardcoded v0 ALPN, so the peer must also be running `@perryts/iroh`.

```typescript
const conn = await iroh.connect(ep, serverNodeId);
```

### `acceptOne(endpoint)`

```typescript
function acceptOne(endpoint: EndpointHandle): Promise<ConnHandle>
```

Wait for the next incoming peer connection on this endpoint and finish the handshake. Rejects if the endpoint is closed before a peer arrives. Each call yields one connection — for a server that handles many peers, call it in a loop.

```typescript
const conn = await iroh.acceptOne(ep);
```

### `openBi(conn)`

```typescript
function openBi(conn: ConnHandle): Promise<BiStreamHandle>
```

Open a bi-directional stream from the local end of the connection. The peer must call `acceptBi` to pick it up.

```typescript
const stream = await iroh.openBi(conn);
```

### `acceptBi(conn)`

```typescript
function acceptBi(conn: ConnHandle): Promise<BiStreamHandle>
```

Accept the next bi-directional stream the peer opens. Mirrors `openBi`.

```typescript
const stream = await iroh.acceptBi(conn);
```

### `streamWrite(stream, data)`

```typescript
function streamWrite(stream: BiStreamHandle, data: string): Promise<void>
```

Write a UTF-8 string to the send half of the stream. v0 is text-only — encode binary as base64/hex if needed. Multiple writes are concatenated; the peer sees the bytes once you call `streamFinish` (or in chunks as they arrive over the wire, terminated by `streamFinish`).

```typescript
await iroh.streamWrite(stream, "hello, peer!");
```

### `streamFinish(stream)`

```typescript
function streamFinish(stream: BiStreamHandle): Promise<void>
```

Close the send half of the stream. The peer's pending `streamReadToEnd` resolves once the in-flight bytes drain. Without this call, the peer's read would hang.

```typescript
await iroh.streamFinish(stream);
```

### `streamReadToEnd(stream, maxBytes)`

```typescript
function streamReadToEnd(stream: BiStreamHandle, maxBytes: number): Promise<string>
```

Drain the recv half of the stream and resolve with the bytes as a UTF-8 string. Rejects if the peer's payload exceeds `maxBytes` (back-pressure cap to prevent unbounded buffering) or if the bytes aren't valid UTF-8.

```typescript
const reply = await iroh.streamReadToEnd(stream, 65_536);
```

### `connClose(conn)`

```typescript
function connClose(conn: ConnHandle): Promise<void>
```

Close a peer connection with a clean QUIC shutdown frame and wait for the close to propagate. Idempotent — closing an already-dropped handle resolves successfully.

```typescript
await iroh.connClose(conn);
```

### `close(endpoint)`

```typescript
function close(endpoint: EndpointHandle): Promise<void>
```

Close the endpoint gracefully. Drops any remaining handle state. Idempotent.

```typescript
await iroh.close(ep);
```

## v0.3.0 — bind options, deterministic keys, status snapshots

### `generateSecretKey()` and `secretKeyFromSeed(seed)`

```typescript
function generateSecretKey(): string;
function secretKeyFromSeed(seed: Uint8Array | Buffer): string;
```

Synchronous helpers for producing the `secretKey` you pass into `bind`. `generateSecretKey` returns a fresh random key as a 64-char hex string; `secretKeyFromSeed` takes exactly 32 bytes (e.g. a SHA-256 of a passphrase) and returns the deterministic key derived from those bytes — same seed in, same key out, same `nodeId` out. Returns `""` on a malformed (wrong-length) seed.

```typescript
import { createHash } from "node:crypto";

// Same passphrase → same nodeId every run, no env file needed.
const seed = createHash("sha256").update("my-app:dev-fixture").digest();
const sk = iroh.secretKeyFromSeed(seed);
const ep = await iroh.bind({ secretKey: sk });
```

### `nodeStatus(endpoint)`

```typescript
interface NodeStatus {
  nodeId: string;
  online: boolean;
  homeRelay: string;       // empty string if none yet
  directAddrs: string[];   // observed "ip:port" entries
}

function nodeStatus(endpoint: EndpointHandle): Promise<NodeStatus>;
```

One-shot snapshot of the endpoint's current network reachability — useful for healthchecks and human-readable status pages. Subscribing to *changes* would need a callback/event surface; that's a deferred followup tracked alongside the connection-event work in `lib.rs`.

```typescript
const status = await iroh.nodeStatus(ep);
console.log(status);
// {
//   nodeId: "f49a76...c1b4e2",
//   online: true,
//   homeRelay: "https://use1-1.relay.iroh.network./",
//   directAddrs: ["192.168.1.42:51820", "[2601:...]:51820"]
// }
```

## v0.2.0 — multi-peer + binary streams

### `endpointConnections(endpoint)` and `connNodeId(conn)`

```typescript
function endpointConnections(endpoint: EndpointHandle): ConnHandle[];
function connNodeId(conn: ConnHandle): string;
```

Synchronous accessors for fan-out / broadcast. `endpointConnections` returns every active peer connection handle that was registered via `connect` or `acceptOne` (and not yet closed via `connClose`). `connNodeId` looks up the remote node id without round-tripping a Promise.

```typescript
// Server: broadcast a message to every connected client
const conns = iroh.endpointConnections(ep);
for (const c of conns) {
  console.log("sending to", iroh.connNodeId(c));
  const stream = await iroh.openBi(c);
  await iroh.streamWrite(stream, "broadcast: hello");
  await iroh.streamFinish(stream);
}
```

### `streamWriteBuffer(stream, buffer)` and `streamReadToEndBuffer(stream, maxBytes)`

```typescript
function streamWriteBuffer(stream: BiStreamHandle, buffer: Uint8Array | Buffer): Promise<void>;
function streamReadToEndBuffer(stream: BiStreamHandle, maxBytes: number): Promise<Uint8Array>;
```

Binary-safe variants of `streamWrite` / `streamReadToEnd`. Use these for file transfer, encrypted payloads, or anything that isn't valid UTF-8.

```typescript
// Client: send a PNG over QUIC, peer reads it back as a Buffer
import { readFile } from 'node:fs/promises';

const png = await readFile('hero.png');
const stream = await iroh.openBi(conn);
await iroh.streamWriteBuffer(stream, png);
await iroh.streamFinish(stream);

// Peer side
const bytes = await iroh.streamReadToEndBuffer(serverStream, 16 * 1024 * 1024);
console.log("received", bytes.length, "bytes");
```

## Types

Exported from the `iroh` module declaration in `src/index.d.ts`:

```typescript
type EndpointHandle = number & { readonly __irohEndpoint: unique symbol };
type ConnHandle     = number & { readonly __irohConn:     unique symbol };
type BiStreamHandle = number & { readonly __irohStream:   unique symbol };
```

These are opaque branded numbers — you should never inspect or arithmetic on them. The brand prevents you from passing an `EndpointHandle` where a `ConnHandle` is expected.

## ALPN

Hardcoded to `"perry-iroh/0"` for v0 — every server registers it at `bind()` time, every client connects with it. This means client and server must both be on `@perryts/iroh` (or another implementation that opts into the same ALPN). Per-call ALPN strings are a v1 followup.

## Error handling

Every async function rejects with an `Error` whose message is prefixed by the operation, e.g. `iroh connect: bad node id: invalid character`. Common rejection reasons:

- Invalid handle (`iroh <op>: invalid <kind> handle`) — you passed a handle that was never returned by this library, or one that was already consumed by `close` / `connClose`.
- Bad node id (`iroh connect: bad node id: ...`) — the string passed to `connect` is not a parseable Iroh `EndpointId`.
- Endpoint closed before peer connected (`iroh acceptOne: ...`) — `close` was called while `acceptOne` was pending.
- Payload too large (`iroh streamReadToEnd: ...`) — the peer wrote more than `maxBytes` before calling `streamFinish`.
- Non-UTF-8 payload (`iroh streamReadToEnd: payload was not valid UTF-8: ...`) — the peer wrote raw binary; v0 is text-only.

## Status & roadmap

What's there:

- `bind(options?)` / `nodeId` / `close` / `nodeStatus` (snapshot)
- `generateSecretKey` / `secretKeyFromSeed` for stable identities
- `connect` / `acceptOne` / `connClose`
- `endpointConnections` / `connNodeId` for fan-out
- `openBi` / `acceptBi` / `streamWrite` / `streamFinish` / `streamReadToEnd`
- `streamWriteBuffer` / `streamReadToEndBuffer` (binary)
- `bind({ mdns: true })` for LAN peer discovery

Known gaps, tracked in [`PerryTS/perry`](https://github.com/PerryTS/perry):

- Per-call ALPN strings (still hardcodes `perry-iroh/0`)
- Streaming subscriptions to node-status / discovery events — `nodeStatus` returns a one-shot snapshot today; subscribing to changes needs a callback/event surface that's a separate followup (also blocks `endpoint.on('connection', cb)`-style)
- Multiple bi-streams per connection in idiomatic JS (today: open one stream and use it)
- Unidirectional streams + datagram surface

## Versioning

Pre-1.0. The `perry.nativeLibrary.abiVersion` (currently `0.5`) is a hard pin against Perry's perry-ffi ABI — bump it in lockstep with the Perry release that the bindings target.

## License

MIT — see [LICENSE](./LICENSE).
