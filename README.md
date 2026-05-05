# @perryts/iroh

Native bindings for [Iroh](https://www.iroh.computer/) — direct peer-to-peer QUIC connections with hole punching + relay fallback — for the [Perry TypeScript-to-native compiler](https://github.com/PerryTS/perry).

Closes [PerryTS/perry#425](https://github.com/PerryTS/perry/issues/425).

## What this is

A Perry "native library" package: a Rust crate exporting `extern "C"` symbols that the Perry compiler links into your TypeScript program. From your TypeScript code you import `iroh` like any npm package; under the hood every method call resolves to a direct call into the bundled staticlib.

## Install

```sh
bun add @perryts/iroh
# or
npm install @perryts/iroh
```

The package's `package.json` declares a `perry.nativeLibrary` block (see the [manifest spec](https://github.com/PerryTS/perry/blob/main/docs/src/native-libraries/manifest-v1.md)) which Perry's compiler reads at link time to discover the staticlib + `extern "C"` symbols.

## Usage

```typescript
import * as iroh from "iroh";

// Server: bind, share node id, accept one peer, echo bytes.
{
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
}

// Client: bind, connect to peer's node id, send + read echo.
{
  const ep = await iroh.bind();
  const conn = await iroh.connect(ep, "<server-node-id>");
  const stream = await iroh.openBi(conn);
  await iroh.streamWrite(stream, "hello, peer!");
  await iroh.streamFinish(stream);
  const reply = await iroh.streamReadToEnd(stream, 65_536);
  console.log(reply);
  await iroh.connClose(conn);
  await iroh.close(ep);
}
```

## API

| Function | Type | Notes |
|---|---|---|
| `bind()` | `Promise<endpointHandle>` | Bind a fresh QUIC endpoint using Iroh's `N0` relay preset; registers the v0 ALPN |
| `nodeId(endpoint)` | `Promise<string>` | Hex/base32 EndpointId — share this for peers to connect |
| `connect(endpoint, nodeId)` | `Promise<connHandle>` | Outgoing connection |
| `acceptOne(endpoint)` | `Promise<connHandle>` | Wait for the next incoming peer |
| `openBi(conn)` | `Promise<biStreamHandle>` | Open a bi-directional stream from the local end |
| `acceptBi(conn)` | `Promise<biStreamHandle>` | Accept the next stream the peer opens |
| `streamWrite(stream, dataString)` | `Promise<void>` | Write UTF-8 to the send half |
| `streamFinish(stream)` | `Promise<void>` | Close the send half so the peer's `streamReadToEnd` resolves |
| `streamReadToEnd(stream, maxBytes)` | `Promise<string>` | Drain the recv half (errors above maxBytes) |
| `connClose(conn)` | `Promise<void>` | Clean QUIC shutdown |
| `close(endpoint)` | `Promise<void>` | Close the endpoint |

## ALPN

Hardcoded to `"perry-iroh/0"` for v0 — every server registers it at `bind()` time, every client connects with it. Per-call ALPN strings are a v1 followup.

## Status

MVP — connection-event callbacks (e.g. `endpoint.on('connection', cb)`) and broadcast-style fan-out are followups. Tracked in the upstream [`PerryTS/perry`](https://github.com/PerryTS/perry) repo.

## License

MIT — see [LICENSE](./LICENSE).
