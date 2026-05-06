declare module "iroh" {
  export type EndpointHandle = number & { readonly __irohEndpoint: unique symbol };
  export type ConnHandle = number & { readonly __irohConn: unique symbol };
  export type BiStreamHandle = number & { readonly __irohStream: unique symbol };

  /**
   * Optional configuration accepted by `bind`.
   *
   * Declare keys in source order if you set both — the native parser
   * dispatches by *type* (string vs. boolean), so order doesn't actually
   * matter as long as the two fields have disjoint types, but keeping the
   * declared order matches the rest of the perry binding ecosystem.
   */
  export interface BindOptions {
    /**
     * Hex- or base32-encoded `SecretKey` for stable node identity across
     * restarts. Generate one once with `generateSecretKey` (or derive from
     * a seed via `secretKeyFromSeed`), persist it, then pass it back here
     * on every subsequent `bind`. Omit to generate a fresh random key.
     */
    secretKey?: string;
    /**
     * Enable LAN peer discovery via mDNS-like swarm discovery, on top of
     * (not in place of) the n0 relay/DNS defaults. Useful for offices
     * and home networks where two peers are on the same subnet and you
     * want them to find each other without round-tripping a relay.
     */
    mdns?: boolean;
  }

  /**
   * Snapshot of an endpoint's reachability — what `nodeStatus` resolves with.
   */
  export interface NodeStatus {
    /** Stable identifier for this endpoint (hex-encoded Ed25519 public key). */
    nodeId: string;
    /** True once at least one relay or direct UDP path is established. */
    online: boolean;
    /** Home relay URL, or empty string if none has been selected yet. */
    homeRelay: string;
    /** Observed direct `ip:port` socket addresses. */
    directAddrs: string[];
  }

  export function bind(options?: BindOptions): Promise<EndpointHandle>;
  export function nodeId(endpoint: EndpointHandle): Promise<string>;
  export function close(endpoint: EndpointHandle): Promise<void>;

  /**
   * Generate a fresh random `SecretKey` and return it hex-encoded.
   * Persist the result somewhere durable to keep a stable node identity
   * across restarts (pass it back via `bind({ secretKey })`).
   */
  export function generateSecretKey(): string;

  /**
   * Derive a `SecretKey` deterministically from exactly 32 bytes of seed
   * material (e.g. SHA-256 of a passphrase, or any fixed 32-byte value).
   * Returns the hex-encoded key. Same seed always produces the same key,
   * which means the same `nodeId` — useful for tests, fixtures, and
   * passphrase-derived identities. Returns the empty string if the seed
   * is missing or not exactly 32 bytes long.
   */
  export function secretKeyFromSeed(seed: Uint8Array | Buffer): string;

  /**
   * Snapshot of the endpoint's current network reachability. Resolves
   * with `{ nodeId, online, homeRelay, directAddrs }`. This is a
   * one-shot read; subscribing to changes is a deferred followup.
   */
  export function nodeStatus(endpoint: EndpointHandle): Promise<NodeStatus>;

  export function connect(endpoint: EndpointHandle, nodeId: string): Promise<ConnHandle>;
  export function acceptOne(endpoint: EndpointHandle): Promise<ConnHandle>;
  export function connClose(conn: ConnHandle): Promise<void>;

  export function openBi(conn: ConnHandle): Promise<BiStreamHandle>;
  export function acceptBi(conn: ConnHandle): Promise<BiStreamHandle>;
  export function streamWrite(stream: BiStreamHandle, data: string): Promise<void>;
  export function streamFinish(stream: BiStreamHandle): Promise<void>;
  export function streamReadToEnd(stream: BiStreamHandle, maxBytes: number): Promise<string>;

  // v0.2.0 — multi-peer enumeration + binary stream payloads
  /**
   * List active peer connection handles for an endpoint. Use this for
   * broadcast / fan-out: `for (const c of endpointConnections(ep)) { ... }`.
   * Empty array if the endpoint has no peers or has been closed.
   */
  export function endpointConnections(endpoint: EndpointHandle): ConnHandle[];

  /**
   * Synchronous accessor for the remote peer's hex-encoded node id on
   * an active connection. Empty string if `conn` is unknown.
   */
  export function connNodeId(conn: ConnHandle): string;

  /**
   * Binary-safe variant of `streamWrite`. Bytes are sent verbatim.
   * Use this for file transfer / encrypted payloads / protocol bytes
   * that aren't valid UTF-8.
   */
  export function streamWriteBuffer(stream: BiStreamHandle, buffer: Uint8Array | Buffer): Promise<void>;

  /**
   * Binary-safe variant of `streamReadToEnd`. Returns a Buffer instead
   * of decoding to UTF-8.
   */
  export function streamReadToEndBuffer(stream: BiStreamHandle, maxBytes: number): Promise<Uint8Array>;
}

declare module "@perryts/iroh" {
  export * from "iroh";
}
