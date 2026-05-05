declare module "iroh" {
  export type EndpointHandle = number & { readonly __irohEndpoint: unique symbol };
  export type ConnHandle = number & { readonly __irohConn: unique symbol };
  export type BiStreamHandle = number & { readonly __irohStream: unique symbol };

  export function bind(): Promise<EndpointHandle>;
  export function nodeId(endpoint: EndpointHandle): Promise<string>;
  export function close(endpoint: EndpointHandle): Promise<void>;

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
