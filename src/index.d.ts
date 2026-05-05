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
}

declare module "@perryts/iroh" {
  export * from "iroh";
}
