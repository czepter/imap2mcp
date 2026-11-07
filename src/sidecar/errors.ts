/** JSON-RPC error codes of the sidecar contract (docs/DESIGN_V1.md, "Sidecar RPC"). */
export const RPC_AUTH = -32001;
export const RPC_UNKNOWN_MAILBOX = -32002;
export const RPC_STALE_REFERENCE = -32010;
export const RPC_UPSTREAM = -32020;
export const RPC_TIMEOUT = -32030;

/** The sidecar answered with a JSON-RPC error. `message` is already redacted by the sidecar; never add secrets. */
export class SidecarRpcError extends Error {
  constructor(readonly code: number, message: string) {
    super(message);
    this.name = "SidecarRpcError";
  }
}

/** The sidecar could not be reached / is not running / dropped the connection. */
export class SidecarUnavailableError extends Error {
  constructor(message = "Sidecar is unavailable") {
    super(message);
    this.name = "SidecarUnavailableError";
  }
}

/** No response within the client-side deadline. */
export class SidecarTimeoutError extends Error {
  constructor(readonly method: string) {
    super(`Sidecar call ${method} timed out`);
    this.name = "SidecarTimeoutError";
  }
}
