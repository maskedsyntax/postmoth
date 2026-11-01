// Browser protocol v1 (mirrors crates/postmoth-ipc/src/browser.rs) and the
// internal content-script <-> service-worker messages.

export const HOST_NAME = "dev.postmoth.native_host";
export const PROTOCOL_VERSION = 1;

export type ErrorCode =
  | "no_match"
  | "expired"
  | "paused"
  | "daemon_unavailable"
  | "bad_request"
  | "forbidden"
  | "version_unsupported"
  | "internal";

const ERROR_CODES: ReadonlySet<string> = new Set([
  "no_match",
  "expired",
  "paused",
  "daemon_unavailable",
  "bad_request",
  "forbidden",
  "version_unsupported",
  "internal",
]);

export type DaemonBody =
  | { status: "ok"; daemon_version: string; paused: boolean }
  | { status: "available"; suggestion_id: string; label: string }
  | { status: "none" }
  | { status: "code"; code: string }
  | { status: "error"; code: ErrorCode; message: string };

export type DaemonResponse = { v: number; request_id: string } & DaemonBody;

function isObj(x: unknown): x is Record<string, unknown> {
  return typeof x === "object" && x !== null && !Array.isArray(x);
}

/** Strictly validate a response from the native host. */
export function parseDaemonResponse(x: unknown, requestId: string): DaemonResponse | null {
  if (!isObj(x) || x["v"] !== PROTOCOL_VERSION || x["request_id"] !== requestId) return null;
  const base = { v: PROTOCOL_VERSION, request_id: requestId };
  switch (x["status"]) {
    case "ok":
      if (typeof x["daemon_version"] !== "string" || typeof x["paused"] !== "boolean") return null;
      return { ...base, status: "ok", daemon_version: x["daemon_version"], paused: x["paused"] };
    case "available":
      if (typeof x["suggestion_id"] !== "string" || typeof x["label"] !== "string") return null;
      return {
        ...base,
        status: "available",
        suggestion_id: x["suggestion_id"],
        label: x["label"].slice(0, 64),
      };
    case "none":
      return { ...base, status: "none" };
    case "code":
      if (typeof x["code"] !== "string" || !/^[A-Za-z0-9 -]{3,16}$/.test(x["code"])) return null;
      return { ...base, status: "code", code: x["code"] };
    case "error": {
      const code = x["code"];
      if (typeof code !== "string" || !ERROR_CODES.has(code)) return null;
      return {
        ...base,
        status: "error",
        code: code as ErrorCode,
        message: typeof x["message"] === "string" ? x["message"] : "",
      };
    }
    default:
      return null;
  }
}

/** Content script -> service worker. Note: no origin, no ids. The service
 *  worker derives everything from `sender`. */
export type ContentRequest = { type: "find" } | { type: "consume" } | { type: "dismiss" };

export function parseContentRequest(x: unknown): ContentRequest | null {
  if (!isObj(x) || Object.keys(x).length !== 1) return null;
  const t = x["type"];
  return t === "find" || t === "consume" || t === "dismiss" ? { type: t } : null;
}

/** Service worker -> content script. */
export type ContentReply =
  | { kind: "available"; label: string }
  | { kind: "none" }
  | { kind: "code"; code: string }
  | { kind: "error"; reason: "expired" | "paused" | "unavailable" | "rejected" };
