// Service-worker logic, free of `chrome.*` so it can be unit tested.
//
// Trust rules (spec §6.2, §8.4):
// * Only our own content script in the top frame of a tab may ask.
// * The origin sent to the daemon comes from `sender.tab.url`, never from
//   the message. `sender.origin` (the frame's own origin) must agree.
// * The suggestion handle stays here (session storage, not readable by
//   content scripts); the page side only ever says "consume".
// * Consume re-derives the origin and requires it to equal the origin the
//   handle was issued for.

import {
  type ContentReply,
  type DaemonResponse,
  PROTOCOL_VERSION,
  parseContentRequest,
  parseDaemonResponse,
} from "./protocol";

/** Handles live slightly shorter than the daemon's 60 s. */
export const SUGGESTION_TTL_MS = 55_000;

export interface KV {
  get(key: string): Promise<unknown>;
  set(key: string, value: unknown): Promise<void>;
  remove(key: string): Promise<void>;
}

export interface Deps {
  /** `chrome.runtime.sendNativeMessage` to our host. Rejects if unavailable. */
  native(message: object): Promise<unknown>;
  /** `chrome.storage.session`: handles. */
  session: KV;
  /** `chrome.storage.local`: user settings. */
  local: KV;
  now(): number;
  newRequestId(): string;
  selfId: string;
  /** Development builds accept localhost test sites. */
  allowLocalhost: boolean;
}

export interface SenderLike {
  id?: string | undefined;
  frameId?: number | undefined;
  origin?: string | undefined;
  tab?: { id?: number | undefined; url?: string | undefined } | undefined;
}

export interface Settings {
  paused: boolean;
  /** Origins where the user never wants suggestions. */
  denied: string[];
}

export const SETTINGS_KEY = "settings";

export async function getSettings(local: KV): Promise<Settings> {
  const raw = await local.get(SETTINGS_KEY);
  const s = (typeof raw === "object" && raw !== null ? raw : {}) as Partial<Settings>;
  return {
    paused: s.paused === true,
    denied: Array.isArray(s.denied) ? s.denied.filter((d) => typeof d === "string") : [],
  };
}

export function originAllowed(url: URL, allowLocalhost: boolean): boolean {
  if (url.hostname === "localhost") {
    return allowLocalhost && (url.protocol === "https:" || url.protocol === "http:");
  }
  return url.protocol === "https:";
}

/** The trusted (origin, tab) for a message, or null to ignore it. */
export function senderContext(
  sender: SenderLike,
  deps: Pick<Deps, "selfId" | "allowLocalhost">,
): { origin: string; tabId: number } | null {
  if (sender.id !== deps.selfId || sender.frameId !== 0) return null;
  const tabId = sender.tab?.id;
  const tabUrl = sender.tab?.url;
  if (typeof tabId !== "number" || tabId < 0 || typeof tabUrl !== "string") return null;
  let url: URL;
  try {
    url = new URL(tabUrl);
  } catch {
    return null;
  }
  if (!originAllowed(url, deps.allowLocalhost)) return null;
  if (sender.origin !== undefined && sender.origin !== url.origin) return null;
  return { origin: url.origin, tabId };
}

interface Pending {
  suggestionId: string;
  origin: string;
  issuedAt: number;
}

const pendingKey = (tabId: number) => `pending:${tabId}`;

function asPending(x: unknown): Pending | null {
  if (typeof x !== "object" || x === null) return null;
  const p = x as Record<string, unknown>;
  return typeof p["suggestionId"] === "string" &&
    typeof p["origin"] === "string" &&
    typeof p["issuedAt"] === "number"
    ? { suggestionId: p["suggestionId"], origin: p["origin"], issuedAt: p["issuedAt"] }
    : null;
}

async function callDaemon(deps: Deps, op: object): Promise<DaemonResponse | null> {
  const requestId = deps.newRequestId();
  let raw: unknown;
  try {
    raw = await deps.native({ v: PROTOCOL_VERSION, request_id: requestId, ...op });
  } catch {
    return null;
  }
  return parseDaemonResponse(raw, requestId);
}

function errorReply(resp: DaemonResponse | null): ContentReply {
  if (resp === null) return { kind: "error", reason: "unavailable" };
  if (resp.status === "error") {
    switch (resp.code) {
      case "paused":
        return { kind: "error", reason: "paused" };
      case "expired":
      case "no_match":
        return { kind: "error", reason: "expired" };
      case "daemon_unavailable":
        return { kind: "error", reason: "unavailable" };
      default:
        return { kind: "error", reason: "rejected" };
    }
  }
  return { kind: "error", reason: "rejected" };
}

export async function handleContentMessage(
  message: unknown,
  sender: SenderLike,
  deps: Deps,
): Promise<ContentReply | null> {
  const req = parseContentRequest(message);
  const ctx = senderContext(sender, deps);
  if (req === null || ctx === null) return null;
  const key = pendingKey(ctx.tabId);

  switch (req.type) {
    case "dismiss":
      await deps.session.remove(key);
      return { kind: "none" };

    case "find": {
      const settings = await getSettings(deps.local);
      if (settings.paused || settings.denied.includes(ctx.origin)) {
        await deps.session.remove(key);
        return { kind: "none" };
      }
      const resp = await callDaemon(deps, {
        op: "find_suggestion",
        top_origin: ctx.origin,
        tab_id: ctx.tabId,
      });
      if (resp?.status === "available") {
        const pending: Pending = {
          suggestionId: resp.suggestion_id,
          origin: ctx.origin,
          issuedAt: deps.now(),
        };
        await deps.session.set(key, pending);
        return { kind: "available", label: resp.label };
      }
      await deps.session.remove(key);
      if (resp?.status === "none") return { kind: "none" };
      return errorReply(resp);
    }

    case "consume": {
      const pending = asPending(await deps.session.get(key));
      // Single use on our side too, whatever happens next.
      await deps.session.remove(key);
      if (
        pending === null ||
        pending.origin !== ctx.origin ||
        deps.now() - pending.issuedAt > SUGGESTION_TTL_MS ||
        deps.now() < pending.issuedAt
      ) {
        return { kind: "error", reason: "expired" };
      }
      const settings = await getSettings(deps.local);
      if (settings.paused || settings.denied.includes(ctx.origin)) {
        return { kind: "error", reason: "paused" };
      }
      const resp = await callDaemon(deps, {
        op: "consume_suggestion",
        suggestion_id: pending.suggestionId,
        top_origin: ctx.origin,
        tab_id: ctx.tabId,
      });
      if (resp?.status === "code") return { kind: "code", code: resp.code };
      return errorReply(resp);
    }
  }
}

/** For the popup: is the daemon reachable? */
export async function daemonStatus(
  deps: Deps,
): Promise<{ reachable: false } | { reachable: true; version: string; paused: boolean }> {
  const resp = await callDaemon(deps, { op: "status" });
  return resp?.status === "ok"
    ? { reachable: true, version: resp.daemon_version, paused: resp.paused }
    : { reachable: false };
}
