import { beforeEach, describe, expect, it } from "vitest";
import { type Deps, type KV, SETTINGS_KEY, SUGGESTION_TTL_MS, handleContentMessage } from "../src/core";

class MemKV implements KV {
  m = new Map<string, unknown>();
  async get(k: string) {
    return this.m.get(k);
  }
  async set(k: string, v: unknown) {
    this.m.set(k, structuredClone(v));
  }
  async remove(k: string) {
    this.m.delete(k);
  }
}

const SELF = "nnbgdhodaoggiiakpcmnlkgalgkoecbk";
const SID = "6f1c2c7e-6a3b-4f7e-9b1a-1e2d3c4b5a69";

/** A fake daemon + host: one candidate for login.example.com. */
function makeDeps() {
  const sent: Record<string, unknown>[] = [];
  let clock = 1_000_000;
  let n = 0;
  let consumed = false;
  const deps: Deps = {
    async native(m) {
      const req = m as Record<string, unknown>;
      sent.push(req);
      const base = { v: 1, request_id: req["request_id"] };
      if (req["op"] === "find_suggestion") {
        return req["top_origin"] === "https://login.example.com" && !consumed
          ? { ...base, status: "available", suggestion_id: SID, label: "Code from Postmoth" }
          : { ...base, status: "none" };
      }
      if (req["op"] === "consume_suggestion") {
        if (req["suggestion_id"] !== SID || consumed || req["top_origin"] !== "https://login.example.com") {
          return { ...base, status: "error", code: "no_match", message: "no_match" };
        }
        consumed = true;
        return { ...base, status: "code", code: "482913" };
      }
      return { ...base, status: "ok", daemon_version: "0.1.0", paused: false };
    },
    session: new MemKV(),
    local: new MemKV(),
    now: () => clock,
    newRequestId: () => `req-${++n}`,
    selfId: SELF,
    allowLocalhost: false,
  };
  return { deps, sent, tick: (ms: number) => (clock += ms) };
}

const sender = (url: string, extra: Record<string, unknown> = {}) => ({
  id: SELF,
  frameId: 0,
  origin: new URL(url).origin,
  tab: { id: 7, url },
  ...extra,
});

const LOGIN = "https://login.example.com/2fa?x=1";

let h: ReturnType<typeof makeDeps>;
beforeEach(() => {
  h = makeDeps();
});

describe("find + consume", () => {
  it("derives origin from the tab, not the message, and fills once", async () => {
    const r = await handleContentMessage({ type: "find" }, sender(LOGIN), h.deps);
    expect(r).toEqual({ kind: "available", label: "Code from Postmoth" });
    expect(h.sent[0]).toMatchObject({ op: "find_suggestion", top_origin: "https://login.example.com", tab_id: 7 });

    const c = await handleContentMessage({ type: "consume" }, sender(LOGIN), h.deps);
    expect(c).toEqual({ kind: "code", code: "482913" });
    const again = await handleContentMessage({ type: "consume" }, sender(LOGIN), h.deps);
    expect(again).toEqual({ kind: "error", reason: "expired" });
  });

  it("refuses consume after navigation to another origin", async () => {
    await handleContentMessage({ type: "find" }, sender(LOGIN), h.deps);
    const c = await handleContentMessage({ type: "consume" }, sender("https://evil.example.net/"), h.deps);
    expect(c).toEqual({ kind: "error", reason: "expired" });
    expect(h.sent.filter((s) => s["op"] === "consume_suggestion")).toHaveLength(0);
  });

  it("expires handles", async () => {
    await handleContentMessage({ type: "find" }, sender(LOGIN), h.deps);
    h.tick(SUGGESTION_TTL_MS + 1);
    expect(await handleContentMessage({ type: "consume" }, sender(LOGIN), h.deps)).toEqual({
      kind: "error",
      reason: "expired",
    });
  });

  it("other origins get nothing", async () => {
    expect(await handleContentMessage({ type: "find" }, sender("https://example.com/"), h.deps)).toEqual({
      kind: "none",
    });
  });
});

describe("sender checks", () => {
  it.each([
    ["sub-frame", sender(LOGIN, { frameId: 3 })],
    ["other extension", sender(LOGIN, { id: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" })],
    ["no tab (extension page)", { id: SELF, frameId: 0 }],
    ["plain http", sender("http://login.example.com/")],
    ["localhost without dev", sender("http://localhost:8080/")],
    ["frame origin disagrees with tab", sender(LOGIN, { origin: "https://evil.example.net" })],
    ["file url", sender("file:///etc/passwd")],
  ])("ignores %s", async (_name, s) => {
    expect(await handleContentMessage({ type: "find" }, s, h.deps)).toBeNull();
    expect(h.sent).toHaveLength(0);
  });

  it.each([
    [{ type: "find", top_origin: "https://login.example.com" }],
    [{ type: "list" }],
    ["find"],
    [null],
  ])("ignores malformed message %j", async (m) => {
    expect(await handleContentMessage(m, sender(LOGIN), h.deps)).toBeNull();
  });

  it("accepts localhost in dev builds", async () => {
    h.deps.allowLocalhost = true;
    expect(await handleContentMessage({ type: "find" }, sender("http://localhost:8443/"), h.deps)).toEqual({
      kind: "none",
    });
    expect(h.sent).toHaveLength(1);
  });
});

describe("settings and failures", () => {
  it("pause and per-site deny skip the daemon", async () => {
    await h.deps.local.set(SETTINGS_KEY, { paused: true, denied: [] });
    expect(await handleContentMessage({ type: "find" }, sender(LOGIN), h.deps)).toEqual({ kind: "none" });
    await h.deps.local.set(SETTINGS_KEY, { paused: false, denied: ["https://login.example.com"] });
    expect(await handleContentMessage({ type: "find" }, sender(LOGIN), h.deps)).toEqual({ kind: "none" });
    expect(h.sent).toHaveLength(0);
  });

  it("missing host and malformed responses are 'unavailable'", async () => {
    h.deps.native = async () => {
      throw new Error("Specified native messaging host not found.");
    };
    expect(await handleContentMessage({ type: "find" }, sender(LOGIN), h.deps)).toEqual({
      kind: "error",
      reason: "unavailable",
    });
    h.deps.native = async (m) => ({ v: 1, request_id: "wrong", status: "none", m });
    expect(await handleContentMessage({ type: "find" }, sender(LOGIN), h.deps)).toEqual({
      kind: "error",
      reason: "unavailable",
    });
  });
});
