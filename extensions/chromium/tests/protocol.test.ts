import { describe, expect, it } from "vitest";
import { parseContentRequest, parseDaemonResponse } from "../src/protocol";

describe("parseDaemonResponse", () => {
  it("requires matching version and id", () => {
    expect(parseDaemonResponse({ v: 1, request_id: "a", status: "none" }, "a")).not.toBeNull();
    expect(parseDaemonResponse({ v: 2, request_id: "a", status: "none" }, "a")).toBeNull();
    expect(parseDaemonResponse({ v: 1, request_id: "b", status: "none" }, "a")).toBeNull();
  });

  it("validates codes and error codes", () => {
    const ok = parseDaemonResponse({ v: 1, request_id: "a", status: "code", code: "482913" }, "a");
    expect(ok).toMatchObject({ status: "code", code: "482913" });
    expect(parseDaemonResponse({ v: 1, request_id: "a", status: "code", code: "<img>" }, "a")).toBeNull();
    expect(parseDaemonResponse({ v: 1, request_id: "a", status: "error", code: "weird" }, "a")).toBeNull();
    expect(parseDaemonResponse({ v: 1, request_id: "a", status: "nope" }, "a")).toBeNull();
  });
});

describe("parseContentRequest", () => {
  it("accepts exactly the three message shapes", () => {
    expect(parseContentRequest({ type: "find" })).toEqual({ type: "find" });
    expect(parseContentRequest({ type: "consume", suggestion_id: "x" })).toBeNull();
    expect(parseContentRequest({ type: "other" })).toBeNull();
  });
});
