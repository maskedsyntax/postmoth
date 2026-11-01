import { describe, expect, it } from "vitest";
import { fillTarget } from "../src/fill";

describe("fillTarget", () => {
  it("fills a single input and fires input/change, never submits", () => {
    document.body.innerHTML = '<form id="f"><input id="t" maxlength="6"></form>';
    const input = document.getElementById("t") as HTMLInputElement;
    const form = document.getElementById("f") as HTMLFormElement;
    const events: string[] = [];
    input.addEventListener("input", () => events.push("input"));
    input.addEventListener("change", () => events.push("change"));
    form.addEventListener("submit", () => events.push("submit"));
    expect(fillTarget({ kind: "single", input }, "482 913")).toBe(true);
    expect(input.value).toBe("482913");
    expect(events).toEqual(["input", "change"]);
  });

  it("refuses codes that do not fit", () => {
    document.body.innerHTML = '<input id="t" maxlength="4">';
    const input = document.getElementById("t") as HTMLInputElement;
    expect(fillTarget({ kind: "single", input }, "123456")).toBe(false);
    expect(input.value).toBe("");
  });

  it("spreads a code over split inputs", () => {
    document.body.innerHTML = Array.from({ length: 6 }, () => '<input maxlength="1">').join("");
    const inputs = Array.from(document.querySelectorAll("input"));
    expect(fillTarget({ kind: "split", inputs }, "12-34-56")).toBe(true);
    expect(inputs.map((i) => i.value).join("")).toBe("123456");
    expect(fillTarget({ kind: "split", inputs }, "1234")).toBe(false);
  });

  it("does not fill detached inputs", () => {
    const input = document.createElement("input");
    expect(fillTarget({ kind: "single", input }, "1234")).toBe(false);
  });
});
