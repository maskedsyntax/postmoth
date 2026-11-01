import { beforeEach, describe, expect, it } from "vitest";
import { findOtpTarget } from "../src/detect";

const opts = { requireVisible: false };

function setup(html: string): void {
  document.body.innerHTML = html;
}

function at(selector: string) {
  return findOtpTarget(document.querySelector(selector), opts);
}

beforeEach(() => setup(""));

describe("single fields", () => {
  it.each([
    ['<input id="t" autocomplete="one-time-code">', "autocomplete wins"],
    ['<input id="t" name="otp" inputmode="numeric">', "name + numeric"],
    ['<label for="t">Verification code</label><input id="t" maxlength="6">', "label + length"],
    ['<input id="t" placeholder="Enter the 6-digit code" type="tel">', "placeholder + tel"],
    ['<input id="t" name="verificationCode" pattern="[0-9]*">', "camelCase + pattern"],
    ['<span id="h">Código de verificación</span><input id="t" aria-labelledby="h" inputmode="numeric">', "spanish aria"],
    ['<input id="t" aria-label="2FA token" maxlength="8">', "2fa"],
  ])("detects %s (%s)", (html) => {
    setup(html);
    expect(at("#t")?.kind).toBe("single");
  });

  it.each([
    ['<input id="t" type="password" autocomplete="one-time-code">', "password excluded"],
    ['<input id="t" name="code">', "hint without corroboration"],
    ['<input id="t" name="zip_code" inputmode="numeric" maxlength="5">', "zip code"],
    ['<input id="t" name="promo-code" maxlength="8">', "promo code"],
    ['<label for="t">Card security code (CVV)</label><input id="t" maxlength="4" inputmode="numeric">', "cvv"],
    ['<input id="t" name="phone_verification" type="tel">', "phone"],
    ['<input id="t" name="recovery_code" maxlength="8">', "recovery codes are user-held"],
    ['<input id="t" name="email" type="email" autocomplete="one-time-code">', "email type"],
    ['<input id="t" name="otp" inputmode="numeric" disabled>', "disabled"],
    ['<input id="t" name="otp" inputmode="numeric" readonly>', "readonly"],
    ['<input id="t" name="search" maxlength="6">', "unrelated"],
  ])("ignores %s (%s)", (html) => {
    setup(html);
    expect(at("#t")).toBeNull();
  });

  it("ignores textareas and non-inputs", () => {
    setup('<textarea id="t" name="otp"></textarea><div id="d"></div>');
    expect(at("#t")).toBeNull();
    expect(at("#d")).toBeNull();
    expect(findOtpTarget(null)).toBeNull();
  });
});

describe("split fields", () => {
  const boxes = (n: number, attrs = 'inputmode="numeric"') =>
    Array.from({ length: n }, (_, i) => `<input id="b${i}" maxlength="1" ${attrs}>`).join("");

  it("groups six numeric single-char inputs", () => {
    setup(`<form><div class="g">${boxes(6)}</div></form>`);
    const t = at("#b2");
    expect(t?.kind).toBe("split");
    expect(t?.kind === "split" && t.inputs.length).toBe(6);
  });

  it("uses surrounding text when inputs are plain", () => {
    setup(`<form><p>Enter the verification code we sent you</p><div>${boxes(6, "")}</div></form>`);
    expect(at("#b0")?.kind).toBe("split");
  });

  it("rejects plain boxes without context, and too few or too many", () => {
    setup(`<form><p>Your initials</p><div>${boxes(4, "")}</div></form>`);
    expect(at("#b0")).toBeNull();
    setup(`<div>${boxes(3)}</div>`);
    expect(at("#b0")).toBeNull();
    setup(`<div>${boxes(12)}</div>`);
    expect(at("#b0")).toBeNull();
  });
});
