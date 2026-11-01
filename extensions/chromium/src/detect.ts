// One-time-code field detection (spec §8.4).
//
// 1. `autocomplete="one-time-code"` wins.
// 2. Otherwise a hint in the field's name/id/label/placeholder/aria text
//    must be corroborated by a numeric input mode or a 4–8 length limit.
// 3. Groups of 4–8 single-character inputs ("split" fields) count when
//    corroborated the same way.
// Password fields, textareas and obviously unrelated fields are excluded.

export type OtpTarget =
  | { kind: "single"; input: HTMLInputElement }
  | { kind: "split"; inputs: HTMLInputElement[] };

export interface DetectOptions {
  /** Skip layout-based visibility checks (jsdom has no layout). */
  requireVisible?: boolean;
}

const HINT =
  /(one[\s_-]?time|\botp|otp\b|passcode|verification|verify|security[\s_-]?code|2fa|mfa|two[\s_-]?(factor|step)|auth(entication)?[\s_-]?code|sms[\s_-]?code|(log|sign)[\s_-]?in[\s_-]?code|confirmation[\s_-]?code|totp|\bcode\b|código|verificación|code de vérification|bestätigungscode|確認コード|認証コード|验证码)/i;
const NEGATIVE =
  /(zip|postal|post[\s_-]?code|promo|coupon|discount|voucher|gift|card|cvv|cvc|csc|phone|mobile|telephone|captcha|referr?al|invit|search|country|area[\s_-]?code|recovery|backup|street|address|iban|swift|sort[\s_-]?code|tracking)/i;

const ELIGIBLE_TYPES = new Set(["", "text", "tel", "number"]);

function eligibleInput(el: Element | null): el is HTMLInputElement {
  if (!(el instanceof HTMLInputElement)) return false;
  const type = (el.getAttribute("type") ?? "").toLowerCase();
  return ELIGIBLE_TYPES.has(type) && !el.disabled && !el.readOnly;
}

function visible(el: HTMLElement): boolean {
  const r = el.getBoundingClientRect();
  if (r.width < 4 || r.height < 4) return false;
  const s = getComputedStyle(el);
  return s.visibility !== "hidden" && s.display !== "none" && Number(s.opacity) > 0.1;
}

function idText(doc: Document, ids: string | null): string {
  if (!ids) return "";
  return ids
    .split(/\s+/)
    .map((id) => doc.getElementById(id)?.textContent ?? "")
    .join(" ");
}

/** All human/machine-readable hints about what this input is for. */
export function hintText(el: HTMLInputElement): string {
  const parts = [
    el.name,
    el.id,
    el.placeholder,
    el.title,
    el.getAttribute("aria-label") ?? "",
    idText(el.ownerDocument, el.getAttribute("aria-labelledby")),
    idText(el.ownerDocument, el.getAttribute("aria-describedby")),
    el.getAttribute("autocomplete") ?? "",
  ];
  for (const l of Array.from(el.labels ?? [])) parts.push(l.textContent ?? "");
  // Split camelCase so "verificationCode" reads as words.
  return parts
    .join(" ")
    .replace(/([a-z])([A-Z])/g, "$1 $2")
    .slice(0, 2000);
}

function isOneTimeCodeAutocomplete(el: HTMLInputElement): boolean {
  return (el.getAttribute("autocomplete") ?? "").toLowerCase().split(/\s+/).includes("one-time-code");
}

function numericish(el: HTMLInputElement): boolean {
  const mode = (el.getAttribute("inputmode") ?? "").toLowerCase();
  const type = (el.getAttribute("type") ?? "").toLowerCase();
  const pattern = el.getAttribute("pattern") ?? "";
  return (
    mode === "numeric" ||
    type === "tel" ||
    type === "number" ||
    /^\^?(\\d|\[0-9\])(\{\d+(,\d+)?\}|\+|\*)?\$?$/.test(pattern)
  );
}

function codeLength(el: HTMLInputElement): boolean {
  return el.maxLength >= 4 && el.maxLength <= 8;
}

function singleField(el: HTMLInputElement): boolean {
  if (isOneTimeCodeAutocomplete(el)) return true;
  const hint = hintText(el);
  if (NEGATIVE.test(hint) || !HINT.test(hint)) return false;
  return numericish(el) || codeLength(el);
}

/** Find the group of single-character inputs `el` belongs to, if any. */
function splitGroup(el: HTMLInputElement): HTMLInputElement[] | null {
  if (el.maxLength !== 1) return null;
  let container: HTMLElement | null = el.parentElement;
  for (let depth = 0; container && depth < 3; depth++, container = container.parentElement) {
    const inputs = Array.from(container.querySelectorAll("input")).filter(
      (i) => eligibleInput(i) && i.maxLength === 1,
    );
    if (inputs.length < 4) continue;
    if (inputs.length > 8 || !inputs.includes(el)) return null;
    const corroborated =
      inputs.some(isOneTimeCodeAutocomplete) ||
      inputs.every(numericish) ||
      (() => {
        const ctx =
          (container.getAttribute("aria-label") ?? "") +
          " " +
          (container.closest("form, fieldset, [role=group], section, main")?.textContent ?? "").slice(0, 600);
        return HINT.test(ctx) && !NEGATIVE.test(inputs.map(hintText).join(" "));
      })();
    return corroborated ? inputs : null;
  }
  return null;
}

/** Decide whether `node` (usually the focused element) is an OTP field. */
export function findOtpTarget(node: EventTarget | null, opts: DetectOptions = {}): OtpTarget | null {
  const requireVisible = opts.requireVisible ?? true;
  if (!(node instanceof Element) || !eligibleInput(node)) return null;
  if (requireVisible && !visible(node)) return null;
  const group = splitGroup(node);
  if (group) {
    if (requireVisible && !group.every(visible)) return null;
    return { kind: "split", inputs: group };
  }
  if (node.maxLength === 1) return null;
  return singleField(node) ? { kind: "single", input: node } : null;
}
