// Insert a code into the page. Never submits, never touches the clipboard.

import type { OtpTarget } from "./detect";

// The content script runs in an isolated world, so this is the pristine
// setter even if the page patched its own prototypes. Using it (instead of
// `input.value = ...`) lets framework-controlled inputs notice the change.
const valueSetter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")?.set;

function setValue(input: HTMLInputElement, value: string): void {
  if (valueSetter) valueSetter.call(input, value);
  else input.value = value;
  input.dispatchEvent(new Event("input", { bubbles: true }));
  input.dispatchEvent(new Event("change", { bubbles: true }));
}

/** Returns false (and changes nothing) if the code does not fit. */
export function fillTarget(target: OtpTarget, rawCode: string): boolean {
  const code = rawCode.replace(/[\s-]/g, "");
  if (code.length === 0) return false;
  if (target.kind === "single") {
    const { input } = target;
    if (!input.isConnected || input.disabled || input.readOnly) return false;
    if (input.maxLength > 0 && code.length > input.maxLength) return false;
    input.focus();
    setValue(input, code);
    return true;
  }
  const { inputs } = target;
  if (inputs.length !== code.length || inputs.some((i) => !i.isConnected || i.disabled)) {
    return false;
  }
  inputs.forEach((input, i) => {
    input.focus();
    setValue(input, code.charAt(i));
  });
  return true;
}
