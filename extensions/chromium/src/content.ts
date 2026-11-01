// Content script (top frame only). Detects OTP fields, asks the service
// worker for a suggestion after a real user interaction, shows the chip,
// and fills the code only when the user accepts it.

import { Chip } from "./chip";
import { type OtpTarget, findOtpTarget } from "./detect";
import { fillTarget } from "./fill";
import type { ContentReply, ContentRequest } from "./protocol";

const CHIP_LIFETIME_MS = 50_000;

let chip: Chip | null = null;
let target: OtpTarget | null = null;
let busy = false;
let dismissedForPage = false;

function send(req: ContentRequest): Promise<ContentReply | null> {
  return chrome.runtime.sendMessage<ContentRequest, ContentReply | null>(req).catch(() => null);
}

function anchorOf(t: OtpTarget): HTMLInputElement {
  return t.kind === "single" ? t.input : (t.inputs[0] as HTMLInputElement);
}

function clearChip(): void {
  chip?.remove();
  chip = null;
  target = null;
}

async function accept(): Promise<void> {
  if (!target || busy) return;
  busy = true;
  const t = target;
  try {
    const reply = await send({ type: "consume" });
    if (reply?.kind === "code") fillTarget(t, reply.code);
  } finally {
    busy = false;
    clearChip();
  }
}

function dismiss(): void {
  dismissedForPage = true;
  clearChip();
  void send({ type: "dismiss" });
}

async function onInteraction(ev: Event): Promise<void> {
  // Real user gesture only: trusted event plus transient user activation.
  if (!ev.isTrusted || busy || dismissedForPage) return;
  if (!navigator.userActivation?.isActive) return;
  const t = findOtpTarget(ev.target);
  if (!t) return;
  if (chip?.isFor(anchorOf(t))) return;
  busy = true;
  let reply: ContentReply | null;
  try {
    reply = await send({ type: "find" });
  } finally {
    busy = false;
  }
  if (reply?.kind !== "available") return;
  clearChip();
  target = t;
  chip = new Chip(anchorOf(t), reply.label, { onAccept: () => void accept(), onDismiss: dismiss }, CHIP_LIFETIME_MS);
}

if (window.top === window) {
  document.addEventListener("focusin", (ev) => void onInteraction(ev), true);
  document.addEventListener("click", (ev) => void onInteraction(ev), true);
  // Leaving the page drops any handle.
  window.addEventListener("pagehide", () => {
    if (chip) void send({ type: "dismiss" });
    clearChip();
  });
}
