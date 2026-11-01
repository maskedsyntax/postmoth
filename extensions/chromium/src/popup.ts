// Toolbar popup: daemon health, pause toggle, per-site opt-out.

import { type Deps, type KV, SETTINGS_KEY, type Settings, daemonStatus, getSettings, originAllowed } from "./core";
import { HOST_NAME } from "./protocol";

declare const __DEV__: boolean;

const local: KV = {
  async get(key) {
    return (await chrome.storage.local.get(key))[key];
  },
  async set(key, value) {
    await chrome.storage.local.set({ [key]: value });
  },
  async remove(key) {
    await chrome.storage.local.remove(key);
  },
};

const deps: Deps = {
  native: (m) => chrome.runtime.sendNativeMessage(HOST_NAME, m),
  session: local, // unused by daemonStatus
  local,
  now: () => Date.now(),
  newRequestId: () => crypto.randomUUID(),
  selfId: chrome.runtime.id,
  allowLocalhost: __DEV__,
};

function $(id: string): HTMLElement {
  const el = document.getElementById(id);
  if (!el) throw new Error(`missing #${id}`);
  return el;
}

async function save(s: Settings): Promise<void> {
  await local.set(SETTINGS_KEY, s);
}

async function currentOrigin(): Promise<string | null> {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.url) return null;
  try {
    const u = new URL(tab.url);
    return originAllowed(u, __DEV__) ? u.origin : null;
  } catch {
    return null;
  }
}

async function render(): Promise<void> {
  const settings = await getSettings(local);
  const pause = $("pause") as HTMLInputElement;
  pause.checked = settings.paused;

  const origin = await currentOrigin();
  const site = $("site");
  const toggle = $("site-toggle") as HTMLButtonElement;
  if (origin) {
    site.textContent = origin;
    const denied = settings.denied.includes(origin);
    toggle.hidden = false;
    toggle.textContent = denied ? "Allow suggestions here" : "Never suggest on this site";
    toggle.onclick = async () => {
      const s = await getSettings(local);
      s.denied = denied ? s.denied.filter((d) => d !== origin) : [...s.denied, origin];
      await save(s);
      await render();
    };
  } else {
    site.textContent = "Not available on this page";
    toggle.hidden = true;
  }

  const list = $("denied");
  list.replaceChildren();
  for (const d of settings.denied) {
    const li = document.createElement("li");
    const span = document.createElement("span");
    span.textContent = d;
    const rm = document.createElement("button");
    rm.type = "button";
    rm.textContent = "Remove";
    rm.setAttribute("aria-label", `Allow suggestions on ${d}`);
    rm.onclick = async () => {
      const s = await getSettings(local);
      s.denied = s.denied.filter((x) => x !== d);
      await save(s);
      await render();
    };
    li.append(span, rm);
    list.append(li);
  }
  $("denied-section").hidden = settings.denied.length === 0;
}

async function renderStatus(): Promise<void> {
  const el = $("status");
  const st = await daemonStatus(deps);
  if (!st.reachable) {
    el.textContent = "Postmoth is not running or not installed.";
    el.dataset["state"] = "down";
  } else if (st.paused) {
    el.textContent = `Postmoth ${st.version}: background mail is paused.`;
    el.dataset["state"] = "paused";
  } else {
    el.textContent = `Connected to Postmoth ${st.version}.`;
    el.dataset["state"] = "ok";
  }
}

($("pause") as HTMLInputElement).addEventListener("change", async (ev) => {
  const s = await getSettings(local);
  s.paused = (ev.target as HTMLInputElement).checked;
  await save(s);
});

void render();
void renderStatus();
