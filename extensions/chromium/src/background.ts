// MV3 service worker: wires `chrome.*` to the logic in core.ts.

import { type Deps, type KV, handleContentMessage } from "./core";
import { HOST_NAME } from "./protocol";

declare const __DEV__: boolean;

function kv(area: chrome.storage.StorageArea): KV {
  return {
    async get(key) {
      const r = await area.get(key);
      return r[key];
    },
    async set(key, value) {
      await area.set({ [key]: value });
    },
    async remove(key) {
      await area.remove(key);
    },
  };
}

export const deps: Deps = {
  native: (message) => chrome.runtime.sendNativeMessage(HOST_NAME, message),
  session: kv(chrome.storage.session),
  local: kv(chrome.storage.local),
  now: () => Date.now(),
  newRequestId: () => crypto.randomUUID(),
  selfId: chrome.runtime.id,
  allowLocalhost: __DEV__,
};

// Content scripts must not read session storage (that is where handles live).
void chrome.storage.session.setAccessLevel({ accessLevel: "TRUSTED_CONTEXTS" });

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  // Popup and other extension pages have no tab; core.ts ignores them.
  handleContentMessage(message, sender, deps).then(
    (reply) => sendResponse(reply),
    () => sendResponse(null),
  );
  return true; // async response
});
