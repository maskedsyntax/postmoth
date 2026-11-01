# Postmoth for Chromium (MV3)

Suggests one-time codes from Postmoth on the site they belong to. The
extension never sees mail; it can only ask the daemon "is there a code for
this tab's origin?" and redeem a single-use handle after you click **Fill**.

## How it decides

* **Field detection** (`src/detect.ts`): `autocomplete="one-time-code"`, or a
  code-like hint (name, label, placeholder, ARIA) corroborated by a numeric
  input mode or a 4–8 character limit; also groups of 4–8 single-character
  boxes. Password fields, textareas, ZIP/promo/CVV/phone fields are ignored.
* **When it asks**: only on a trusted focus or click with transient user
  activation, only in the top frame (`all_frames: false`).
* **Origin**: taken by the service worker from `sender.tab.url` (and checked
  against `sender.origin`); content scripts cannot supply one. HTTPS only
  (dev builds also allow `localhost`).
* **Handles**: kept in `chrome.storage.session` (not readable by content
  scripts), bound to tab and origin, single use, 55 s.
* **Filling**: on a trusted click or Enter on the chip (closed shadow root).
  Sets the value and fires `input`/`change`. Never submits, never copies to
  the clipboard.

The popup has a pause switch and a per-site "never suggest here" list.

## Develop

```sh
npm ci
npm run typecheck && npm test      # vitest + jsdom
npm run build:dev                  # dist/, pinned dev ID, localhost allowed
../../scripts/dev-native-host.sh install
```

Load `dist/` via `chrome://extensions` → Developer mode → Load unpacked.
The dev build's ID is `nnbgdhodaoggiiakpcmnlkgalgkoecbk`.

## End-to-end

`npm run e2e` (or `tests/e2e/run.sh`) runs GreenMail, the daemon, the
native host and this extension in Playwright's Chromium against an HTTPS
test site on `127.0.0.1:443` (`*.postmoth.test`). Needs Docker and
`npx playwright install chromium`. Your real browser profile is not
touched.
