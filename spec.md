# Postmoth — Product & Engineering Specification

**Status:** Proposed / implementation blueprint  
**Version:** 0.1  
**Last updated:** 2026-10-31  
**Target:** Linux desktop, starting with Ubuntu GNOME  
**License recommendation:** GPL-3.0-or-later for the app, with separately licensed reusable libraries if desired  
**Working name:** Postmoth (trademark, repositories, and domains not yet cleared)

## 1. Executive summary

Postmoth is a **native, local-first Linux email client** designed to feel like a first-class part of the operating system. Its signature feature is **secure, user-mediated one-time-code suggestions**: when a verification email arrives, Postmoth recognizes a likely code locally and, where appropriate, offers it in the browser via a companion extension and native messaging host.

Postmoth is **not** a webmail wrapper, Electron application, AI-first mailbox, or hosted email service. Account data stays on the user's machine. Backend/server infrastructure is not needed for the core product.

The architectural centerpiece is a **headless mail and integration daemon**, which keeps syncing and detecting codes even when the application window is closed. A lightweight GTK4/libadwaita application provides the native desktop UI. A Chromium-family browser extension communicates with a narrowly scoped native messaging host; the host delegates requests to the daemon through authenticated local IPC.

### Product promise

> Your mail, at home on Linux.

- A polished, keyboard-friendly, native Linux mail experience.
- Responsive mailbox search, offline access, attachments, threading, and multiple accounts.
- Desktop notifications and mail actions without an open window.
- Browser OTP suggestions that minimize code exposure and require explicit interaction.
- No mandatory account with Postmoth, no analytics by default, and no email upload to Postmoth servers.

## 2. Goals, non-goals, and principles

### 2.1 Goals

1. Deliver a reliable everyday mail client with readable conversations, composition, and local offline storage.
2. Provide Gmail and standards-based IMAP/SMTP account connections using modern authentication where supported.
3. Surface incoming OTPs from verified, high-confidence email patterns in a safe, minimally intrusive browser UI.
4. Integrate with Linux desktop facilities: notifications, secret storage, default mail handler, file chooser, MIME/open-with, and background startup.
5. Keep all content processing local. Make data flows inspectable and features independently switchable.
6. Support GNOME first, then KDE Plasma and standalone X11/Wayland environments without rewriting core logic.
7. Build clean separations between network protocols, storage, code detection, desktop UI, and browser transport.

### 2.2 Non-goals for v1

- Reproducing macOS's system-wide AutoFill inside arbitrary native applications.
- Sending or receiving cellular SMS directly; optional KDE Connect integration can come later.
- Hosted email accounts, proprietary Postmoth mail servers, or mobile apps.
- End-to-end encrypted mail as a newly invented protocol (OpenPGP/S/MIME support is a later feature).
- Unified calendar, contacts sync, or a full productivity suite.
- Automatic OTP submission, blind autofill, automatic focus hijacking, or bypassing MFA.
- Universal, zero-permission integration into every browser.
- Plugins executing arbitrary mail content or scripts.

### 2.3 Principles

- **Local-first:** the mail cache, search index, preferences, and OTP extraction remain on device.
- **Least privilege:** OAuth scopes, browser extension permissions, IPC methods, and secrets are restricted to necessary functionality.
- **Opt-in integration:** code suggestions and message previews can be disabled per account or globally.
- **Predictability:** never guess silently, never send codes automatically, and always make failure explicit.
- **Portable core:** UI toolkit details do not leak into mail synchronization or parsing.
- **Accessible and fast:** keyboard navigation, screen-reader semantics, reduced motion, responsive updates.

## 3. Personas and primary user journeys

### Personas

- **Linux-first developer:** uses Chromium or Brave, multiple email accounts, keyboard-driven workflow, and wants frictionless login OTPs.
- **Everyday desktop user:** expects reliable inbox notifications, attachments, quick replies, and familiar folders.
- **Privacy-conscious user:** dislikes remote processing and wants clear on-device storage and deletion controls.

### Journey A — OTP suggestion

1. A user initiates a login on `accounts.example.com`.
2. A verification email arrives in an already connected account.
3. The sync daemon notices the new message and parses its sender, subject, headers, and safe text body.
4. OTP detection extracts a candidate code and computes confidence; the candidate is held temporarily in volatile memory.
5. The browser extension detects a likely OTP field and communicates the **current top-level HTTPS origin** to the local native messaging host.
6. The daemon compares the requesting origin to validated, configured service-domain associations. Unknown/mismatched origins receive no code.
7. For a safe match, the extension renders a small suggestion; the user explicitly clicks or uses a keyboard action to insert it.
8. The code expires, is invalidated on user action or relevant account logout, and is never submitted automatically.

**Important:** a verification email saying “code for Example” is not enough to trust the `example.com` association. Domain mappings must be user-confirmed or supplied by vetted local rules; email content and display names are untrusted.

### Journey B — Mail while the window is closed

1. The user closes the Postmoth UI window.
2. A user-level systemd service continues mail sync where permitted/configured.
3. New-mail desktop notifications appear according to per-account settings.
4. Clicking a notification opens the conversation in Postmoth.

### Journey C — Offline access

1. Postmoth has synchronized a configured subset of message bodies and metadata.
2. The user goes offline and can still read cached mail, search local indexed content, draft messages, and queue outgoing messages.
3. On reconnect, the daemon retries queued sends with idempotence/duplicate-send safeguards and reconciles server changes.

## 4. Scope and priorities

| Priority | Capability | Milestone |
|---|---|---|
| P0 | Account setup (IMAP/SMTP), credential management | Alpha |
| P0 | Inbox, sent, drafts, archive/trash, search, message reader | Alpha |
| P0 | Local SQLite cache, safe MIME parser, background sync | Alpha |
| P0 | Reliable compose/send/reply/forward, attachments | Alpha |
| P0 | OTP detector, volatile code cache, strict matching | Prototype |
| P0 | Chromium extension + native messaging bridge | Prototype |
| P0 | Security/privacy controls, redaction, expiry | Prototype |
| P1 | Gmail OAuth/XOAUTH2, account switching, threading | Beta |
| P1 | Linux desktop notifications and deep links | Beta |
| P1 | Fast local full-text search, keyboard shortcuts | Beta |
| P1 | Packaging and upgrades on Ubuntu GNOME | Beta |
| P2 | KDE Plasma polish, generic X11/Wayland compatibility | v1.x |
| P2 | Rules/filters, signatures, snooze, unified inbox | v1.x |
| P2 | Firefox companion extension | v1.x |
| P3 | KDE Connect SMS OTP adapter | Future |
| P3 | OpenPGP/S/MIME, calendar/contacts, conversation intelligence | Future |

**Delivery strategy:** validate end-to-end OTP utility **before** investing in a fully featured mail UI. The prototype may use one test mailbox and a minimal diagnostic interface; the public release still needs dependable mail basics.

## 5. Proposed stack and dependencies

| Layer | Recommendation | Rationale / note |
|---|---|---|
| Language | Stable Rust | Memory safety, reusable headless services |
| UI | GTK4 + libadwaita via `gtk4-rs` | GNOME-native appearance, accessibility |
| Async runtime | Tokio | Async network and daemon tasks |
| Mail transport | Maintained Rust IMAP client + SMTP client, selected after spike | Verify IDLE, TLS, OAuth, and maintenance |
| MIME / email parsing | Maintained Rust MIME/message parser | Robust multipart, charsets, attachments |
| Local database | SQLite with SQLx or rusqlite | Transactional cache and migrations |
| Search | SQLite FTS5 initially | No external search service |
| Credentials | Secret Service API (GNOME Keyring / KWallet-compatible provider) | Tokens/passwords out of SQLite |
| Local IPC | Session D-Bus for UI/service; restricted local socket or D-Bus for host | Typed commands, Linux integration |
| Background start | `systemd --user` service with appropriate activation | UI-independent sync |
| Browser extension | TypeScript, Manifest V3 (Chromium) | Browser UI and OTP field detection |
| Extension transport | Chromium Native Messaging | No localhost HTTP server required |
| Packaging | `.deb` initially; Flatpak feasibility spike; optional AppImage later | Desktop integration differs by sandbox |
| CI | GitHub Actions or equivalent | Tests, formatting, builds, artifacts |

**Dependency gate:** before locking crates, audit current maintenance, release cadence, license, security history, feature coverage, and minimum Rust version. Avoid treating sample crate names as commitments until tested.

## 6. Architecture

```text
        IMAP / SMTP / OAuth providers
                    │ TLS
                    ▼
          ┌────────────────────┐
          │ postmoth-daemon    │
          │ - account manager  │
          │ - sync scheduler   │
          │ - MIME parser      │
          │ - OTP detector     │
          │ - message queue    │
          └──────────┬─────────┘
                     │
      ┌──────────────┼─────────────────┐
      ▼              ▼                 ▼
 SQLite / FTS5  Secret Service     Session D-Bus
 (mail cache)    (tokens)          / notifications
                                       │
                        ┌──────────────┴─────────────┐
                        ▼                            ▼
                Postmoth GTK UI              Native host executable
                                                    ▲
                                           Native Messaging JSON
                                                    ▲
                                          Browser extension
                                                    ▲
                                           OTP input on HTTPS page
```

### 6.1 Process boundaries

- `postmoth-daemon`: owns account state, sync, database writes, secret access, code candidate lifecycle, notification orchestration.
- `postmoth`: GTK desktop app, talks to daemon through session IPC; it does not directly fetch mail or manage OAuth refresh tokens.
- `postmoth-native-host`: tiny process launched by Chromium's native messaging subsystem, communicates over length-prefixed JSON stdin/stdout; validates caller origin and forwards only approved requests.
- `postmoth-browser`: extension service worker, content scripts, and minimal suggestion UI; cannot read arbitrary mail.
- Optional `postmothctl`: local diagnostics/CLI, never expose raw codes in default output.

### 6.2 Inter-process boundary rules

- A caller cannot enumerate message bodies, tokens, or an OTP feed by invoking the browser-facing host.
- Browser APIs are separated from broader GTK UI APIs: an extension gets only `status`, `find_suggestion`, and `consume_suggestion` operations.
- Do **not** trust the origin string supplied by an arbitrary caller alone. Browser extension service worker should derive the top-level tab URL from browser APIs, verify tab/frame IDs, and pass it to the host; host permits only a pinned extension ID. Still consider a malicious/compromised extension in the threat model.
- Restrict user-session socket filesystem permissions to the owner (`0600`) if used. Avoid open TCP ports and world-readable logs.
- IPC errors use stable machine-readable error codes; service version is negotiated.

## 7. Mail engine

### 7.1 Providers and onboarding

- **Generic IMAP/SMTP:** configured hostnames, ports, TLS mode, login. Prefer OAuth where available, otherwise provider-supported app passwords. Refuse cleartext password transfer.
- **Gmail:** implement installed-app OAuth with PKCE where applicable and Gmail IMAP/SMTP SASL XOAUTH2, subject to Google's policies. Gmail's IMAP/SMTP access uses the `https://mail.google.com/` scope, which requires careful verification planning for a public app.
- **Microsoft 365 / Outlook:** separate provider adapter and OAuth registration; confirm supported scopes and SMTP authorization behavior during implementation.
- Auto-discovery is advisory; show endpoints and security parameters for confirmation if discovery fails.
- Show provider limitations and authentication errors clearly.

### 7.2 Synchronization behavior

- On initial sync: fetch mailbox metadata and headers in pages, then selected bodies based on download policy.
- Incrementally sync using IMAP UIDs and UIDVALIDITY; use CONDSTORE/QRESYNC when server supports them, otherwise reconcile changes.
- Prefer IMAP IDLE for active folders; have bounded periodic polling fallback with configurable interval and exponential backoff.
- Detect UIDVALIDITY changes and rebuild affected folder mappings without losing local drafts.
- Respect provider quotas and throttling; avoid aggressive reconnection loops.
- Maintain clear server-state vs pending-local-action fields; support retriable move, mark read/unread, star, delete, and archive.
- Account for Gmail labels vs IMAP folders (don't assume a one-to-one mapping).
- Store safe normalized HTML for rendering, plain text fallback, and attachment metadata; preserve raw MIME only as needed by retention policy.

### 7.3 Sending and drafts

- Support compose, reply, reply-all, forward, signatures, attachments, and draft autosave.
- Send via SMTP over TLS with recipient validation and a visible sending state.
- Outbox entries have durable state (`draft`, `queued`, `sending`, `sent`, `uncertain`, `failed`) and stable local IDs.
- On ambiguous SMTP completion, **never blindly retry** and risk duplicate mail; surface `uncertain` state and allow manual reconciliation.
- Sent-mail upload/filing uses provider-appropriate behavior to prevent duplicate Sent copies.

### 7.4 Email security

- Sanitize all HTML. Block remote images and tracking resources by default; expose explicit per-message and per-sender overrides.
- Disallow script execution, forms, embedded active content, and arbitrary remote navigation in the message viewer.
- Treat attachments as untrusted files; show type/size, require explicit opening, and avoid executable auto-launch.
- Show authenticated sender information without implying display names prove sender identity.
- Support proper Unicode, MIME charset decoding, and RFC-compliant address parsing.

## 8. OTP detection and browser suggestion system

### 8.1 Candidate schema (in volatile memory)

```rust
struct OtpCandidate {
    id: Uuid,
    account_id: AccountId,
    source_message_id: MessageId,
    sender_address: String,
    service_domain: Option<String>, // only from verified mapping/rules
    code: SecretString,
    created_at: SystemTime,
    expires_at: SystemTime,
    confidence: Confidence,
    consumed: bool,
}
```

**Never log or persist `code` in plaintext.** Prefer no OTP database table at all. If crash restoration is eventually desired, require a separate security review.

### 8.2 Detection stages

1. Only inspect newly received inbound messages that are eligible under per-account privacy settings.
2. Decode safe text parts; cap processing size and parsing time to prevent resource exhaustion.
3. Use contextual patterns (`verification code`, `sign-in code`, `one-time password`, etc.) together with a bounded code matcher (e.g., 4–8 alphanumeric characters; exact rules driven by a test corpus).
4. Penalize ambiguous content such as multiple plausible codes, order numbers, dates, phone numbers, and quoted previous emails.
5. Extract message timestamp and source ID; ignore stale mail and obvious newsletter/forward contexts.
6. Calculate confidence and default to **no suggestion** on ambiguity.
7. Bind the candidate to a service domain **only** through a vetted mapping or explicit user-confirmed association. DNS and display-name resemblance are insufficient.
8. Keep candidate for a short TTL (initial default: 5 minutes, configurable within a strict limit). Clear on expiry, account removal, explicit dismiss/consumption, or service shutdown.

### 8.3 Domain association policy

- Maintain a small reviewed local rule catalog mapping specific verified email sender patterns to explicit login origins.
- Support a user-approved association flow (`Allow codes from sender@example.net on https://login.example.com?`). Show clear sender and website details; never auto-trust based on the email text.
- Match normalized full origin/registrable domain carefully, accounting for subdomains and public suffixes. Never allow wildcards like `*.com` or substring matches (`example.com.evil.net`).
- Only inject on HTTPS pages (an explicit localhost-development exception can be opt-in).
- Embedded third-party frames, cross-origin iframes, browser internal pages, and password-manager-sensitive contexts should fail closed in MVP.
- No candidate data goes to a page until deliberate user selection; extension UI must isolate itself appropriately.

### 8.4 Browser extension detection

- Prioritize `autocomplete="one-time-code"`, then corroborated indicators such as input labels, accessible names, and short-code field patterns.
- Handle single-field codes and grouped digit inputs without intercepting passwords or arbitrary textareas.
- Wait for an actively focused, visible eligible field and a user gesture before requesting or revealing a suggestion.
- Service worker retrieves **tab's actual top-level URL** using permitted browser APIs; content script cannot supply the privileged origin unilaterally.
- The extension requests only a matched candidate for the active origin. It must not receive a list of all recent OTPs.
- Render a small, accessible in-page dropdown or toolbar affordance. Clicking fills fields and emits appropriate input/change events. Never submit the form.
- No clipboard copying by default. Provide explicit "Copy code" only if desired, acknowledging clipboard exposure.
- Support user pause, per-site denial, and easy extension uninstall.

### 8.5 Native Messaging details

- Define a native host manifest for the exact installed extension ID(s) using `allowed_origins`; never use wildcard origins.
- Chrome/Chromium communicate with hosts using **length-prefixed UTF-8 JSON** over stdin/stdout. Host stdout must contain protocol messages only; diagnostics belong on stderr with secret redaction.
- Installer must place manifests into appropriate browser-specific directories; Chrome, Chromium, and Brave locations/behavior must be tested independently.
- Suggested request protocol:

```json
{"v":1,"request_id":"...","op":"find_suggestion","top_origin":"https://login.example.com","tab_id":123}
```

- Suggested response, only after trust checks:

```json
{"v":1,"request_id":"...","status":"available","suggestion_id":"opaque-id","label":"Code from Postmoth"}
```

- Avoid returning the code in the initial availability response. For `consume_suggestion`, require user-triggered extension request, live tab/origin re-validation, single-use opaque ID, and a short lifetime. The code necessarily reaches the trusted extension to insert into the page, so treat extension compromise as an explicit risk.
- Browser transport is **not** a universal OS autofill API; it only works in supported browsers with the extension installed and enabled.

### 8.6 Abuse cases and mitigations

| Threat | Required control |
|---|---|
| Phishing login page requests code for another service | Verified domain matching; fail closed on unknown mappings |
| Spoofed sender/display name | Treat headers as untrusted; account for SPF/DKIM/DMARC where provider supplies reliable authentication results; user confirmation for mappings |
| Malicious email containing fabricated code | Context + confidence gating, verified domain mapping, short TTL |
| Compromised website scripts | No code exposure until user confirmation; recognize that page can read a code **after** it is inserted |
| Compromised extension | Minimal permissions, signed distribution, pinned native host origin, limited IPC methods |
| Other local process | User-session isolation and file permissions; document local-user compromise as an out-of-scope hard boundary |
| Clipboard monitor | Do not automatically copy codes |
| Logs, crash dumps, telemetry | Redact codes/tokens/message bodies; telemetry off by default |
| OTPs from previous logins | Strict recent-message matching, expiry, active-site scope |

## 9. Local storage model

Recommended logical tables (final schema subject to migration design):

- `accounts(id, provider_type, address, display_name, created_at, sync_config, auth_secret_ref)`
- `folders(id, account_id, remote_id, role, uidvalidity, cursor, last_sync_at)`
- `messages(id, account_id, internet_message_id, thread_id, subject, sender, recipients, date, snippet, flags, body_plain, body_html_sanitized, ...)`
- `folder_messages(folder_id, message_id, remote_uid, modseq)`
- `attachments(id, message_id, filename, mime_type, size, content_hash, local_path, download_state)`
- `drafts(id, account_id, composition_json, updated_at)`
- `outbox(id, account_id, draft_id, state, attempt_count, last_error, created_at)`
- `domain_mappings(id, sender_pattern, trusted_origin, source, confirmed_at)`
- `settings(key, value_json)`
- `schema_migrations(version, applied_at)`

Security rules:

- Database files live under XDG data directories with owner-only permissions.
- Store authentication tokens/passwords in Secret Service, referenced by an opaque key; never in settings JSON or logs.
- Use WAL, transactions, indexed folder/message keys, bounded attachment cache, and migrations with rollback/recovery strategy.
- Standard SQLite is **not** encryption at rest; provide accurate UI language. Evaluate SQLCipher later only if key management and packaging meet requirements.
- Delete account cache and secret references explicitly when account removal is confirmed. Offer full data wipe / export controls.

## 10. Desktop UI/UX specification

### 10.1 Layout

- Adaptive three-pane interface on wide displays: folders/accounts, message list, selected conversation.
- Two-pane or stacked navigation for narrow windows.
- GNOME HeaderBar, native-style dialogs, keyboard shortcuts, dark/light/system theme, sensible empty/loading/offline states.
- No ads, mandatory sign-up, decorative dashboard, or intrusive assistant UI.

### 10.2 Main screens

1. **Welcome & account setup:** provider picker, OAuth login, IMAP details, sync policy, privacy settings.
2. **Mailboxes:** unified inbox, account-specific folders, unread badges, favorites.
3. **Message list:** sender, subject, preview, date, unread/star indicators, context actions, incremental loading.
4. **Conversation reader:** clear sender identity, grouped thread, sanitized body, downloadable attachments, reply actions.
5. **Composer:** To/Cc/Bcc, subject, rich/plain formatting strategy, attachments, drafts, send status.
6. **Search:** local full-text search with account/folder/date filters and visible indexing status.
7. **Preferences:** accounts, background sync, notifications, images, OTP integration, trusted site mappings, storage usage, shortcuts.
8. **Diagnostics:** sync status, recent sanitized errors, version information, exportable redacted logs.

### 10.3 Keyboard-first behavior

- `Ctrl+K`: focus global search (configurable).
- `Ctrl+N`: compose.
- `Ctrl+R`: reply when reader focused; avoid overriding web-content or text-entry expectations.
- `Ctrl+Enter`: send only with confirmation or configurable protection to prevent accidents.
- `J/K`: navigate messages when list is focused (optional preset).
- All actions have an accessible menu alternative.

### 10.4 Native integration

- Register `mailto:` handler through standard desktop entry/MIME association.
- Show notifications using freedesktop-compatible interfaces; activate deep links into message/conversation.
- Use portal APIs where needed for file selection/opening and sandbox compatibility.
- Support tray/status indicators only as optional desktop-specific enhancements, not as essential navigation.
- Respect GNOME, KDE, and standalone WM environments without assuming every panel/tray implementation exists.

## 11. Background service & Linux environments

### 11.1 Default runtime

- Use a **user-level** `systemd` unit, enabled explicitly as part of onboarding, not a privileged root service.
- Service starts after login and may use D-Bus activation or socket activation where viable.
- Closing the UI does not stop sync. A user-controlled “Pause background mail” option is mandatory.
- Suspend/resume, network transitions, offline state, token expiry, and system clock changes must be handled.
- Show background-state health in the UI.

### 11.2 Desktop compatibility

| Environment | Target | Notes |
|---|---|---|
| Ubuntu GNOME, Wayland | Primary | GTK4/libadwaita, GNOME notifications, Secret Service |
| Ubuntu GNOME, X11 | Primary | Same UI; test input and notification behavior |
| KDE Plasma, Wayland/X11 | Secondary | GTK app runs; polish theme, notifications, secret provider behavior |
| i3/bspwm/dwm or other WM | Secondary | Requires working notification daemon, secret provider, and user D-Bus session |
| Flatpak sandbox | Feasibility spike | Native host installation and background service permissions make packaging nontrivial |

**Important:** Wayland and X11 do not themselves supply a generic, privileged OTP autofill service. The supported-browser extension is the portable MVP integration route. Do not use global keyboard injection as a primary approach.

## 12. Repo and crate structure

```text
postmoth/
├── spec.md
├── README.md
├── LICENSE
├── Cargo.toml                  # Rust workspace
├── crates/
│   ├── postmoth-core/         # IDs, domain models, errors, policies
│   ├── postmoth-mail/         # IMAP/SMTP/provider adapters
│   ├── postmoth-mime/         # message parsing and sanitization
│   ├── postmoth-store/        # SQLite and FTS migrations
│   ├── postmoth-otp/          # detection, confidence, TTL, mapping
│   ├── postmoth-ipc/          # shared typed protocol
│   └── postmoth-platform/     # secret storage, notifications, XDG paths
├── apps/
│   ├── daemon/                # postmoth-daemon
│   ├── desktop/               # GTK4/libadwaita
│   ├── native-host/           # stdin/stdout JSON adapter
│   └── cli/                   # optional postmothctl
├── extensions/
│   └── chromium/              # TypeScript MV3 extension
├── packaging/
│   ├── deb/
│   ├── desktop/
│   ├── systemd/
│   └── native-messaging/
├── tests/
│   ├── fixtures/              # synthetic MIME and OTP messages
│   ├── integration/
│   └── end-to-end/
└── docs/
    ├── architecture.md
    ├── threat-model.md
    ├── oauth-providers.md
    └── release-checklist.md
```

### Interface contracts

Define versioned request/response messages in `postmoth-ipc`:

- `Accounts.List`, `Accounts.Add`, `Accounts.Remove`, `Accounts.SyncNow`
- `Mailboxes.List`, `Messages.Page`, `Messages.Read`, `Messages.UpdateFlags`
- `Search.Query`, `Drafts.Save`, `Outgoing.Send`
- `Settings.Get`, `Settings.Update`
- `Otp.MatchForOrigin` **(extension-only privilege)**, `Otp.ConsumeSuggestion` **(extension-only privilege)**
- `Events.MessageReceived`, `Events.SyncState`, `Events.NotificationRequested`

Even if using D-Bus for all operations, separate browser exposure into its own checked capability surface; never simply forward arbitrary UI methods from the host.

## 13. Performance, reliability and accessibility targets

Targets measured on a mid-range Linux laptop using seeded test mailboxes; revise using benchmarks:

| Metric | Initial target |
|---|---|
| Cold UI startup to usable cached inbox | < 2 seconds, excluding first account sync |
| UI list interaction | 60 fps target; no sync on main UI thread |
| Local search, 10k cached messages | < 250 ms p95 for common queries |
| OTP detection processing | < 100 ms p95 after text available, for normal-sized messages |
| OTP suggestion appearance | < 500 ms p95 after extension requests a valid candidate |
| Crash recovery | Preserve DB consistency and queued drafts |
| Background idle behavior | Low CPU; network utilization bounded and backoff-aware |
| Accessibility | Complete keyboard navigation, appropriate labels, reduced motion |

Network delivery times, provider rate limits, and IMAP IDLE support are outside Postmoth's control. Do not promise instant delivery.

## 14. Testing plan

### Unit

- OTP parser with multilingual synthetic fixtures, false positives, ambiguity, multiple codes, expiration, Unicode, quoted chains.
- Domain parsing and matching including public-suffix edge cases, lookalike domains, IDN/punycode, and subdomains.
- MIME decoding, malformed messages, nested multipart structure, attachment metadata.
- Queue state transitions, sync cursor behavior, and error classifications.

### Integration

- Local test IMAP/SMTP servers and protocol fixtures; simulate reconnects, UIDVALIDITY resets, server throttling, duplicate messages.
- Secret Service availability/unavailability and credential deletion.
- D-Bus authorization and unauthorized native host requests.
- Chromium native messaging protocol framing and pinning of extension IDs.
- SQLite schema migrations, WAL recovery, bulk indexing, account deletion.

### End-to-end

1. Connect a test account, receive a message, see it in inbox.
2. Close UI, receive mail, see desktop notification; click to open correct message.
3. Receive a vetted OTP email, open matched HTTPS login page, see suggestion, click to insert, verify no auto-submit.
4. Open an unrelated origin and a phishing lookalike; no code offered.
5. Install extension without native app; clear graceful error. Install native app without extension; mail works normally.
6. Lock screen/suspend/network loss/reconnect; verify no leaking code or broken sync.
7. Uninstall extension and remove account; browser access and secrets are revoked/removed appropriately.
8. Run on GNOME Wayland, GNOME X11, KDE Plasma, and one standalone X11 WM.

### Security review gates

- Threat model reviewed before first public OTP beta.
- Static dependency audit and secret-scanning in CI.
- Fuzz MIME parsing and OTP text extraction when feasible.
- No remote mail resources auto-loaded in renderer.
- Confirm no raw OTP or OAuth token appears in logs, notifications, crash reporting, or analytics.
- Browser extension permission review and phishing test suite.

## 15. Roadmap and milestones

These are **milestones and exit criteria, not calendar promises**.

### M0 — Technical feasibility

- Build Rust daemon skeleton with service management and SQLite migration.
- Receive one test IMAP email and parse it safely.
- Detect candidate OTP, hold it in memory with TTL.
- Implement native messaging request/response on Linux.
- Build a tiny Chromium extension that suggests a code on a locally controlled test site after user action.
- Pass negative-origin and phishing tests.

**Exit:** complete local end-to-end OTP proof of concept with no code leakage to unrelated origins.

### M1 — Mail-client alpha

- Multi-account basics, safe message reader, compose/send, attachments, local storage, drafts, offline behavior.
- Native GNOME UI and account onboarding.
- Mail notifications and background service.

**Exit:** daily usable on a small set of test accounts; basic crash and reconnect resilience.

### M2 — Private beta

- Gmail OAuth integration and provider-specific sync fixes.
- Search, conversation threading, keyboard navigation, accessibility checks.
- Trusted-domain mapping management and strict OTP settings.
- `.deb` packaging and browser-extension install instructions.

**Exit:** test accounts and real-user pilot pass security and reliability checklist.

### M3 — v1 public release

- Stable migrations, upgrade/uninstall behavior, diagnostics, docs, privacy policy, signed releases, bug-report workflow.
- Confirm applicable OAuth app verification and distribution approvals.
- Formal compatibility matrix (Ubuntu versions, Chromium-based browsers, GNOME sessions).

**Exit:** no unresolved high-severity security issues, reliable send/sync, and reproducible builds.

### M4 — Later iterations

- KDE-specific polish; Firefox transport; rules, filters, enhanced searching; KDE Connect bridge; possibly Flatpak.

## 16. Open decisions and risks

| Decision / risk | Current stance | Required validation |
|---|---|---|
| UI toolkit | GTK4/libadwaita | Confirm acceptable appearance on KDE and non-GNOME WMs |
| Gmail access | XOAUTH2/IMAP preferred initially | OAuth scopes, verification, user consent, distribution policy |
| Core IMAP crates | Not chosen | Maintenance and full sync semantics spike |
| Extension browser support | Chromium first | Chrome/Chromium/Brave native host installation matrix |
| OTP sender↔site mappings | Reviewed local rules + user approval | Anti-phishing usability test |
| OTP persistence | Memory-only | Verify acceptable behavior after daemon restart |
| Packaging | `.deb` first | Ensure service and native messaging registration/uninstall |
| Flatpak | Deferred | Sandboxed background daemon and native host communication |
| HTML renderer | Sanitized viewer | Security boundaries, links, remote image blocking |
| Mail-data encryption | OS storage permissions initially | SQLCipher/keyring/backup security assessment |
| Branding | Postmoth | Trademark/domain/repository check before distribution |

## 17. Definition of done (v1)

Postmoth v1 is ready when:

- A user can install it on a supported Ubuntu release, add an account, read/send/reply/forward mail, manage folders, and work with cached mail offline.
- Sync, notifications, and OTP detection continue when the UI window is closed (with background service enabled).
- A supported browser with the extension installed presents a suggestion **only for high-confidence, site-matched, recent OTPs** after user interaction.
- Unrelated sites, stale codes, malformed messages, and domain lookalikes cannot obtain a suggestion.
- No server operated by Postmoth receives email content or OTPs; credentials are stored in the system secret provider.
- Importantly, messaging is accurate: **browser-extension OTP suggestions**, not universal OS-level AutoFill.
- Test suite, threat model, accessibility audit, migration testing, and packaging checks meet the release checklist.

## 18. Immediate engineering backlog

1. Initialize Cargo workspace, CI (fmt/clippy/test), and issue templates.
2. Implement `postmoth-core` account/message types and `postmoth-ipc` schema v1.
3. Spike Rust IMAP client with TLS, UID sync, and IDLE fallback against a local test server.
4. Implement SQLite storage, migrations, and FTS5 proof-of-concept.
5. Implement secure MIME-to-text extraction and synthetic OTP test corpus.
6. Implement in-memory OTP candidate cache and strict domain mapping rules.
7. Build a minimal local IPC daemon API and extension-only authorization checks.
8. Build Chromium MV3 extension and native messaging host; prove code suggestion with explicit click.
9. Add phishing/negative-origin security tests **before** connecting real mailboxes to OTP UI.
10. Build GTK shell, message list, account setup, and background notification integration.

## 19. Primary technical references

- Chrome Native Messaging: https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging
- Gmail IMAP/SMTP OAuth XOAUTH2: https://developers.google.com/workspace/gmail/imap/xoauth2-protocol
- Gmail API scopes and verification considerations: https://developers.google.com/workspace/gmail/api/auth/scopes
- HTML `autocomplete` attributes: https://developer.mozilla.org/en-US/docs/Web/HTML/Reference/Attributes/autocomplete
- gtk-rs: https://gtk-rs.org/
- libadwaita: https://gnome.pages.gitlab.gnome.org/libadwaita/
- XDG Base Directory: https://specifications.freedesktop.org/basedir-spec/latest/
- Freedesktop Desktop Notifications: https://specifications.freedesktop.org/notification-spec/latest/
- systemd user services: https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html

---

**Guiding constraint:** Build the email client people can trust first; make the OTP experience feel magical **without** weakening the security properties of one-time codes.
