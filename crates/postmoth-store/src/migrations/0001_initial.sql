-- Postmoth initial schema (spec §9).
-- OTP codes are deliberately NOT stored anywhere in this database.

CREATE TABLE accounts (
    id              TEXT PRIMARY KEY NOT NULL,
    provider_type   TEXT NOT NULL,
    address         TEXT NOT NULL,
    display_name    TEXT,
    created_at      INTEGER NOT NULL,
    -- Endpoints, login name, per-account toggles. Never secrets.
    config_json     TEXT NOT NULL,
    -- Opaque Secret Service lookup key.
    auth_secret_ref TEXT NOT NULL
);

CREATE TABLE folders (
    id           TEXT PRIMARY KEY NOT NULL,
    account_id   TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    remote_id    TEXT NOT NULL,
    role         TEXT NOT NULL,
    uidvalidity  INTEGER,
    -- Sync cursor (highest UID seen, HIGHESTMODSEQ, ...), JSON.
    cursor       TEXT,
    last_sync_at INTEGER,
    UNIQUE (account_id, remote_id)
);

-- `seq` is an explicit INTEGER PRIMARY KEY so the rowid used by the FTS
-- index is stable across VACUUM.
CREATE TABLE messages (
    seq                 INTEGER PRIMARY KEY,
    id                  TEXT NOT NULL UNIQUE,
    account_id          TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    internet_message_id TEXT,
    thread_id           TEXT,
    subject             TEXT,
    sender_name         TEXT,
    sender_address      TEXT,
    recipients_json     TEXT NOT NULL DEFAULT '[]',
    date                INTEGER NOT NULL,
    received_at         INTEGER NOT NULL,
    snippet             TEXT NOT NULL DEFAULT '',
    flags               INTEGER NOT NULL DEFAULT 0,
    body_plain          TEXT,
    body_html_sanitized TEXT,
    blocked_remote      INTEGER NOT NULL DEFAULT 0,
    has_attachments     INTEGER NOT NULL DEFAULT 0,
    is_bulk             INTEGER NOT NULL DEFAULT 0,
    -- 'headers' | 'full'
    body_state          TEXT NOT NULL DEFAULT 'headers'
);
CREATE INDEX messages_account_date ON messages (account_id, date DESC, seq DESC);
CREATE INDEX messages_internet_id ON messages (account_id, internet_message_id);
CREATE INDEX messages_thread ON messages (thread_id);

CREATE TABLE folder_messages (
    folder_id  TEXT NOT NULL REFERENCES folders(id) ON DELETE CASCADE,
    message_id TEXT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    remote_uid INTEGER NOT NULL,
    modseq     INTEGER,
    PRIMARY KEY (folder_id, remote_uid)
);
CREATE INDEX folder_messages_message ON folder_messages (message_id);

-- Local changes not yet confirmed by the server (spec §7.2).
CREATE TABLE pending_actions (
    id            INTEGER PRIMARY KEY,
    account_id    TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    message_id    TEXT REFERENCES messages(id) ON DELETE CASCADE,
    kind          TEXT NOT NULL,
    payload_json  TEXT NOT NULL DEFAULT '{}',
    created_at    INTEGER NOT NULL,
    attempt_count INTEGER NOT NULL DEFAULT 0,
    last_error    TEXT
);

CREATE TABLE attachments (
    id             TEXT PRIMARY KEY NOT NULL,
    message_id     TEXT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    part_index     INTEGER NOT NULL,
    filename       TEXT NOT NULL,
    mime_type      TEXT NOT NULL,
    size           INTEGER NOT NULL,
    content_id     TEXT,
    is_inline      INTEGER NOT NULL DEFAULT 0,
    is_executable  INTEGER NOT NULL DEFAULT 0,
    content_hash   TEXT,
    local_path     TEXT,
    download_state TEXT NOT NULL DEFAULT 'remote'
);
CREATE INDEX attachments_message ON attachments (message_id);

CREATE TABLE drafts (
    id               TEXT PRIMARY KEY NOT NULL,
    account_id       TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    composition_json TEXT NOT NULL,
    updated_at       INTEGER NOT NULL
);

CREATE TABLE outbox (
    id                  TEXT PRIMARY KEY NOT NULL,
    account_id          TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    draft_id            TEXT,
    -- Fixed at queue time so an uncertain send can be reconciled.
    internet_message_id TEXT NOT NULL,
    state               TEXT NOT NULL CHECK (state IN
                        ('draft','queued','sending','sent','uncertain','failed')),
    attempt_count       INTEGER NOT NULL DEFAULT 0,
    last_error          TEXT,
    created_at          INTEGER NOT NULL,
    updated_at          INTEGER NOT NULL
);

CREATE TABLE domain_mappings (
    id                 INTEGER PRIMARY KEY,
    sender_pattern     TEXT NOT NULL,
    trusted_origin     TEXT NOT NULL,
    include_subdomains INTEGER NOT NULL DEFAULT 0,
    source             TEXT NOT NULL CHECK (source IN ('catalog','user')),
    confirmed_at       INTEGER NOT NULL,
    UNIQUE (sender_pattern, trusted_origin)
);

CREATE TABLE settings (
    key        TEXT PRIMARY KEY NOT NULL,
    value_json TEXT NOT NULL
);

-- Full-text index over cached content (external content = messages).
CREATE VIRTUAL TABLE messages_fts USING fts5(
    subject, sender, recipients, body,
    content = '',
    contentless_delete = 1,
    tokenize = 'unicode61 remove_diacritics 2'
);

CREATE TRIGGER messages_fts_ai AFTER INSERT ON messages BEGIN
    INSERT INTO messages_fts (rowid, subject, sender, recipients, body)
    VALUES (new.seq, new.subject,
            coalesce(new.sender_name, '') || ' ' || coalesce(new.sender_address, ''),
            new.recipients_json, new.body_plain);
END;

CREATE TRIGGER messages_fts_ad AFTER DELETE ON messages BEGIN
    DELETE FROM messages_fts WHERE rowid = old.seq;
END;

CREATE TRIGGER messages_fts_au AFTER UPDATE OF subject, sender_name, sender_address,
    recipients_json, body_plain ON messages BEGIN
    DELETE FROM messages_fts WHERE rowid = old.seq;
    INSERT INTO messages_fts (rowid, subject, sender, recipients, body)
    VALUES (new.seq, new.subject,
            coalesce(new.sender_name, '') || ' ' || coalesce(new.sender_address, ''),
            new.recipients_json, new.body_plain);
END;
