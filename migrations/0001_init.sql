CREATE TABLE IF NOT EXISTS snapshots (
    id        BIGSERIAL PRIMARY KEY,
    taken_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    repo      TEXT NOT NULL,
    stats     JSONB NOT NULL
);
CREATE INDEX IF NOT EXISTS snapshots_repo_time ON snapshots (repo, taken_at DESC);

CREATE TABLE IF NOT EXISTS recommendations (
    id          BIGSERIAL PRIMARY KEY,
    repo        TEXT NOT NULL,
    kind        TEXT NOT NULL,
    reason      TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'open', -- open | dismissed | done
    first_seen  TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen   TIMESTAMPTZ NOT NULL DEFAULT now(),
    notified_at TIMESTAMPTZ,
    UNIQUE (repo, kind)
);

-- Dedupe for threshold alerts (e.g. one "50% used" mail per month).
CREATE TABLE IF NOT EXISTS alerts (
    key      TEXT PRIMARY KEY,
    fired_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    detail   JSONB
);

-- Single-use, expiring button tokens. Only the SHA-256 of the token is stored.
CREATE TABLE IF NOT EXISTS action_tokens (
    token_hash TEXT PRIMARY KEY,
    rec_id     BIGINT NOT NULL REFERENCES recommendations(id) ON DELETE CASCADE,
    action     TEXT NOT NULL, -- archive | disable_actions | dismiss
    repo       TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at    TIMESTAMPTZ,
    used_by    TEXT
);

CREATE TABLE IF NOT EXISTS action_log (
    id        BIGSERIAL PRIMARY KEY,
    at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor     TEXT NOT NULL,
    action    TEXT NOT NULL,
    repo      TEXT NOT NULL,
    ok        BOOLEAN,
    detail    TEXT
);
