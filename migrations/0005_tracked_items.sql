-- Durable per-issue/PR state shared by triage (discovery -> plan -> assign) and the stale digest.
CREATE TABLE IF NOT EXISTS tracked_items (
    repo              TEXT NOT NULL,
    number            BIGINT NOT NULL,
    kind              TEXT NOT NULL,                 -- 'issue' | 'pr'
    title             TEXT NOT NULL DEFAULT '',
    url               TEXT NOT NULL DEFAULT '',
    author            TEXT NOT NULL DEFAULT '',
    author_is_bot     BOOLEAN NOT NULL DEFAULT false,
    first_seen_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- triage
    unassigned        BOOLEAN NOT NULL DEFAULT false,
    plan_state        TEXT NOT NULL DEFAULT 'new',   -- new | planned | unassignable
    planned_assignees TEXT,
    plan_source       TEXT,
    planned_at        TIMESTAMPTZ,
    last_attempt_at   TIMESTAMPTZ,
    -- stale digest
    stale             BOOLEAN NOT NULL DEFAULT false,
    last_activity_at  TIMESTAMPTZ,
    first_flagged_at  TIMESTAMPTZ,
    last_emailed_at   TIMESTAMPTZ,
    snoozed_until     TIMESTAMPTZ,
    PRIMARY KEY (repo, number)
);
CREATE INDEX IF NOT EXISTS tracked_items_unassigned ON tracked_items (unassigned, plan_state);
CREATE INDEX IF NOT EXISTS tracked_items_stale ON tracked_items (stale, last_activity_at);
