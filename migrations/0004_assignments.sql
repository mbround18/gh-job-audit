CREATE TABLE IF NOT EXISTS assignments (
    id        BIGSERIAL PRIMARY KEY,
    at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    repo      TEXT NOT NULL,
    number    BIGINT NOT NULL,
    assignees TEXT NOT NULL,
    ok        BOOLEAN NOT NULL,
    detail    TEXT
);
