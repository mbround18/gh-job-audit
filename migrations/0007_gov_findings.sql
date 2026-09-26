-- Latest findings per governance job (replaced each run) and its one-line summary; the weekly
-- digest is composed from these instead of each job sending its own email.
CREATE TABLE IF NOT EXISTS gov_findings (
    job    TEXT NOT NULL,
    kind   TEXT NOT NULL,
    sev    SMALLINT NOT NULL,
    label  TEXT NOT NULL,
    url    TEXT NOT NULL DEFAULT '',
    detail TEXT NOT NULL DEFAULT '',
    at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS gov_findings_job ON gov_findings (job, kind);
CREATE TABLE IF NOT EXISTS gov_notes (
    job  TEXT PRIMARY KEY,
    note TEXT NOT NULL,
    at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
