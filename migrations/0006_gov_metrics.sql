-- Point-in-time numbers from the governance jobs, for week-over-week trends and the rollup email.
CREATE TABLE IF NOT EXISTS gov_metrics (
    id    BIGSERIAL PRIMARY KEY,
    at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    job   TEXT NOT NULL,
    key   TEXT NOT NULL,
    value DOUBLE PRECISION NOT NULL
);
CREATE INDEX IF NOT EXISTS gov_metrics_lookup ON gov_metrics (job, key, at DESC);
