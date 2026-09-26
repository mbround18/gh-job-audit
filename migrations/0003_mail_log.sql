-- Mailer bookkeeping: one row per delivered message that carried a dedupe key.
CREATE TABLE IF NOT EXISTS mail_log (
    dedupe_key TEXT PRIMARY KEY,
    subject    TEXT NOT NULL,
    sent_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
