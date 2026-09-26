# gh-audit

Rust workspace for watching a GitHub account.

| crate | what |
| --- | --- |
| `gh-core` | GitHub client (App or PAT auth), repo stats, threshold-based recommendations |
| `knock-knock` | the service: `daily`, `usage`, `serve`, `report` |

## Commands

```
knock-knock report        # print recommendations, no DB/mail needed (GH_OWNER + GITHUB_TOKEN)
knock-knock daily [--force]  # scan, snapshot to Postgres, email new recommendations
knock-knock usage         # email when monthly Actions minutes cross USAGE_ALERT_PCTS
knock-knock serve         # email-button web UI + NATS JetStream action worker
```

## Recommendations

`archive`, `review_archive` (dormant but has stars/forks/open PRs), `disable_actions`,
`heavy_ci`, `private_cost`, `bot_churn`. All thresholds are env vars (see `.env.example`).
Each recommendation is emailed once, then again after `RENOTIFY_DAYS` while it stays open.
Recommendations that stop tripping a threshold are closed automatically.

## Email buttons

Archive / Disable CI / Dismiss buttons are single-use, expire after `ACTION_TTL_HOURS`, and the
click needs GitHub sign-in (GitHub App user auth) as `GH_OWNER`. Confirmed clicks are published to
NATS JetStream (`knock.actions.requested`, stream `KNOCK`) and executed by a durable consumer; results
go to `knock.actions.result`. Without `NATS_URL` the action runs inline. Every action is in `action_log`.
The App needs **Administration: read & write** (archive, disable Actions), **Actions: read**,
**Metadata: read**. Set the App's callback URL to `$BASE_URL/callback`.

## Billing note

GitHub Apps cannot call the billing API. For real Actions-minutes numbers provide a classic PAT with
the `user` scope as `GITHUB_TOKEN`; otherwise the usage job estimates from private-repo run history.

## Run

```
cp .env.example .env   # fill in
docker compose up -d
docker compose run --rm knock-knock daily --force
```
