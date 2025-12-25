# Environment variable setup (Fly.io and local)

Use secrets for sensitive values (API keys, passwords) and `[env]` for non-sensitive settings.

## Required secrets (Fly)
- `SECRET_KEY` – secure random string for sessions/CSRF.
- `SECURITY_PASSWORD_SALT` – secure random string for verification tokens.
- `RESEND_API_KEY` – your Resend key (e.g., `re_xxx`) for verification emails.
- Optional if using Postgres: `DATABASE_URL` (e.g., `postgresql://user:pass@host:port/dbname`).
- Optional SMTP fallback: `MAIL_PASSWORD` (and `MAIL_USERNAME` if needed).

Set secrets:
```
fly secrets set SECRET_KEY=<random> SECURITY_PASSWORD_SALT=<random> RESEND_API_KEY=<re_key>
# Add DATABASE_URL or SMTP secrets if you use them
```

## Non-sensitive env vars
Configure in `fly.toml` `[env]` or `.env` for local:
- `APP_BASE_URL` (e.g., `https://<app>.fly.dev`) for correct verification links.
- `RESEND_FROM` (e.g., `Case Commons <hello@yourdomain.com>`; must be verified in Resend).
- `MAIL_SERVER`, `MAIL_PORT`, `MAIL_USE_TLS`, `MAIL_USE_SSL`, `MAIL_DEFAULT_SENDER` (only if using SMTP fallback).
- `DATABASE_URL=sqlite:////data/app.db` (default for Fly volume-backed SQLite; override if using Postgres).

## Viewing env vars on Fly
```
fly ssh console -C "printenv"
```
Shows secrets and `[env]` values currently in the app.

## Local development
1) Copy `.env.example` to `.env` and fill in values (set `MAIL_DEV_LOG_ONLY=true` to log verification links).
2) Start services: `docker compose up --build`.
3) For Mailpit testing: `docker compose --profile mail up mailpit` and set `MAIL_SERVER=mailpit`, `MAIL_PORT=1025`, `MAIL_USE_TLS=false`, `MAIL_DEV_LOG_ONLY=false`, `MAIL_DEFAULT_SENDER=dev@localhost`.

## Manual steps to ensure verification emails work
1) Set `RESEND_API_KEY` and `RESEND_FROM` via `fly secrets set ...`.
2) Verify the `RESEND_FROM` domain/address in Resend.
3) Set `APP_BASE_URL` so links in release/CLI contexts resolve correctly.
4) Re-deploy: `fly deploy`.
5) Tail logs for delivery errors: `fly logs`.
