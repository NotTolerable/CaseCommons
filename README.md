# Case Commons

Light-theme Flask app for law student case analysis reports and discussions.

## Setup
1. Copy `.env.example` to `.env` and adjust secrets.
2. Start services: `docker-compose up --build` (exposes port 8080). The app reads `DATABASE_URL` (Fly secret/local env); if the value uses the legacy `postgres://` prefix it will be rewritten to `postgresql://` automatically. Uploads persist to `/data/uploads` by default—Docker and Fly volumes should mount this path.
3. Initialize DB migrations inside the web container:
   - `docker-compose run --rm web flask db upgrade` (also runs automatically on container start)
4. Seed data: `docker-compose run --rm web python seed.py`

## Accounts
- Admin: `admin@example.com` / `password`
- User: `user@example.com` / `password`
- Muted: `muted@example.com` / `password`
- Banned: `banned@example.com` / `password`

## Tests
Run `pytest` (requires dependencies from `requirements.txt`).

## Fly.io deployment
1. Update `fly.toml` with your Fly app name and preferred region if different.
2. Ensure a persistent volume is attached for `/data/uploads` and a Postgres database is provisioned; set `DATABASE_URL` accordingly.
3. Deploy with `fly deploy`. A release command runs `flask db upgrade` before new machines start, and the container listens on `0.0.0.0:${PORT}` (default 8080) via gunicorn.

## Troubleshooting
- Missing tables / OperationalError: check logs for "Database schema missing tables" and run `flask db upgrade` inside the container or Fly release command.
- CSRF failures redirect back with a warning and log the failing path/IP; refresh the page and resubmit.
- Quill not loading: browser console will show "Quill failed to load"—ensure CDN access or bundle the asset locally.
