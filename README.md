# Case Commons

Light-theme Flask app for law student case analysis reports and discussions.

## Local development
1. Copy `.env.example` to `.env` and set secrets (CSRF secret, security salt, mail settings). By default the app uses SQLite at `sqlite:////data/app.db` (normalized automatically if `postgres://` is provided).
2. Start services (SQLite): `docker compose up --build` (web listens on `0.0.0.0:8080`). A `data` volume is mounted at `/data` so the SQLite DB and `/data/uploads` persist across restarts.
3. Optional Postgres profile: `docker compose --profile postgres up --build` will also start the Postgres container and you can point `DATABASE_URL` to it (e.g., `postgresql://postgres:postgres@db:${DB_PORT:-5432}/casecommons`).
4. Run migrations inside the web container (also runs automatically on start):
   - `docker compose run --rm web flask db upgrade`
5. Seed data for quick testing: `docker compose run --rm web python seed.py`.

## Accounts
- Admin: `admin@example.com` / `password` (use this for `/admin` to create/manage users)
- User: `user@example.com` / `password`
- Muted: `muted@example.com` / `password`
- Banned: `banned@example.com` / `password`
- Public signup is disabled. Applicants submit via `/apply`, and admins approve + create accounts in the admin panel.

## Tests
- Unit/integration suite: `pytest`
- Include the dockerized persistence check (requires Docker): `RUN_DOCKER_INTEGRATION=1 pytest -m integration`

## Fly.io deployment (manual steps)
SQLite-only deployment is fully supported and is the default Fly.io path below. The app stores the SQLite database and uploads on the mounted Fly volume at `/data` so data survives restarts and deploys. If you prefer Postgres later, set a Postgres `DATABASE_URL` secret and skip the SQLite-specific steps.

1. **Authenticate and set the app name/region**
   - `fly auth login`
   - `fly apps create <app-name> --region <region>` (or reuse an existing app)

2. **Create the data volume (DB + uploads)**
   - `fly volumes create data --app <app-name> --region <region> --size 1`
   - If you scale to more than one machine (e.g., `fly scale count 2`), either reduce back to one machine or create one volume per machine: `fly volumes create data --app <app-name> --region <region> --size 1 --count <machine-count>`.
   - `fly.toml` mounts this volume at `/data`, which holds both the SQLite DB (`/data/app.db`) and uploads (`/data/uploads`).

3. **Set required secrets** (at minimum)
   - `fly secrets set SECRET_KEY=<random-long-string> SECURITY_PASSWORD_SALT=<random-long-string>`
   - Optional: mail provider secrets as needed.
   - SQLite default: no `DATABASE_URL` secret is needed; the app will default to `sqlite:////data/app.db` on the mounted volume.
   - Postgres option (paid): set `fly secrets set DATABASE_URL=<postgresql://...>` (the app will normalize legacy `postgres://`).

4. **Deploy (SQLite path)**
   - `fly deploy` (release command runs `flask db upgrade` before starting machines). The default `fly.toml` exports `DATABASE_URL=sqlite:////data/app.db` to match the mounted volume.
   - The app listens on `0.0.0.0:$PORT` (Fly injects `PORT`, defaults to 8080).

5. **Verify SQLite persistence**
   - `fly ssh console -C "ls -l /data && sqlite3 /data/app.db '.tables'"` to confirm the DB file and schema exist on the volume.
   - `fly ssh console -C "ls -l /data/uploads"` to confirm uploads are stored on the volume.
   - `fly logs` to confirm migration head/state and upload path.
   - `fly status` and `fly open` for health checks.

6. **Post-deploy sanity checks**
   - Visit the site, submit an application via `/apply`, approve it in `/admin`, and confirm the created account can log in.
   - Upload an image in the admin report editor and verify it persists in `/data/uploads`.
   - Create a discussion/comment to confirm muted/banned rules behave as expected.

> Notes:
> - SQLite on Fly works for single-region deployments using the mounted volume; if you need automated backups or multi-region HA, add your own backup cadence for `/data` or switch to managed Postgres and point `DATABASE_URL` to it.
> - The app runs fully on SQLite when `DATABASE_URL` is unset. If you later enable Postgres, rerun `flask db upgrade` to migrate the new database before traffic.

## Troubleshooting
- Missing tables / OperationalError: check logs for "Database schema missing tables" and run `flask db upgrade` inside the container or via Fly release command.
- Missing volume / deploy error (`Process group 'app' needs volumes with name 'data'`): create the volume(s) in the primary region with `fly volumes create data --app <app-name> --region <region> --size 1 [--count N]`, or scale the app down to one machine with `fly scale count 1` if you only create a single volume.
- CSRF failures redirect back with a warning and log the failing path/IP; refresh the page and resubmit.
- Quill not loading: browser console will show "Quill failed to load"—ensure CDN access or bundle the asset locally.
- Sessions/logins: ensure `SECRET_KEY` is stable, set `SESSION_COOKIE_SECURE=true` when serving over HTTPS (Fly), and confirm the browser accepts cookies.

## Local setup: application approval emails
- Required env vars when emailing applicants (set in `.env` or Fly secrets):
  - **Resend (recommended):** `RESEND_API_KEY` (e.g., `re_xxx`), `RESEND_FROM` (verified sender, e.g., `Case Commons <hello@yourdomain.com>`).
  - **SMTP (alternative):** `MAIL_SERVER`, `MAIL_PORT`, `MAIL_USERNAME`, `MAIL_PASSWORD`, `MAIL_DEFAULT_SENDER`, `MAIL_USE_TLS`/`MAIL_USE_SSL`.
  - `APP_BASE_URL` (optional) if you include links in mail content.
- Development defaults:
  - `MAIL_DEV_LOG_ONLY=true` logs outbound mail content to the server console instead of sending.
  - No SMTP/Resend key is needed in this mode.
- Optional local inbox (Mailpit):
  - Start: `docker compose --profile mail up mailpit` (UI at http://localhost:8025, SMTP at :1025).
  - Configure env: `MAIL_SERVER=mailpit`, `MAIL_PORT=1025`, `MAIL_USE_TLS=false`, `MAIL_DEV_LOG_ONLY=false`, `MAIL_DEFAULT_SENDER=dev@localhost`.
- Fly deployment with Resend:
  - Set `RESEND_API_KEY` and `RESEND_FROM` via `fly secrets set ...`.
  - Ensure the sender is authorized/verified in Resend.
- Troubleshooting missing emails:
  - Check Fly logs for `Resend API error` messages.
  - Confirm the sender address is authorized and the Resend key is valid.
  - Ensure `MAIL_DEV_LOG_ONLY` is `false` when you expect real delivery and that outbound HTTPS is allowed in your environment.

This application is fully functional on SQLite when deployed with a Fly volume; Postgres is optional, not required for core features.
