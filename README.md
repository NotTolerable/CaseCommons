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
- Admin: `admin@example.com` / `password`
- User: `user@example.com` / `password`
- Muted: `muted@example.com` / `password`
- Banned: `banned@example.com` / `password`

## Tests
- Unit/integration suite: `pytest`
- Include the dockerized persistence check (requires Docker): `RUN_DOCKER_INTEGRATION=1 pytest -m integration`

## Fly.io deployment (manual steps)
This setup uses SQLite on a Fly volume to avoid paid Postgres. If you prefer Postgres later, set a Postgres `DATABASE_URL` secret and skip the SQLite steps.

1. **Authenticate and set the app name/region**
   - `fly auth login`
   - `fly apps create <app-name> --region <region>` (or reuse an existing app)

2. **Create the data volume (DB + uploads)**
   - `fly volumes create data --app <app-name> --region <region> --size 1`
   - `fly.toml` mounts this volume at `/data`, which holds both the SQLite DB (`/data/app.db`) and uploads (`/data/uploads`).

3. **Set required secrets** (at minimum)
   - `fly secrets set SECRET_KEY=<random-long-string> SECURITY_PASSWORD_SALT=<random-long-string>`
   - Optional: mail provider secrets as needed.
   - If you later want Postgres instead of SQLite, also set `fly secrets set DATABASE_URL=<postgresql://...>` (the app will normalize legacy `postgres://`).

4. **Deploy**
   - `fly deploy` (release command runs `flask db upgrade` before starting machines). The default `fly.toml` exports `DATABASE_URL=sqlite:////data/app.db` to match the mounted volume.
   - The app listens on `0.0.0.0:$PORT` (Fly injects `PORT`, defaults to 8080).

5. **Verify environment and health**
   - `fly ssh console -C "printenv DATABASE_URL"` (should show `sqlite:////data/app.db` unless overridden)
   - `fly logs` to confirm migration head/state and upload path
   - `fly status` and `fly open` for health checks

6. **Post-deploy sanity checks**
   - Visit the site, sign up a test user, and confirm email verification gating
   - Upload an image in the admin report editor and verify it persists in `/data/uploads`
   - Create a discussion/comment to confirm muted/banned rules behave as expected

> Note: If you need automated backups or multi-region HA while staying on SQLite, you’ll need an external backup cadence for `/data` (not included here); otherwise switch to managed Postgres on Fly and point `DATABASE_URL` to it.

## Troubleshooting
- Missing tables / OperationalError: check logs for "Database schema missing tables" and run `flask db upgrade` inside the container or via Fly release command.
- CSRF failures redirect back with a warning and log the failing path/IP; refresh the page and resubmit.
- Quill not loading: browser console will show "Quill failed to load"—ensure CDN access or bundle the asset locally.
