# Case Commons

Light-theme Flask app for law student case analysis reports and discussions.

## Local development
1. Copy `.env.example` to `.env` and set secrets (CSRF secret, security salt, mail settings). `DATABASE_URL` should point to Postgres; `postgres://` will be rewritten to `postgresql://` automatically.
2. Start services: `docker compose up --build` (web listens on `0.0.0.0:8080`). Uploads persist to `/data/uploads` by default and are volume-mounted by docker-compose.
3. Run migrations inside the web container (also runs automatically on start):
   - `docker compose run --rm web flask db upgrade`
4. Seed data for quick testing: `docker compose run --rm web python seed.py`.

## Accounts
- Admin: `admin@example.com` / `password`
- User: `user@example.com` / `password`
- Muted: `muted@example.com` / `password`
- Banned: `banned@example.com` / `password`

## Tests
- Unit/integration suite: `pytest`
- Include the dockerized persistence check (requires Docker): `RUN_DOCKER_INTEGRATION=1 pytest -m integration`

## Fly.io deployment
1. Provision Postgres: `fly postgres create` (or `fly postgres attach --app <app>` if you already have one). Note the `DATABASE_URL` secret.
2. Set the database secret (scheme normalized in-app if needed): `fly secrets set DATABASE_URL=<url>` (legacy `postgres://` is rewritten to `postgresql://`).
3. Create a persistent volume for uploads: `fly volumes create uploads --app <app> --region <region> --size 1` and ensure `fly.toml` mounts it at `/data/uploads`.
4. Deploy: `fly deploy`. The release command runs `flask db upgrade` before machines start, keeping migrations in sync. The app serves on `0.0.0.0:$PORT` (defaults to 8080 on Fly).
5. Verify environment and health:
   - `fly ssh console -C "printenv DATABASE_URL"`
   - `fly logs` to confirm startup and migration status
   - `fly status` and `fly open` for health and HTTP checks

## Troubleshooting
- Missing tables / OperationalError: check logs for "Database schema missing tables" and run `flask db upgrade` inside the container or via Fly release command.
- CSRF failures redirect back with a warning and log the failing path/IP; refresh the page and resubmit.
- Quill not loading: browser console will show "Quill failed to load"—ensure CDN access or bundle the asset locally.
