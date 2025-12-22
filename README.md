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

## Fly.io deployment (manual steps)
1. **Authenticate and set the app name/region**
   - `fly auth login`
   - `fly apps create <app-name> --region <region>` (or reuse an existing app)

2. **Provision and attach Postgres**
   - `fly postgres create --app <app-name>-db --region <region>` (or reuse an existing cluster)
   - `fly postgres attach --app <app-name> <app-name>-db`
   - Capture the provided `DATABASE_URL` secret; legacy `postgres://` will be normalized to `postgresql://` by the app and Alembic.

3. **Create the uploads volume**
   - `fly volumes create uploads --app <app-name> --region <region> --size 1`
   - Ensure `fly.toml` includes the mount (already mapped to `/data/uploads`).

4. **Set required secrets** (at minimum)
   - `fly secrets set DATABASE_URL=<from attach>`
   - `fly secrets set SECRET_KEY=<random-long-string> SECURITY_PASSWORD_SALT=<random-long-string>`
   - Optional: mail provider secrets as needed.

5. **Deploy**
   - `fly deploy` (release command runs `flask db upgrade` before starting machines)
   - The app listens on `0.0.0.0:$PORT` (Fly injects `PORT`, defaults to 8080).

6. **Verify environment and health**
   - `fly ssh console -C "printenv DATABASE_URL"`
   - `fly logs` to confirm migration head/state and upload path
   - `fly status` and `fly open` for health checks

7. **Post-deploy sanity checks**
   - Visit the site, sign up a test user, and confirm email verification gating
   - Upload an image in the admin report editor and verify it persists in `/data/uploads`
   - Create a discussion/comment to confirm muted/banned rules behave as expected

## Troubleshooting
- Missing tables / OperationalError: check logs for "Database schema missing tables" and run `flask db upgrade` inside the container or via Fly release command.
- CSRF failures redirect back with a warning and log the failing path/IP; refresh the page and resubmit.
- Quill not loading: browser console will show "Quill failed to load"—ensure CDN access or bundle the asset locally.
