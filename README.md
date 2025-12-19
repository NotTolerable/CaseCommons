# Case Commons

Light-theme Flask app for law student case analysis reports and discussions.

## Setup
1. Copy `.env.example` to `.env` and adjust secrets.
2. Start services: `docker-compose up --build`.
3. Initialize DB migrations inside the web container:
   - `docker-compose run --rm web flask db upgrade`
4. Seed data: `docker-compose run --rm web python seed.py`

## Accounts
- Admin: `admin@example.com` / `password`
- User: `user@example.com` / `password`
- Muted: `muted@example.com` / `password`
- Banned: `banned@example.com` / `password`

## Tests
Run `pytest` (requires dependencies from `requirements.txt`).
