# Deployment volume error (Fly.io)

## What happened
Deploying with `flyctl deploy -a casecommons --image registry.fly.io/casecommons:deployment-9c54aaa143fe4ede9bb8854bc46b13c0 --depot-scope=app --config fly.toml` failed with:

```
Process group 'app' needs volumes with name 'data' to fulfill mounts defined in fly.toml; Run `fly volume create data -r REGION -n COUNT` for the following regions and counts: iad=2
```

The app uses a mounted volume at `/data` for the SQLite database and uploads. Fly requires **one volume per running machine** in the region. Your Fly app currently expects two machines in `iad`, but no `data` volumes exist there.

## How to fix
Choose one of these options before re-deploying:

1) **Create the required volume(s) in `iad` (recommended)**
   - If you want to keep two machines: `fly volumes create data --app casecommons --region iad --size 1 --count 2`
   - If you only need one machine: `fly volumes create data --app casecommons --region iad --size 1`

2) **Reduce machine count to one (if you only create one volume)**
   - `fly scale count 1`
   - Then create a single volume as above.

3) **Verify volumes**
   - `fly volumes list --app casecommons`
   - Each running machine must map to a `data` volume in `iad` (the primary region).

After creating the volume(s), rerun the deploy command.

## Notes
- The `fly.toml` mount is required for persistence. Do not remove it; instead, ensure volumes exist.
- Volume names must be `data` to match the mount declaration.
- If you change regions, create the volumes in the new `primary_region` as well.
