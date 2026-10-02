# POS-System_backend

FastAPI backend for the ABA PayWay point-of-sale system: products, orders, KHQR
payments, users/roles with bearer-token sessions, an audit trail and a settings
page for the merchant credentials. Data lives in a single SQLite file
(`pos.db`). The React front end is a separate project.

## Requirements

* Python 3.11+ (built and tested on 3.12)
* An ABA PayWay merchant account (`profile_id` + `secret_key`)
* PowerShell (for `smoke_test.ps1`) and Windows is assumed by the helper scripts

## Setup

```powershell
cd backend_api
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
copy .env.example .env      # then edit .env and fill in your ABA credentials
```

`.env` is intentionally **not** in this repository (see `.gitignore`), because it
holds the signing secret. Every deployment needs its own copy. Keys supplied
through `.env` show up in the Settings page but are read-only there, so the file
stays the single source of truth; keys you type into the Settings page instead
are stored in the database.

## Run

```powershell
python -m uvicorn main:app --host 127.0.0.1 --port 8000
```

On the very first start the API creates the administrator `admin` and writes the
generated password to `initial_admin_password.txt` (git-ignored). Set
`POS_ADMIN_PASSWORD` (and optionally `POS_ADMIN_USERNAME`) in the environment to
choose the password yourself instead. Sign in, then change it from the Security
page and delete that file.

## Tests

```powershell
python security_selftest.py     # auth / rate-limit / lockout checks on a temp DB
.\smoke_test.ps1                # end-to-end API flow on a temp DB and port
```

Both scripts create and drop their own throwaway database, so they never touch
`pos.db`.

## Offline administration

```powershell
python manage.py list                       # who exists
python manage.py passwd admin               # rotate a password
python manage.py add-user sreyneang --role cashier
python manage.py revoke-tokens              # sign every device out
```

## Deploying on a host (example: Render)

The repository root *is* the app folder, so leave **Root Directory** empty:

| Field | Value |
| --- | --- |
| Build command | `pip install -r requirements.txt` |
| Start command | `uvicorn main:app --host 0.0.0.0 --port $PORT` |
| Health check path | `/api/health` |

Do **not** add `--workers`: the rate limiter and the login lockout keep their
state per process (`security.py`) and SQLite has a single writer, so several
workers would multiply every limit and collide on writes.

`python main.py` is for local use only - it binds `127.0.0.1` and enables reload.

### Storage: the setting that silently loses data

A hosted filesystem is ephemeral: `pos.db` next to the code is deleted on every
deploy, restart and (free plan) spin-down. To keep the data:

1. Use a paid instance type - **free web services cannot have a disk at all**.
2. Add a disk (1 GB is plenty) with mount path `/var/data`.
3. Set `DATABASE_URL=sqlite:////var/data/pos.db` - note the **four** slashes
   (three belong to the scheme, the rest is the absolute path).

Each start logs the file it opened, so the log tells you whether the data is
really persisting:

```
[db] using existing database file /var/data/pos.db
```

If `DATABASE_URL` names a disk mount path and no disk is attached, that folder
does not exist and sqlite only says `unable to open database file`, which never
mentions the folder. `database.py` therefore creates the folder when it can -
warning loudly that anything written there will be lost - and otherwise fails
with an error that names the missing folder.

### Environment variables to set

| Key | Value |
| --- | --- |
| `ABA_PROFILE_ID`, `ABA_SECRET_KEY` | merchant credentials (never in the repository) |
| `ABA_DEMO_MODE` | `false` - otherwise `POST /api/orders/{id}/confirm` can settle an order without the gateway |
| `DATABASE_URL` | `sqlite:////var/data/pos.db` (see above) |
| `CORS_ORIGINS` | the deployed front-end origin, e.g. `https://pos-system-frontend.onrender.com`; the default allows only localhost and LAN addresses, so the browser would block every call |
| `POS_ALLOWED_HOSTS` | your own host, e.g. `pos-system-backend.onrender.com` |
| `FRONTEND_BASE_URL`, `ABA_SUCCESS_URL`, `ABA_CANCEL_URL` | the deployed front-end url; the defaults point at `localhost:3000`, which is unreachable from a customer's phone |
| `POS_ADMIN_USERNAME`, `POS_ADMIN_PASSWORD` | so you choose the first password instead of reading it out of a log |
| `POS_ENABLE_DOCS` / `POS_AUTH_DISABLED` | keep both `false` |

Any key set in the environment wins over the database and is shown read-only in
the Settings page (see `config.py`), so shop staff cannot overwrite the gateway
credentials from the till.

## Security notes

* Never commit `.env`, `pos.db`, `initial_admin_password.txt` or `FIRST_LOGINS.txt`.
* The backend is meant to run on the till itself (`127.0.0.1`); see the comments in
  `.env.example` before exposing it to a network.
* Rotating the ABA secret means updating both the ABA merchant portal and `.env`
  (or the Settings page), then restarting the service.
