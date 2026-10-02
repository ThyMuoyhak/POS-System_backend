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

## Security notes

* Never commit `.env`, `pos.db`, `initial_admin_password.txt` or `FIRST_LOGINS.txt`.
* The backend is meant to run on the till itself (`127.0.0.1`); see the comments in
  `.env.example` before exposing it to a network.
* Rotating the ABA secret means updating both the ABA merchant portal and `.env`
  (or the Settings page), then restarting the service.
