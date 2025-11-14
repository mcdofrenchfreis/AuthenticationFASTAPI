# Authentication App (FastAPI + SQLAlchemy)

A full-stack authentication starter built with FastAPI, SQLAlchemy, and Jinja2 templates. It supports user registration, email OTP verification, login, password reset via OTP, sessionless auth with JWT cookies, and a modern glassmorphism UI with a day/night mode toggle and toast notifications.

## Features
- Web UI (Jinja2) with glassmorphism styling and toast notifications
- Day/Night theme toggle with localStorage persistence
- Registration with email verification (OTP)
- Login with cookie-based JWT
- Forgot password with OTP verification, then password reset
- Password policy enforced (client and server)
- SQLAlchemy ORM; default SQLite, configurable to MySQL (PyMySQL)
- Lightweight auto-migration for new user columns

## Tech Stack
- FastAPI, Starlette, Jinja2
- SQLAlchemy 2.x
- passlib[bcrypt] (bcrypt pinned for compatibility)
- python-jose (JWT)
- PyMySQL (optional, for MySQL)

## Quickstart (Windows)
1. Clone and open this folder in your IDE.
2. Create and activate a virtual environment:
   - `python -m venv .venv311`
   - `.\.venv311\Scripts\activate`
3. Install dependencies:
   - `pip install -r requirements.txt`
4. Configure environment (optional, see Environment below). Defaults work with SQLite and require SMTP config for emails.
5. Run the app:
   - PowerShell: `./run.ps1`
   - Or directly: `python -m uvicorn app.main:app --reload`
6. Open http://127.0.0.1:8000

## Project Structure
- `app/main.py` — FastAPI app factory, DB init, routers, static mount
- `app/database.py` — engine/session setup, Base, lightweight migrations
- `app/models.py` — SQLAlchemy models (`User`, `OtpCode`)
- `app/auth.py` — JSON API routes under `/auth/*`
- `app/web_routes/` — Web routes (Jinja2 pages)
  - `app/web_routes/base.py` — shared router and templates setup
  - `app/web_routes/pages/` — home and register pages
  - `app/web_routes/auth/` — login/logout and register POST handlers
  - `app/web_routes/reset/` — forgot, verify-otp, reset password pages
  - `app/web_routes/verify/` — account verification page and POST
  - `app/web_routes/cookies.py` — helpers to set/clear auth cookie
- `app/templates/*` — HTML templates
- `app/static/*` — Static assets (CSS, JS, images)
- `app/infrastructure/mailer.py` — SMTP mail sending helpers
- `requirements.txt` — Python dependencies (bcrypt pinned)

## Environment
Configuration is centrally managed in `app/core/settings.py` using Pydantic BaseSettings. It automatically reads environment variables and, if present, a `.env` file at the project root.

Recommended variables to set via your shell or a `.env` loader:
- `AUTH_SECRET_KEY` — secret for JWT signing
- `AUTH_ACCESS_TOKEN_EXPIRE_MINUTES` — default 60
- `AUTH_OTP_EXP_MINUTES` — default 10
- `DATABASE_URL` — default `sqlite:///./auth.db`
  - MySQL example: `mysql+pymysql://user:pass@localhost:3306/auth_db`
- SMTP (if you intend to send emails):
  - `SMTP_HOST` (default `smtp.gmail.com`)
  - `SMTP_PORT` (default `587`)
  - `SMTP_USER`
  - `SMTP_PASSWORD` (Gmail App Password if using Gmail)
  - `SMTP_FROM` (defaults to user)
  - `SMTP_FROM_NAME` (defaults to `Auth App`)

Notes:
- Do not hardcode secrets in source code. Prefer setting them via `.env` or environment variables.
- For Gmail, set up an App Password and use STARTTLS on port 587.

## Database
- Default: SQLite file `auth.db` in project root.
- SQLAlchemy engine is configured via `DATABASE_URL`. If it starts with `sqlite`, we enable `check_same_thread=False`.
- On startup, `Base.metadata.create_all()` runs and a small `run_migrations()` helper adds any new columns (idempotent) to the `users` table.

## Password Policy
Enforced on both client and server (registration and reset):
- At least 8 characters
- At least 1 lowercase letter
- At least 1 uppercase letter
- At least 1 number
- At least 1 special character
- No spaces
- Confirm password must match

## Web Flow
- Registration: `/register` (POST creates user, sends verification code) → Verify `/verify-account` → Login `/login`
- Login: `/login` sets an HTTP-only JWT cookie; `/dashboard` requires cookie
- Forgot Password: `/forgot` → Verify OTP `/verify-otp` → Reset `/reset`
- Toasts: used for success states (e.g., reset complete) and theme toggle exists in the header
- Day/Night: icon toggle in header; persists choice in localStorage

## JSON API (Auth)
Base prefix: `/auth`
- `POST /auth/register` — create account (sends verification OTP)
- `POST /auth/login` — returns access token
- `POST /auth/forgot-password` — sends OTP if email exists
- `POST /auth/verify-otp` — verifies OTP (password reset context)
- `POST /auth/reset-password` — reset with valid OTP
- `POST /auth/verify-account` — verify account with OTP
- `POST /auth/resend-verification` — resend verification OTP

## Running Notes
- Hot reload is enabled when using `--reload` or `./run.ps1`.
- Auth cookie name: `access_token` (see `app/web_routes/cookies.py`).
- If you switch databases, install the required driver and update `DATABASE_URL`.
- Bcrypt compatibility: we pin `bcrypt==4.0.1` to work with `passlib==1.7.4`.

## Security
- Do not commit real SMTP credentials or JWT secrets to source control.
- Use App Passwords for Gmail.
- Consider setting `secure=True` on cookies and serving behind HTTPS in production.
