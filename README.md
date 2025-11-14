# Authentication App (FastAPI + SQLAlchemy)

A full-stack authentication starter built with FastAPI, SQLAlchemy, and Jinja2 templates. It supports user registration, email OTP verification, login, password reset via OTP, sessionless auth with JWT cookies, and a modern glassmorphism UI with a day/night mode toggle and toast notifications.

## Features
- Web UI (Jinja2) with glassmorphism styling and toast notifications
- Day/Night theme toggle with localStorage persistence
- Registration with email verification (OTP)
- Login with cookie-based JWT
- Optional TOTP-based MFA for accounts (enable/disable via settings page)
- Forgot password with OTP verification, then password reset
- Password policy enforced (client and server)
- SQLAlchemy ORM with PostgreSQL (psycopg2)
- Lightweight auto-migration for new user columns
- Simple login rate limiting (per IP/email) to mitigate brute-force attacks
- Configurable security (ENV-aware settings, cookie flags, JWT expiry)

## Tech Stack
- FastAPI, Starlette, Jinja2
- SQLAlchemy 2.x
- passlib[bcrypt] (bcrypt pinned for compatibility)
- python-jose (JWT)
- pyotp (TOTP codes for MFA)

## Quickstart (Windows)
1. Clone and open this folder in your IDE.
2. Create and activate a virtual environment:
   - `python -m venv .venv311`
   - `.\.venv311\Scripts\activate`
3. Install dependencies:
   - `pip install -r requirements.txt`
4. Configure environment (optional, see Environment below). Defaults assume PostgreSQL and require SMTP config for emails.
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

Core settings you will typically configure via your shell or a `.env` file:

- `ENV` — environment name. Defaults to `dev`.
  - In `dev`, security validation is relaxed for convenience.
  - In non-`dev` (e.g. `prod`), startup will fail if critical settings are unsafe (weak secret, insecure cookies).
- `AUTH_SECRET_KEY` — secret for JWT signing.
  - In non-dev environments this must be a long, random value (>= 32 chars) and not the default.
- `AUTH_ACCESS_TOKEN_EXPIRE_MINUTES` — default 60.
- `AUTH_OTP_EXP_MINUTES` — default 10.
- `AUTH_COOKIE_SECURE` — `False` in dev, **must be `True` in non-dev** (enforced by `validate_for_runtime`).
- `AUTH_COOKIE_SAMESITE` — cookie SameSite mode, default `lax`.
- `AUTH_ISSUER` — optional JWT issuer string.
- `DATABASE_URL` — PostgreSQL DSN, e.g. `postgresql+psycopg2://user:password@localhost:5432/auth_db`.
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

On startup, `settings.validate_for_runtime()` enforces that non-dev environments use a strong `AUTH_SECRET_KEY` and secure cookies.

## Database
- PostgreSQL is the supported database.
- SQLAlchemy engine is configured via `DATABASE_URL` (e.g., `postgresql+psycopg2://user:password@localhost:5432/auth_db`).
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
- MFA Settings: `/settings/mfa` for enabling/disabling TOTP MFA on the current account
  - Start setup: `/settings/mfa/start` (POST)
  - Confirm setup: `/settings/mfa/confirm` (POST with TOTP code)
  - Disable MFA: `/settings/mfa/disable` (POST with TOTP code)
- If MFA is enabled for an account, `/login` redirects to `/login/mfa` for the second factor step
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
- `POST /auth/mfa/setup` — start MFA setup with email/password; returns TOTP secret and `otpauth://` URL
- `POST /auth/mfa/confirm` — confirm MFA setup with a TOTP code and enable MFA on the account
- `POST /auth/mfa/disable` — disable MFA after verifying a TOTP code
- `POST /auth/login/mfa/start` — start an MFA login flow; returns a short-lived MFA token
- `POST /auth/login/mfa/verify` — complete MFA login using the MFA token and TOTP code; returns access token

## Running Notes
- Hot reload is enabled when using `--reload` or `./run.ps1`.
- Auth cookie name: `access_token` (see `app/web_routes/cookies.py`).
- If you switch databases, install the required driver and update `DATABASE_URL`.
- Bcrypt compatibility: we pin `bcrypt==4.0.1` to work with `passlib==1.7.4`.

## Security
- Do not commit real SMTP credentials or JWT secrets to source control.
- Use App Passwords for Gmail.
- Always run with `ENV=prod` (or similar) and a strong `AUTH_SECRET_KEY` in production.
- In production, `AUTH_COOKIE_SECURE` **must** be `True` so cookies are only sent over HTTPS (this is enforced at startup).
- A simple in-memory login rate limiter is enabled for `/auth/login` to slow down brute-force attempts.

## Architecture Overview

This project is structured in layers to keep concerns separated and make reuse/testability easier:

- **Domain layer**
  - `app/services/auth_service.py` — core authentication and OTP flows, using repositories and raising domain-specific errors.
  - `app/domain/interfaces.py` — repository protocols.
  - `app/domain/errors.py` — auth-specific exception types (e.g. `InvalidCredentialsError`, `OtpInvalidOrExpiredError`).
- **Adapters**
  - `app/adapters/auth_adapter.py` — JSON API adapter: maps domain errors to `HTTPException`, schedules verification/reset emails using FastAPI `BackgroundTasks`.
  - `app/adapters/web_auth_adapter.py` — Web adapter: used by Jinja2 routes to call `AuthService`, handle errors, and schedule emails via `BackgroundTasks`.
- **Transport/UI**
  - `app/auth.py` — JSON API endpoints under `/auth/*` (thin wiring + rate limiting).
  - `app/web_routes/*` — Web routes (form handling + template rendering) that delegate auth logic to adapters.

Email sending is centralized in `app/infrastructure/mailer.py` and is invoked asynchronously via `BackgroundTasks` for registration, forgot-password, and resend-verification flows.
