# FastAPI Auth Service

JWT-based authentication service with PostgreSQL, bcrypt password hashing, and rate limiting.

## Stack
- **FastAPI** (async web framework)
- **SQLAlchemy** ORM + **PostgreSQL**
- **python-jose** for JWT access/refresh tokens
- **passlib[bcrypt]** for password hashing
- **slowapi** for rate limiting
- **Docker Compose** for local dev / deployment

## Endpoints

| Method | Path                 | Description                        | Auth required |
|--------|----------------------|-------------------------------------|----------------|
| POST   | `/auth/register`     | Create a new user                  | No             |
| POST   | `/auth/login`        | Get access + refresh token (OAuth2 form) | No       |
| POST   | `/auth/refresh`      | Exchange refresh token for new pair | No            |
| GET    | `/users/me`          | Get current user profile           | Yes (Bearer)   |
| PUT    | `/users/me/password` | Change password                    | Yes (Bearer)   |
| GET    | `/health`            | Health check                       | No             |

## Quickstart (Docker)

```bash
cp .env.example .env   # edit SECRET_KEY
docker compose up --build
```

App runs at `http://localhost:8000`. Interactive docs at `http://localhost:8000/docs`.

## Quickstart (local, no Docker)

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# point DATABASE_URL at a local Postgres instance in .env
uvicorn app.main:app --reload
```

## Example flow

```bash
# Register
curl -X POST localhost:8000/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"a@b.com","username":"soham","password":"secret123"}'

# Login (OAuth2 form, not JSON)
curl -X POST localhost:8000/auth/login \
  -F "username=soham" -F "password=secret123"

# Use access token
curl localhost:8000/users/me \
  -H "Authorization: Bearer <access_token>"
```

## Notes / next steps for production
- Tables are created via `Base.metadata.create_all` for convenience — swap to **Alembic migrations** before shipping.
- Add refresh-token revocation/rotation (e.g., store issued token IDs in Redis) if you need logout-everywhere or stolen-token mitigation.
- Add unit tests (pytest + a test DB fixture) and E2E tests against the running app.
- Put this behind HTTPS and a reverse proxy (nginx/Caddy) in production; never expose port 5432 publicly.
- Set a strong random `SECRET_KEY` (e.g., `openssl rand -hex 32`) via environment variable, never commit it.
