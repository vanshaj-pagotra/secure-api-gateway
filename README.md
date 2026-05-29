# Sentinel Gateway

A lightweight API gateway you can drop in front of any HTTP backend. It handles JWT validation, role-based access control, WAF attack detection, IP rate limiting, and security logging — so your backend doesn't have to.

---

## What it does

Every request coming into your API passes through a five-stage pipeline before it ever reaches your backend:

1. **Rate limiting** — blocks IPs that exceed your configured request threshold
2. **WAF** — scans URLs and request bodies for SQL injection, XSS, and path traversal (29 compiled rules)
3. **JWT validation** — rejects requests without a valid, non-expired, non-revoked token on protected routes
4. **RBAC** — enforces that only `Admin`-role tokens can reach `/admin/*` paths
5. **Proxy** — forwards clean requests to the correct backend service and returns the response

All blocked requests are logged to MySQL. Admins get a live dashboard at `/admin/dashboard` showing event stats and a searchable log table.

---

## How authentication works

The gateway **validates** JWTs — it doesn't issue them for your application users. Your backend issues the tokens; the gateway checks them.

The only requirement is that both sides use the **same `JWT_SECRET_KEY`**. Set it in your `.env`, and use the same value in your backend when signing tokens.

Your JWTs need to contain:
```json
{
  "sub": "username",
  "role": "User",
  "exp": 1234567890
}
```

The `role` field is how RBAC works. Requests to `/admin/*` are blocked unless `role` is `"Admin"`. For everything else, any valid token passes.

The gateway does have its own `/login` endpoint and `users` table, but that's only for gateway admins accessing the dashboard — not your application users.

Logout is supported via `POST /logout` — the token gets added to a revocation list so it can't be reused even if it hasn't expired yet. Stale revocation entries are cleaned up automatically each time the gateway starts.

---

## Routing

The gateway supports routing different URL prefixes to different backend services. Configure it in `.env`:

```ini
ROUTES=/api/users|http://users-service:5001, /api/orders|http://orders-service:5002, /|http://main-backend:5000
```

Longest prefix wins, so `/api/users/123` goes to `users-service` before `/` would match. If you only have one backend, use `BACKEND_URL` instead:

```ini
BACKEND_URL=http://localhost:5000
```

---

## Setup

**Requirements:** Python 3.10+, MySQL

```bash
git clone https://github.com/vanshaj-pagotra/secure-api-gateway.git
cd secure-api-gateway
python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate   # macOS/Linux
pip install -r requirements.txt
```

**Set up the database:**
```bash
mysql -u root -p < schema.sql
```

**Configure your environment:**
```bash
cp .env.example .env
```
Open `.env` and fill in your values. The most important ones:
- `JWT_SECRET_KEY` — must match the secret your backend uses to sign tokens
- `ROUTES` or `BACKEND_URL` — where to forward requests
- `DB_*` — your MySQL credentials

**Create a gateway admin account:**
```bash
python manage.py
```
This creates an admin user who can log into the dashboard. It's separate from your application's users.

**Start the gateway:**
```bash
uvicorn main:app --reload
```

The gateway will be available at `http://127.0.0.1:8000`. Point your frontend at this URL instead of directly at your backend.

---

## Integrating with your backend

Two things to do on your side:

1. Sign JWTs using the same `JWT_SECRET_KEY` you put in the gateway's `.env`
2. Include a `role` claim in the token (`"User"` or `"Admin"`)

That's it. No changes to your routes, no middleware to install. The gateway sits in front of your backend transparently.

Your frontend should send all API requests to the gateway's URL (e.g. `http://localhost:8000`), not directly to your backend. Protected paths require an `Authorization: Bearer <token>` header.

---

## Configuration reference

| Variable | Description |
|---|---|
| `JWT_SECRET_KEY` | Secret used to validate JWTs. Must match your backend. |
| `JWT_ALGORITHM` | Signing algorithm. Default: `HS256` |
| `JWT_EXPIRY_MINUTES` | Token lifetime for gateway admin sessions |
| `DB_HOST` / `DB_PORT` / `DB_NAME` / `DB_USER` / `DB_PASSWORD` | MySQL connection |
| `ROUTES` | Path-based routing rules. Format: `/prefix\|http://host:port` (comma-separated) |
| `BACKEND_URL` | Single-backend fallback if `ROUTES` is not set |
| `RATE_LIMIT_MAX_REQUESTS` | Max requests per IP per window |
| `RATE_LIMIT_WINDOW_SECONDS` | Rate limit window size in seconds |
| `PUBLIC_PATHS` | Comma-separated paths that skip JWT validation |
| `ALLOWED_ORIGINS` | Comma-separated CORS origins |

---

## Admin dashboard

Hit `/admin/dashboard` in your browser and log in with the credentials you created via `manage.py`. You'll get:

- Event counts broken down by type (WAF blocks, rate limit hits, failed logins)
- A time-series chart of security events
- A searchable log table with IP, event type, timestamp, and details

The dashboard auto-refreshes every 30 seconds.

---

## Project structure

```
sentinel-gateway/
├── main.py           # FastAPI app, middleware pipeline, routes
├── auth.py           # JWT validation, RBAC, password hashing
├── proxy.py          # Path-based routing and request forwarding
├── waf.py            # SQLi, XSS, and path traversal detection with input normalization
├── rate_limiter.py   # IP-based request throttling
├── logger.py         # Security event logging
├── database.py       # MySQL connection handler
├── manage.py         # CLI tool for managing gateway admin accounts
├── schema.sql        # Database schema (3 tables)
├── templates/
│   └── dashboard.html  # Admin dashboard UI
├── .env.example      # Configuration template
└── requirements.txt
```

---

## Known limitations

- **Rate limiter is in-memory** — counters reset on server restart. Fine for most use cases; swap the store for Redis if you need persistence across restarts.
- **WAF uses regex patterns** — covers SQLi, XSS, and path traversal with input normalization to resist encoding-based bypasses. Not a replacement for a dedicated WAF engine (e.g. ModSecurity), but the pattern list in `waf.py` can be extended without touching anything else.
- **No request logging** — only security events (blocks, failures) are logged, not normal traffic. If you need full access logs, add that upstream with nginx or similar.
