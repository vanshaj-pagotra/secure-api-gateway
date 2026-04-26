from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.responses import JSONResponse, HTMLResponse
from pydantic import BaseModel
import json
import os

from auth import authenticate_user, create_access_token, decode_token, require_admin, verify_token
from waf import inspect_request, inspect_json_body
from rate_limiter import is_rate_limited
from logger import log_event
from proxy import forward_request
from database import get_db_connection

from dotenv import load_dotenv
load_dotenv()

app = FastAPI(title="Secure API Gateway")

# Load public paths once at startup
PUBLIC_PATHS = [p.strip() for p in os.getenv("PUBLIC_PATHS", "/,/login").split(",")]

# --- MIDDLEWARE ---

@app.middleware("http")
async def security_middleware(request: Request, call_next):
    """
    Runs on EVERY request before it reaches any route.
    Checks: rate limit > WAF (URL) > WAF (body) > JWT auth
    """
    client_ip = request.client.host

    # 1. Rate Limiting
    if is_rate_limited(client_ip):
        log_event("Rate_Limit", client_ip, "Rate limit exceeded.")
        return JSONResponse(
            status_code = 429,
            content = {"detail": "Too many requests. Slow down."}
        )
    
    # 2. WAF - inspect the URL/path for attack patterns
    url_check = inspect_request(str(request.url))
    if url_check["is_malicious"]:
        log_event("WAF_BLOCK", client_ip, f"{url_check['attack_type']} detected in URL")
        return JSONResponse(
            status_code = 400,
            content = {"detail": f"Blocked by WAF: {url_check['attack_type']}"}
        )

    # 3. WAF - inspect the request body (JSON content-type only)
    content_type = request.headers.get("content-type", "")
    if request.method in ("POST", "PUT", "PATCH") and "application/json" in content_type:
        try:
            body_bytes = await request.body()
            body = json.loads(body_bytes)
            body_check = inspect_json_body(body)
            if body_check["is_malicious"]:
                log_event("WAF_BLOCK", client_ip, f"{body_check['attack_type']} detected in request body")
                return JSONResponse(
                    status_code=400,
                    content = {"detail": f"Blocked by WAF: {body_check['attack_type']}"}
                )
        except json.JSONDecodeError:
            log_event("WAF_BLOCK", client_ip, "Malformed JSON body")
            return JSONResponse(
                status_code = 400,
                content = {"detail": "Invalid JSON body"}
            )

    # 4. JWT Authentication - enforce for all non-public routes
    if request.url.path not in PUBLIC_PATHS:
        auth = request.headers.get("authorization", "")
        if not auth or not auth.startswith("Bearer "):
            return JSONResponse(status_code=401, content={"detail": "Authorization required"})
        try:
            decode_token(auth.split(" ")[1])
        except HTTPException as e:
            return JSONResponse(status_code=e.status_code, content={"detail": e.detail})

    # All checks passed - forward to route handler
    response = await call_next(request)
    return response


# --- Routes ---

# This defines the shape of the login request body
class LoginRequest(BaseModel):
    username: str
    password: str

@app.get("/")
def health_check():
    """Simple endpoint to confirm the server is alive."""
    return {"status": "Secure API Gateway is running"}

@app.post("/login")
def login(request: LoginRequest):
    """
    Accepts username and password, verifies credentials,
    and returns a signed JWT token on success.
    """
    user = authenticate_user(request.username, request.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid username or password")

    token = create_access_token(username=user["username"], role=user["role"])
    return {
        "access_token": token,
        "token_type": "bearer",
        "role": user["role"]
    }

#--- Admin Routes ---

@app.get("/admin/logs")
def get_security_logs(payload: dict = Depends(require_admin)):
    """
    Admin-only: returns the 100 most recent security events from the database.
    Requires a valid JWT with role='Admin' in the Authorization header.
    """
    connection = None
    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)
        cursor.execute(
            "SELECT id, event_type, source_ip, details, timestamp "
            "FROM security_logs ORDER BY timestamp DESC LIMIT 100"
        )
        logs = cursor.fetchall()
        for log in logs:
            if log.get("timestamp"):
                log["timestamp"] = str(log["timestamp"])
        return {"total": len(logs), "logs": logs}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
    finally:
        if connection:
            connection.close()

@app.get("/admin/dashboard", response_class=HTMLResponse)
def admin_dashboard():
    """
    Serves the admin dashboard HTML page.
    Auth enforced client-side: shows login form if no JWT, fetches /admin/logs if Admin.
    """
    with open("templates/dashboard.html", "r", encoding="utf-8") as f:
        return HTMLResponse(content=f.read())

# --- Proxy: forward all other requests to backend ---

@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"])
async def proxy(request: Request, path: str):
    """Catch-all: forwards clean requests to the configured backend."""
    return await forward_request(request)