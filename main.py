from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import json

from auth import authenticate_user, create_access_token
from waf import inspect_request, inspect_json_body
from rate_limiter import is_rate_limited
from logger import log_event
from proxy import forward_request

app = FastAPI(title="Secure API Gateway")

# --- MIDDLEWARE ---

@app.middleware("http")
async def security_middleware(request: Request, call_next):
    """
    Runs on EVERY request before it reaches any route.
    Checks: rate limit > WAF (URL) > WAF (body)
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

# --- Proxy: forward all other requests to backend ---

@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"])
async def proxy(request: Request, path: str):
    """Catch-all: forwards clean requests to the configured backend."""
    return await forward_request(request)