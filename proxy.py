import httpx
import os
from dotenv import load_dotenv
from fastapi import Request
from fastapi.responses import Response

load_dotenv()

def _load_routes():
    """
    Parse ROUTES from .env into a sorted list of (prefix, backend_url) tuples.
    Longest prefix first so the most specific route always wins.
    Falls back to BACKEND_URL if ROUTES is not set (single-backend mode).
    """
    routes_env = os.getenv("ROUTES", "").strip()
    if routes_env:
        routes = []
        for entry in routes_env.split(","):
            entry = entry.strip()
            if "|" not in entry:
                continue
            prefix, backend_url = entry.split("|", 1)
            routes.append((prefix.strip(), backend_url.strip()))
        routes.sort(key=lambda r: len(r[0]), reverse=True)
        return routes

    # Single-backend fallback
    backend_url = os.getenv("BACKEND_URL")
    if not backend_url:
        raise ValueError("No routes configured, Set ROUTES or BACKEND_URL in your .env file.")
    return [("/", backend_url)]
    
ROUTES = _load_routes()

def _match_route(path: str) -> str:
    """
    Find the correct backend URL for a given request path.
    Returns the backend URL of the longest matching prefix.
    Returns None if no route matches.
    """
    for prefix, backend_url in ROUTES:
        if path.startswith(prefix):
            return backend_url
    return None

async def forward_request(request: Request) -> Response:
    """
    Forwards the incoming request to the configured backend.
    Preserves: HTTP method, path, query params, headers, and body.
    Adds X-Forwarded-For so the backend knows the real client IP.
    """
    # Build the full target URL
    path = request.url.path
    query = request.url.query

    backend_url = _match_route(path)
    if backend_url is None:
        return Response(
            content=b'{"detail": "No route configured for this path"}',
            status_code=404,
            media_type="application/json"
        )

    target_url = f"{backend_url}{path}"
    if query:
        target_url += f"?{query}"

    # Copy headers from the incoming request
    headers = dict(request.headers)
    headers.pop("host", None) # Remove host header - httpx will set the correct host
    headers["X-Forwarded-For"] = request.client.host # Pass real client IP

    # Read the body (already cached from middleware, safe to read again)
    body = await request.body()

    # Forward to backend
    try:
        async with httpx.AsyncClient() as client:
            backend_response = await client.request(
                method = request.method,
                url = target_url,
                headers = headers,
                content = body,
                follow_redirects = True,
                timeout = 10.0
            )
        # Hop-by-hop headers must not be forwarded — Starlette manages these itself
        HOP_BY_HOP = {"content-length", "transfer-encoding", "connection",
                       "keep-alive", "upgrade", "proxy-authenticate",
                       "proxy-authorization", "te", "trailers"}
        safe_headers = {k: v for k, v in backend_response.headers.items()
                        if k.lower() not in HOP_BY_HOP}
        return Response(
            content = backend_response.content,
            status_code = backend_response.status_code,
            headers = safe_headers,
            media_type = backend_response.headers.get("content-type")
        )
    except httpx.ConnectError:
        return Response(
            content = b'{"detail": "Backend service is unreachable"}',
            status_code = 503,
            media_type = "application/json"
        )
    except httpx.TimeoutException:
        return Response(
            content = b'{"detail": "Backend service timed out"}',
            status_code = 504,
            media_type = "application/json"
        )
    except Exception as exc:
        print(f"[PROXY ERROR] Unexpected error forwarding to backend: {exc}")
        return Response(
            content = b'{"detail": "Internal gateway error"}',
            status_code = 500,
            media_type = "application/json"
        )
        