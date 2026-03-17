import time
import os
from dotenv import load_dotenv

load_dotenv()

# Configuration - read from .env, with fallback defaults
MAX_REQUESTS = int(os.getenv("RATE_LIMIT_MAX_REQUESTS", 10))
WINDOW_SECONDS = int(os.getenv("RATE_LIMIT_WINDOW_SECONDS", 60))

# In-memory store: { "ip_address": [request_count, window_start_time] }
rate_limit_store = {}

def is_rate_limited(ip: str) -> bool:
    """
    Returns True if the IP has exceeded the request limit.
    Returns False if the request is allowed.
    """
    current_time = time.time()

    if ip not in rate_limit_store:
        # First time we've seen this IP - start a fresh window
        rate_limit_store[ip] = [1, current_time]
        return False

    count, window_start = rate_limit_store[ip]

    if current_time - window_start > WINDOW_SECONDS:
        # The window has expired - reset counter and start fresh
        rate_limit_store[ip] = [1, current_time]
        return False

    if count >= MAX_REQUESTS:
        # Still inside the window and limit reached - block it
        return True

    # Within window, under limit - allow it and increment counter
    rate_limit_store[ip][0] += 1
    return False