import os
import jwt
import hashlib
import datetime
from passlib.context import CryptContext
from fastapi import HTTPException, Header, Depends
from database import get_db_connection
from dotenv import load_dotenv

load_dotenv()

# This tells passlib to use bcrypt for hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

SECRET_KEY = os.getenv("JWT_SECRET_KEY")
ALGORITHM = os.getenv("JWT_ALGORITHM")
EXPIRY_MINUTES = int(os.getenv("JWT_EXPIRY_MINUTES"))

def verify_password(plain_password, hashed_password):
    """
    Check if the plain password matches the stored hash.
    """
    return pwd_context.verify(plain_password, hashed_password)

def hash_password(plain_password):
    """
    Hash a plain password using bcrypt.
    """
    return pwd_context.hash(plain_password)

def create_access_token(username: str, role: str):
    """
    Generate a signed JWT token containing the user's identity and role.
    The token expires after EXPIRY_MINUTES minutes.
    """
    payload = {
        "sub": username,
        "role": role,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=EXPIRY_MINUTES)
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    return token

def decode_token(token: str) -> dict:
    """
    Core JWT decoding - single source of truth for the entire gateway.
    Validates signature and expiry, then checks the token blacklist.
    Called by both require_admin (Depends) and the security middleware.
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

    # Check if this token has been explicitly revoked via /logout
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "SELECT 1 FROM token_blacklist WHERE token_hash = %s AND expires_at > NOW()",
            (token_hash,)
        )
        if cursor.fetchone():
            raise HTTPException(status_code=401, detail="Token has been revoked. Please log in again.")
    finally:
        cursor.close()
        conn.close()

    return payload

def blacklist_token(token: str, exp_timestamp: int):
    """
    Adds a token to the blacklist (called on logout).
    Stores a SHA-256 hash of the token alongside its expiry datetime.
    """
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    expires_at = datetime.datetime.fromtimestamp(exp_timestamp)
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT IGNORE INTO token_blacklist (token_hash, expires_at) VALUES (%s, %s)",
            (token_hash, expires_at)
        )
        conn.commit()
    finally:
        cursor.close()
        conn.close()

def verify_token(authorization: str = Header(None)) -> dict:
    """
    FastAPI dependency: extracts and validates Bearer token from Authorization header.
    Use with Depends() on any route that requires authentication.
    """
    if not authorization:
        raise HTTPException(status_code=401, detail="Authorization header missing")
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid format: Use: Bearer <token>")
    return decode_token(authorization.split(" ")[1])

def require_admin(payload: dict = Depends(verify_token)) -> dict:
    """
    FastAPI dependancy: extends verify_token, by enforcing Admin role.
    Use with Depends() on admin-only routes.
    """
    if payload.get("role") != "Admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return payload

def authenticate_user(username: str, password: str):
    """
    Look up the user in MySQL, verify their password.
    Returns the user row if valid, None if not.
    """
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()
        if not user:
            return None
        if not verify_password(password, user["password_hash"]):
            return None
        return user
    finally:
        cursor.close()
        conn.close()

def cleanup_expired_blacklist():
    """
    Deletes token blacklist entries whose expiry has already passed.
    Expiry check before the blacklist is ever consulted.
    Called once on gateway startup.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("DELETE FROM token_blacklist WHERE expires_at <= NOW()")
        conn.commit()
        print(f"[STARTUP] Cleaned up {cursor.rowcount} expired blacklist entries.")
    except Exception as e:
        print(f"[STARTUP] Blacklist cleanup failed: {e}")
    finally:
        cursor.close()
        conn.close()