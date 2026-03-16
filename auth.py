import os
import jwt
import datetime
from passlib.context import CryptContext
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