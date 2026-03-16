from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from auth import authenticate_user, create_access_token

app = FastAPI(title="Secure API Gateway")

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