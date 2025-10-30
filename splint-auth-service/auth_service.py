import hashlib
import json
import os
from datetime import datetime, timedelta
import jwt
from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer
from typing import Optional, List
from pydantic import BaseModel

# --- Configuration ---
SECRET_KEY = os.getenv("SECRET_KEY", "your-default-secret-key")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = 30
# This path is correct for the self-contained service structure
USERS_JSON_PATH = "./users.json" 

app = FastAPI()

# --- User & Token Models ---
class User(BaseModel):
    username: str
    role: str

class Token(BaseModel):
    access_token: str
    token_type: str

# --- Security Dependency Setup ---
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

async def get_current_admin_user(token: str = Depends(oauth2_scheme)) -> User:
    """
    Dependency to get the current user from a token and verify they are an admin.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        role: str = payload.get("role")
        if username is None or role is None:
            raise credentials_exception
        if role != "admin":
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin privileges required")
        return User(username=username, role=role)
    except jwt.PyJWTError:
        raise credentials_exception

# --- Helper Functions ---
def load_users() -> dict:
    """Loads users from the users.json file."""
    try:
        with open(USERS_JSON_PATH, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        # If the file doesn't exist or is empty, it's a critical error for the container.
        # However, returning an empty dict allows for graceful failure.
        return {}

def save_users(users_data: dict):
    """Saves the users dictionary back to the users.json file."""
    # Note: When users.json is baked into the image, these changes will not persist
    # after the container restarts. This is acceptable for the current setup.
    # For a production system, this would write to a persistent volume or database.
    with open(USERS_JSON_PATH, "w") as f:
        json.dump(users_data, f, indent=2)

def hash_password(password: str) -> str:
    """Hashes a password using SHA-256."""
    return hashlib.sha256(password.encode()).hexdigest()

def verify_user(username, password) -> Optional[dict]:
    """Checks if a username and password are valid."""
    users = load_users()
    user_data = users.get(username)
    if not user_data or hash_password(password) != user_data.get("password"):
        return None
    return user_data

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """Creates a new JWT access token."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# --- API Endpoints ---
@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: Request):
    """Handles user login and returns a JWT token."""
    # FastAPI expects form data for OAuth2, so we read it from the request
    form = await form_data.form()
    username = form.get("username")
    password = form.get("password")
    
    user = verify_user(username, password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {"sub": username, "role": user.get("role")}
    access_token = create_access_token(data=payload, expires_delta=access_token_expires)
    return {"access_token": access_token, "token_type": "bearer"}

# --- User Management Endpoints (Admin Only) ---
@app.get("/users/all", response_model=List[User])
async def get_all_users(current_user: User = Depends(get_current_admin_user)):
    """Returns a list of all configured users."""
    users = load_users()
    return [{"username": u, "role": d.get("role")} for u, d in users.items()]

@app.post("/users/add")
async def add_user(user_data: dict, current_user: User = Depends(get_current_admin_user)):
    """Creates a new user."""
    required = ["username", "password", "role"]
    if not all(field in user_data for field in required):
        raise HTTPException(status_code=400, detail="Missing required fields.")
    
    users = load_users()
    username = user_data['username']
    if username in users:
        raise HTTPException(status_code=409, detail="Username already exists.")
    
    users[username] = {
        "password": hash_password(user_data['password']),
        "role": user_data['role']
    }
    save_users(users)
    return {"status": "success", "message": f"User '{username}' added."}

@app.post("/users/remove")
async def remove_user(user_data: dict, current_user: User = Depends(get_current_admin_user)):
    """Removes an existing user."""
    username = user_data.get('username')
    if not username:
        raise HTTPException(status_code=400, detail="Username is required.")
    if username == 'admin':
        raise HTTPException(status_code=403, detail="Cannot remove the primary admin.")
    
    users = load_users()
    if username in users:
        del users[username]
        save_users(users)
        return {"status": "success", "message": f"User '{username}' removed."}
    
    raise HTTPException(status_code=404, detail="User not found.")

