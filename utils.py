import json
import os
import bcrypt
from flask import request
from config import API_KEY

USER_FILE = "users.json"

def load_users():
    if not os.path.exists(USER_FILE):
        return []
    try:
        with open(USER_FILE, "r") as f:
            return json.load(f)
    except json.JSONDecodeError:
        return []

def save_users(users):
    with open(USER_FILE, "w") as f:
        json.dump(users, f, indent=4)

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def check_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode(), hashed.encode())

def verify_api_key():
    api_key = request.headers.get("X-API-KEY")
    return api_key == API_KEY