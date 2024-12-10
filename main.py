from fastapi import Depends, FastAPI, HTTPException
from jose import jwt
from pydantic import BaseModel
from datetime import datetime, timezone, timedelta
import secrets
from fastapi.security import OAuth2PasswordBearer

app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

SECRET_KEY = secrets.token_urlsafe(32)
ALGORITHM = 'HS256'

users_db = {}

class User(BaseModel):
    username: str
    password: str


def get_expire_date(expires_delta: timedelta):
    current_date = datetime.now(timezone.utc)
    unix_timestamp = current_date.timestamp()
    return int(unix_timestamp + expires_delta.total_seconds())

def create_token(payload: dict):
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    return token


@app.get("/refresh")
def refresh(refresh_token: str):
    try:
        payload = jwt.decode(refresh_token, SECRET_KEY, algorithm=ALGORITHM)
        username = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid refresh token")
        new_access_token = create_token(payload={"sub": username, "exp": get_expire_date(timedelta(minutes=15))})
        new_refresh_token = create_token(payload={"sub": username, "exp": get_expire_date(timedelta(days=30))})
        return {"access_token": new_access_token, "refresh_token": new_refresh_token}
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Refresh token has expired")
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="Invalid refresh token")
    except Exception as e:
        print(f"Unexpected error: {e}")
        raise HTTPException(status_code=500, detail="Server error")
    

@app.post("/login")
def login(user: User):
    if user.username in users_db and user.password == users_db[user.username]:
        access_token = create_token(payload={"sub": user.username, "exp": get_expire_date(timedelta(minutes=15))})
        refresh_token = create_token(payload={"sub": user.username, "exp": get_expire_date(timedelta(days=30))})

        return {"access_token": access_token, "refresh_token": refresh_token}
    raise HTTPException(status_code=401, detail="Invalid credentials")


@app.get("/protected")
def protected_route(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithm=ALGORITHM)
        username = payload.get("sub")
        if not username:
            raise HTTPException(status_code=401, detail="Invalid token payload")
        
        return {"message": "Authorized", "username": username}
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    except Exception as e:
        print(f"Unexpected error: {e}")
        raise HTTPException(status_code=500, detail="Server error")
