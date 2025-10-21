import jwt
from jwt.exceptions import InvalidTokenError
from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from models.users import UserCreate, UserInDB, TokenData, Token, UserDisplay
from typing import Annotated
from pwdlib import PasswordHash

router = APIRouter(prefix="/user", tags=["user"])

SECURITY_KEY = "8d1b9b07037322a631b3ae0adaf81b758d2ddbbf764b82275824481063f3a7cd"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 15



pwd_hash = PasswordHash.recommended()

def verify_password(password, hashed):
    return pwd_hash.verify(password, hashed)

def get_password_hash(password):
    return pwd_hash.hash(password)

def authenticate_user(users, username: str, password: str):
    user = get_user(users, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/user/token")


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECURITY_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_user(users: dict, username: str) -> UserInDB | None:
    user_dict = users.get(username)
    if user_dict:
        return UserInDB(**user_dict)
    return None

def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]): 
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
          detail="could not validate credentials", 
          headers = {"WWW-Authenticate" : "Bearer"})
    try:
        payload = jwt.decode(token, SECURITY_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except InvalidTokenError:
        raise credentials_exception
    user = get_user(users, username=token_data.username)
    if user is None:
        raise credentials_exception
    return user



@router.post("/token")
async def login(form_data: Annotated[OAuth2PasswordRequestForm, Depends()]) ->  Token:
    user = authenticate_user(users, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate" : "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return Token(access_token=access_token, token_type="bearer")

@router.get("/register")
async def register_page():
    return {
        "message" : "Register Page",
        "fields" : {
            "username" : "3 - 20 character long string",
            "full_name" : "User's full name",
            "email" : "string that ends with @xxx.xxx",
            "password" : "password with at least 8 characters"
        }

    }

@router.post("/register")
async def register_user(user: UserCreate):
    if user.username in users:
        raise HTTPException(status_code=400, detail="Username already taken.")
    elif any(u["email"] == user.email for u in users.values()):
        raise HTTPException(status_code=400, detail = "Email already in use.")
    
    hashed = pwd_hash.hash(user.password)
    new_user = {
        "username": user.username,
        "full_name" : user.full_name,
        "email" : user.email,
        "hashed_password" : hashed 
        }
    
    users[user.username] = new_user

    return users


@router.get("/me", response_model=UserDisplay)
async def profile_display(current_user: Annotated[UserInDB, Depends(get_current_user)]): 
    return current_user


users = {
    "example1" : {
        "username" : "example1",
        "full_name" : "exam ple1",
        "email" : "example1@gmail.com",
        "hashed_password" : pwd_hash.hash("exam1"),
        "disabled" : False
    },
    "example2" : {
        "username" : "example2",
        "full_name" : "exam ple2",
        "email" : "example2@gmail.com",
        "hashed_password" : pwd_hash.hash("exam2"),
        "disabled" : False
    }
}