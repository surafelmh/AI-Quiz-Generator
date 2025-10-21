from pydantic import BaseModel, EmailStr


class UserCreate(BaseModel):
    username: str
    full_name: str | None = None
    email: EmailStr
    password: str

class UserDisplay(BaseModel):
    username: str
    full_name: str | None = None
    email: EmailStr
    disabled: bool = False

class UserInDB(BaseModel):
    username: str
    full_name: str | None = None
    email: EmailStr
    hashed_password: str
    disabled: bool = False

class Token(BaseModel):
    access_token: str
    token_type : str

class TokenData(BaseModel):
    username: str | None = None