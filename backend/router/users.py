from fastapi import APIRouter, HTTPException
from models.users import UserCreate

router = APIRouter(prefix="/user", tags=["user"])  #tags is for documentation. prefix places the /user pathing before including the pathing for each function. so register would be /users/register

users = []


@router.get("/register")
async def register_page():
    return {
        "message" : "Register Page",
        "fields" : {
            "email" : "string that ends with @xxx.xxx",
            "username" : "3 - 20 character long string", 
            "password" : "password with at least 8 characters"
        }

    }

@router.post("/register")
async def register_user(user: UserCreate):
    if any(u["username"] == user.username for u in users):
        raise HTTPException(status_code=400, detail="Username already taken.")
    elif any(u["email"] == user.email for u in users):
        raise HTTPException(status_code=400, detail = "Email already in use.")
    
    new_user = {
        "username": user.username,
        "email" : user.email,
        "password" : user.password #PLAIN TEXT, NEEDS HASHING
    }
    users.append(new_user)


