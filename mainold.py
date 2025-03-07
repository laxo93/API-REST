from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr
from typing import List
from passlib.context import CryptContext
from datetime import datetime, timedelta
import jwt

# App initialization
app = FastAPI()

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

# JWT Token settings
SECRET_KEY = "your_secret_key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# User & Order Models
class User(BaseModel):
    id: int
    email: EmailStr
    password: str
    phone: str
    address: str

class UserInDB(User):
    password: str

class UserResponse(BaseModel):
    id: int
    email: EmailStr
    phone: str
    address: str

class Order(BaseModel):
    id: int
    product: str
    price: float
    description: str

# Fake Database
users_db = {}
orders_db = {}

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")

# Auth Route
@app.post("/token")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = users_db.get(form_data.username)
    if not user or not verify_password(form_data.password, user["password"]):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    
    access_token = create_access_token(data={"sub": user["email"]})
    return {"access_token": access_token, "token_type": "bearer"}

# Users Routes
@app.post("/users", response_model=UserResponse)
def create_user(user: User):
    if user.email in users_db:
        raise HTTPException(status_code=400, detail="User already exists")
    
    users_db[user.email] = {"id": len(users_db) + 1, "email": user.email, "password": hash_password(user.password), "phone": user.phone, "address": user.address}
    return UserResponse(**users_db[user.email])

@app.get("/users", response_model=List[UserResponse])
def get_users():
    return [UserResponse(**user) for user in users_db.values()]

# Orders Routes
@app.post("/orders", response_model=Order)
def create_order(order: Order):
    orders_db[order.id] = order.dict()
    return order

@app.get("/orders", response_model=List[Order])
def get_orders():
    return list(orders_db.values())

@app.delete("/orders/{order_id}", response_model=Order)
def delete_order(order_id: int):
    if order_id not in orders_db:
        raise HTTPException(status_code=404, detail="Order not found")
    return orders_db.pop(order_id)
