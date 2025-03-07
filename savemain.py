from fastapi import FastAPI, Depends, HTTPException, status, Form, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, EmailStr
from typing import List
from passlib.context import CryptContext
from datetime import datetime, timedelta
import jwt
import random
from sqlalchemy import Column, Integer, String, Float, ForeignKey, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship

# Configuration de la base de données
SQLALCHEMY_DATABASE_URL = "sqlite:///./test.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Configuration des templates HTML
templates = Jinja2Templates(directory="templates")

# Modèle de la base de données pour les utilisateurs
class UserDB(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    email = Column(String, unique=True, index=True)
    password = Column(String)
    phone = Column(String)
    last_name = Column(String)
    first_name = Column(String)
    orders = relationship("OrderDB", back_populates="user")

# Modèle de la base de données pour les commandes
class OrderDB(Base):
    __tablename__ = "orders"
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    product = Column(String)
    price = Column(Float, nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"))
    user = relationship("UserDB", back_populates="orders")

Base.metadata.create_all(bind=engine)

# Configuration de l'application FastAPI
app = FastAPI()

# Sécurité et Hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

# JWT Token
SECRET_KEY = "your_secret_key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# Dépendance pour récupérer la session DB
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Schémas Pydantic
class UserCreate(BaseModel):
    email: EmailStr
    password: str
    phone: str
    last_name: str
    first_name: str

class UserUpdate(BaseModel):
    phone: str
    last_name: str
    first_name: str

class UserResponse(BaseModel):
    id: int
    email: EmailStr
    phone: str
    last_name: str
    first_name: str
    orders: List[dict] = []

    class Config:
        orm_mode = True

class OrderCreate(BaseModel):
    user_id: int
    product: str
    price: float

class OrderUpdate(BaseModel):
    product: str
    price: float

class OrderResponse(BaseModel):
    id: int
    user_id: int
    product: str
    price: float

    class Config:
        orm_mode = True

# Dictionnaire des prix des produits
PRODUCT_PRICES = {
    "Smartphone": 499.00,
    "Laptop": 899.00,
    "Tablette": 299.00,
    "Écouteurs": 149.00,
    "Montre connectée": 199.00
}

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/authenticate")

@app.get("/register", response_class=HTMLResponse)
def register_form(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/authenticate")

# Route pour l'authentification
@app.post("/authenticate")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(UserDB).filter(UserDB.email == form_data.username).first()
    if not user or not verify_password(form_data.password, user.password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    access_token = create_access_token(data={"sub": user.email})
    return {"access_token": access_token, "token_type": "bearer"}

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
    except jwt.PyJWTError:
        raise credentials_exception
    user = db.query(UserDB).filter(UserDB.email == email).first()
    if user is None:
        raise credentials_exception
    return user

# CRUD Utilisateurs
@app.get("/users", response_model=List[UserResponse])
def get_users(current_user: UserDB = Depends(get_current_user), db: Session = Depends(get_db)):
    return db.query(UserDB).all()

@app.get("/users/{user_id}", response_model=UserResponse)
def get_user(user_id: int, current_user: UserDB = Depends(get_current_user), db: Session = Depends(get_db)):
    user = db.query(UserDB).filter(UserDB.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


@app.post("/users", response_model=UserResponse)
def create_user(
    email: EmailStr = Form(...),
    password: str = Form(...),
    phone: str = Form(...),
    last_name: str = Form(...),
    first_name: str = Form(...),
    db: Session = Depends(get_db)
):
    db_user = UserDB(
        email=email,
        password=hash_password(password),  # Hash le mot de passe
        phone=phone,
        last_name=last_name,
        first_name=first_name
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

@app.get("/users/{user_id}", response_model=UserResponse)
def get_user(user_id: int, db: Session = Depends(get_db)):
    user = db.query(UserDB).filter(UserDB.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


@app.put("/users/{user_id}", response_model=UserResponse)
def update_user(user_id: int, user_update: UserUpdate, db: Session = Depends(get_db)):
    user = db.query(UserDB).filter(UserDB.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    for key, value in user_update.dict().items():
        setattr(user, key, value)
    db.commit()
    db.refresh(user)
    return user

@app.delete("/users/{user_id}")
def delete_user(user_id: int, db: Session = Depends(get_db)):
    user = db.query(UserDB).filter(UserDB.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    db.delete(user)
    db.commit()
    return {"message": "User deleted successfully"}

# CRUD Commandes
@app.get("/orders", response_model=List[OrderResponse])
def get_orders(db: Session = Depends(get_db)):
    return db.query(OrderDB).all()

@app.get("/orders/{user_id}", response_model=List[OrderResponse])
def get_orders_by_user(user_id: int, db: Session = Depends(get_db)):
    return db.query(OrderDB).filter(OrderDB.user_id == user_id).all()

@app.post("/orders", response_model=OrderResponse)
def create_order(order: OrderCreate, db: Session = Depends(get_db)):
    print(order.dict())  # 🔍 Vérifie si les données arrivent correctement
    db_order = OrderDB(user_id=order.user_id, product=order.product, price=order.price)
    db.add(db_order)
    db.commit()
    db.refresh(db_order)
    return db_order




@app.put("/orders/{order_id}", response_model=OrderResponse)
def update_order(order_id: int, order_update: OrderUpdate, db: Session = Depends(get_db)):
    order = db.query(OrderDB).filter(OrderDB.id == order_id).first()
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")
    for key, value in order_update.dict().items():
        setattr(order, key, value)
    db.commit()
    db.refresh(order)
    return order

@app.delete("/orders/{order_id}")
def delete_order(order_id: int, db: Session = Depends(get_db)):
    order = db.query(OrderDB).filter(OrderDB.id == order_id).first()
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")
    db.delete(order)
    db.commit()
    return {"message": "Order deleted successfully"}
