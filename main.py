import logging
from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import List, Optional
import asyncpg
from contextlib import asynccontextmanager
import os
from dotenv import load_dotenv
from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext

load_dotenv()

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("todo-api")

DB_CONFIG = {
    "user": os.getenv("DB_USER", "postgres"),
    "password": os.getenv("DB_PASSWORD"),
    "database": os.getenv("DB_NAME", "todo_db"),
    "host": os.getenv("DB_HOST", "localhost"),
    "port": int(os.getenv("DB_PORT", "5432"))
}

db_pool = None

SECRET_KEY = os.getenv("SECRET_KEY", "my-super-secret-key-change-it")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS = 7

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def create_refresh_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    
    async with get_db() as conn:
        user = await conn.fetchrow("SELECT id, username, role FROM users WHERE username = $1", username)
        if user is None:
            raise credentials_exception
        return {"id": user["id"], "username": user["username"], "role": user["role"]}

async def get_current_admin(current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin rights required")
    return current_user

class TaskCreate(BaseModel):
    title: str = Field(..., min_length=1, max_length=200)
    description: Optional[str] = None
    priority: int = 1

class TaskResponse(BaseModel):
    id: int
    title: str
    description: Optional[str]
    priority: int
    completed: bool
    created_at: str
    updated_at: str

class TaskUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    priority: Optional[int] = None
    completed: Optional[bool] = None

class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=6)

class UserResponse(BaseModel):
    id: int
    username: str
    role: str
    created_at: str

class RefreshRequest(BaseModel):
    refresh_token: str

@asynccontextmanager
async def get_db():
    async with db_pool.acquire() as conn:
        yield conn

async def init_db():
    async with get_db() as conn:
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                hashed_password TEXT NOT NULL,
                role TEXT DEFAULT 'user',
                refresh_token TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS tasks (
                id SERIAL PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT,
                priority INTEGER DEFAULT 1,
                completed BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE
            )
        """)
        
        admin_exists = await conn.fetchval("SELECT id FROM users WHERE username = $1", "admin")
        if not admin_exists:
            hashed = get_password_hash("admin123")
            await conn.execute(
                "INSERT INTO users (username, hashed_password, role) VALUES ($1, $2, $3)",
                "admin", hashed, "admin"
            )
            logger.info("Администратор создан: admin / admin123")
        
        logger.info("База данных инициализирована")

app = FastAPI(
    title="Todo API",
    description="REST API с PostgreSQL и JWT аутентификацией",
    version="3.0.0",
    swagger_ui_parameters={"persistAuthorization": True}
)

# CORS настройки для фронтенда
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:5500", "http://localhost:5500"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
async def startup():
    global db_pool
    logger.info("Подключение к PostgreSQL...")
    db_pool = await asyncpg.create_pool(**DB_CONFIG, min_size=1, max_size=10)
    await init_db()
    logger.info("API запущен")

@app.on_event("shutdown")
async def shutdown():
    if db_pool:
        await db_pool.close()
        logger.info("Соединение с БД закрыто")

@app.get("/")
async def root():
    return {"status": "ok", "message": "Todo API работает с PostgreSQL и JWT!"}

@app.post("/register", status_code=201)
async def register(user: UserCreate):
    async with get_db() as conn:
        existing = await conn.fetchrow("SELECT id FROM users WHERE username = $1", user.username)
        if existing:
            raise HTTPException(400, "Username already registered")
        
        hashed = get_password_hash(user.password)
        row = await conn.fetchrow(
            "INSERT INTO users (username, hashed_password) VALUES ($1, $2) RETURNING id, username, role, created_at",
            user.username, hashed
        )
        logger.info(f"Пользователь {user.username} зарегистрирован")
        return {
            "id": row["id"],
            "username": row["username"],
            "role": row["role"],
            "created_at": row["created_at"].isoformat()
        }

@app.post("/login")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    async with get_db() as conn:
        user = await conn.fetchrow("SELECT * FROM users WHERE username = $1", form_data.username)
        if not user or not verify_password(form_data.password, user["hashed_password"]):
            raise HTTPException(401, "Incorrect username or password")
        
        access_token = create_access_token(data={"sub": user["username"]})
        refresh_token = create_refresh_token(data={"sub": user["username"]})
        
        await conn.execute(
            "UPDATE users SET refresh_token = $1 WHERE id = $2",
            refresh_token, user["id"]
        )
        
        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer"
        }

@app.post("/refresh")
async def refresh_token(refresh_data: RefreshRequest):
    async with get_db() as conn:
        try:
            payload = jwt.decode(refresh_data.refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
            username: str = payload.get("sub")
            if username is None:
                raise HTTPException(401, "Invalid token")
        except JWTError:
            raise HTTPException(401, "Invalid token")
        
        user = await conn.fetchrow(
            "SELECT id, username, refresh_token FROM users WHERE username = $1", 
            username
        )
        if not user or user["refresh_token"] != refresh_data.refresh_token:
            raise HTTPException(401, "Invalid refresh token")
        
        new_access_token = create_access_token(data={"sub": user["username"]})
        new_refresh_token = create_refresh_token(data={"sub": user["username"]})
        
        await conn.execute(
            "UPDATE users SET refresh_token = $1 WHERE id = $2",
            new_refresh_token, user["id"]
        )
        
        return {
            "access_token": new_access_token,
            "refresh_token": new_refresh_token,
            "token_type": "bearer"
        }

@app.post("/users", status_code=201)
async def create_user(
    user: UserCreate, 
    role: str = "user",
    current_user: dict = Depends(get_current_admin)
):
    async with get_db() as conn:
        existing = await conn.fetchrow("SELECT id FROM users WHERE username = $1", user.username)
        if existing:
            raise HTTPException(400, "Username already registered")
        
        hashed = get_password_hash(user.password)
        row = await conn.fetchrow(
            "INSERT INTO users (username, hashed_password, role) VALUES ($1, $2, $3) RETURNING id, username, role, created_at",
            user.username, hashed, role
        )
        logger.info(f"Администратор {current_user['username']} создал пользователя {user.username} с ролью {role}")
        return dict(row)

@app.get("/tasks")
async def get_tasks(
    skip: int = 0, 
    limit: int = 100, 
    completed: Optional[bool] = None,
    current_user: dict = Depends(get_current_user)
):
    async with get_db() as conn:
        if current_user["role"] == "admin":
            query = "SELECT t.*, u.username FROM tasks t LEFT JOIN users u ON t.user_id = u.id"
            params = []
        else:
            query = "SELECT t.*, u.username FROM tasks t LEFT JOIN users u ON t.user_id = u.id WHERE t.user_id = $1"
            params = [current_user["id"]]
        
        if completed is not None:
            query += " AND t.completed = $" + str(len(params) + 1)
            params.append(completed)
        
        query += " ORDER BY t.priority DESC LIMIT $" + str(len(params) + 1) + " OFFSET $" + str(len(params) + 2)
        params.extend([limit, skip])
        
        rows = await conn.fetch(query, *params)
        return [dict(row) for row in rows]

@app.post("/tasks", status_code=201)
async def create_task(task: TaskCreate, current_user: dict = Depends(get_current_user)):
    async with get_db() as conn:
        row = await conn.fetchrow(
            "INSERT INTO tasks (title, description, priority, user_id) VALUES ($1, $2, $3, $4) RETURNING *",
            task.title, task.description, task.priority, current_user["id"]
        )
        return dict(row)

@app.get("/tasks/{task_id}")
async def get_task(task_id: int, current_user: dict = Depends(get_current_user)):
    async with get_db() as conn:
        if current_user["role"] == "admin":
            row = await conn.fetchrow("SELECT * FROM tasks WHERE id = $1", task_id)
        else:
            row = await conn.fetchrow("SELECT * FROM tasks WHERE id = $1 AND user_id = $2", task_id, current_user["id"])
        if not row:
            raise HTTPException(404, "Task not found")
        return dict(row)

@app.put("/tasks/{task_id}")
async def update_task(task_id: int, task: TaskUpdate, current_user: dict = Depends(get_current_user)):
    async with get_db() as conn:
        if current_user["role"] == "admin":
            existing = await conn.fetchrow("SELECT id FROM tasks WHERE id = $1", task_id)
        else:
            existing = await conn.fetchrow("SELECT id FROM tasks WHERE id = $1 AND user_id = $2", task_id, current_user["id"])
        if not existing:
            raise HTTPException(404, "Task not found")
        
        updates = []
        params = []
        i = 1
        if task.title is not None:
            updates.append(f"title = ${i}")
            params.append(task.title)
            i += 1
        if task.description is not None:
            updates.append(f"description = ${i}")
            params.append(task.description)
            i += 1
        if task.priority is not None:
            updates.append(f"priority = ${i}")
            params.append(task.priority)
            i += 1
        if task.completed is not None:
            updates.append(f"completed = ${i}")
            params.append(task.completed)
            i += 1
        
        if not updates:
            row = await conn.fetchrow("SELECT * FROM tasks WHERE id = $1", task_id)
            return dict(row)
        
        updates.append("updated_at = CURRENT_TIMESTAMP")
        params.append(task_id)
        query = f"UPDATE tasks SET {', '.join(updates)} WHERE id = ${i} RETURNING *"
        row = await conn.fetchrow(query, *params)
        return dict(row)

@app.delete("/tasks/{task_id}")
async def delete_task(task_id: int, current_user: dict = Depends(get_current_user)):
    async with get_db() as conn:
        if current_user["role"] == "admin":
            result = await conn.execute("DELETE FROM tasks WHERE id = $1", task_id)
        else:
            result = await conn.execute("DELETE FROM tasks WHERE id = $1 AND user_id = $2", task_id, current_user["id"])
        if result == "DELETE 0":
            raise HTTPException(404, "Task not found")
        return {"status": "deleted"}

@app.get("/tasks/high-priority")
async def get_high_priority_tasks(current_user: dict = Depends(get_current_user)):
    async with get_db() as conn:
        if current_user["role"] == "admin":
            rows = await conn.fetch("SELECT * FROM tasks WHERE priority >= 4 ORDER BY priority DESC")
        else:
            rows = await conn.fetch("SELECT * FROM tasks WHERE user_id = $1 AND priority >= 4 ORDER BY priority DESC", current_user["id"])
        return [dict(row) for row in rows]

@app.get("/tasks/stats")
async def get_stats(current_user: dict = Depends(get_current_user)):
    async with get_db() as conn:
        if current_user["role"] == "admin":
            total = await conn.fetchval("SELECT COUNT(*) FROM tasks")
            completed = await conn.fetchval("SELECT COUNT(*) FROM tasks WHERE completed = true")
            avg = await conn.fetchval("SELECT AVG(priority) FROM tasks")
        else:
            total = await conn.fetchval("SELECT COUNT(*) FROM tasks WHERE user_id = $1", current_user["id"])
            completed = await conn.fetchval("SELECT COUNT(*) FROM tasks WHERE user_id = $1 AND completed = true", current_user["id"])
            avg = await conn.fetchval("SELECT AVG(priority) FROM tasks WHERE user_id = $1", current_user["id"])
        return {
            "total": total,
            "completed": completed,
            "not_completed": total - completed,
            "avg_priority": round(avg or 0, 2)
        }