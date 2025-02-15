from datetime import datetime, timedelta
from fastapi import FastAPI, Depends, HTTPException, status, Form
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
from sqlalchemy import select, insert, delete, update
from sqlalchemy.orm import Session
from typing import Optional

from db import User, Task, get_db, TokenData, Permission

app = FastAPI()

SECRET_KEY = "AOAOOAOAOAO7752151"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 300000

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

class PermissionAssignment(BaseModel):
    user_id: int
    permission: str

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """
    Создает токен с ограниченым сроком
    """
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def authenticate_user(db: Session, username: str, password: str):
    """
    Аунтификация пользователя
    """
    user = await db.execute(select(User).filter(User.username == username))
    user = user.scalar_one_or_none()
    if not user:
        return False
    if not pwd_context.verify(password, user.password):
        return False
    return user

async def get_current_user(db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)):
    """
    Дает пользователя на основе токена
    """
    credentials_exception = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = await db.execute(select(User).filter(User.username == username))
    user = user.scalar_one_or_none()
    if user is None:
        raise credentials_exception
    return user

@app.post("/login")
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    """
    Вход, который дает в ответ токен
    """
    user = await authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": user.username}, expires_delta=access_token_expires)
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/register")
async def register(username: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    """
    Регистрация нового пользователя
    """
    user = await db.execute(select(User).filter(User.username == username))
    user = user.scalar_one_or_none()
    if user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username already taken")
    hashed_password = pwd_context.hash(password)
    user = User(username=username, password=hashed_password)
    db.add(user)
    await db.commit()
    return {"username": user.username}

async def assign_permission(db: Session, task_id: int, user_id: int, permission: str):
    query = insert(Permission).values(task_id=task_id, user_id=user_id, permission=permission)
    await db.execute(query)
    await db.commit()

async def revoke_permission(db: Session, task_id: int, user_id: int):
    query = delete(Permission).where(Permission.task_id == task_id, Permission.user_id == user_id)
    await db.execute(query)
    await db.commit()

async def get_task_by_id(db: Session, task_id: int):
    task = await db.execute(select(Task).filter(Task.id == task_id))
    return task.scalar_one_or_none()

@app.post("/tasks/{task_id}/permissions")
async def assign_task_permission(task_id: int, assignment: PermissionAssignment,
                                 db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """
    Создаем новый доступ к конкретной задаче
    """
    user_id = assignment.user_id
    permission = assignment.permission
    task = await get_task_by_id(db, task_id)
    if not task:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Task not found")
    if task.owner_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="You are not the owner of this task")
    if permission not in ["read", "update", "author"]:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid permission type")
    await assign_permission(db, task_id, user_id, permission)
    return {"message": "Permissions assigned"}

@app.delete("/tasks/{task_id}/permissions/{user_id}")
async def revoke_task_permission(task_id: int, user_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """
    Изымаем доступ у пользователя к конкретной задаче
    """
    task = await get_task_by_id(db, task_id)
    if not task:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Task not found")
    if task.owner_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="You are not the owner of this task")

    await revoke_permission(db, task_id, user_id)
    return {"message": "Permissions revoked"}

async def update_task(db: Session, task_id: int, title: Optional[str] = None, description: Optional[str] = None):
    query = update(Task).where(Task.id == task_id)
    if title is not None:
        query = query.values(title=title)
    if description is not None:
        query = query.values(description=description)
    await db.execute(query)
    await db.commit()

async def has_permission(db: Session, task_id: int, user_id: int, permission: Optional[str] = None):
    if permission:
        permission_query = select(Permission).where(
            Permission.task_id == task_id, Permission.user_id == user_id, Permission.permission == permission
        )
    else:
        permission_query = select(Permission).where(
            Permission.task_id == task_id, Permission.user_id == user_id
        )
    permission = await db.execute(permission_query)
    return permission.scalar_one_or_none()

@app.put("/tasks/{task_id}")
async def update_task_route(task_id: int, title: Optional[str] = Form(None), description: Optional[str] = Form(None),
                            db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """
    Изменяем название и описание задачки
    """
    task = await get_task_by_id(db, task_id)
    if not task:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Task not found")

    if task.owner_id != current_user.id:
        has_update_permission = await has_permission(db, task_id, current_user.id, "обновление")
        has_author_permission = await has_permission(db, task_id, current_user.id, "права автора")
        if has_update_permission or has_author_permission:
            await update_task(db, task_id, title, description)
            return {"message": "Task updated"}
        else:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions to modify")
    else:
        await update_task(db, task_id, title, description)
        return {"message": "Task updated"}

@app.delete("/tasks/{task_id}")
async def delete_task(task_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """
    Удаление задачи
    """
    task = await get_task_by_id(db, task_id)

    if not task:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Task not found")

    has_author_permission = await has_permission(db, task_id, current_user.id, "права автора")
    if task.owner_id != current_user.id or has_author_permission:
        query = delete(Task).where(Task.id == task_id)
        await db.execute(query)
        await db.commit()
        return {"message": "Task deleted"}
    else:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="You are not the owner of this task, you cannot delete it.")


@app.get("/tasks/{task_id}")
async def read_task(task_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """
    Получаем содержимое задачи
    """
    task = await get_task_by_id(db, task_id)
    if not task:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Task not found")

    if task.owner_id != current_user.id:
        has_read_permission = await has_permission(db, task_id, current_user.id, "чтение")
        if not has_read_permission:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions to read")
    return task