import pytest
from fastapi.testclient import TestClient
from passlib.context import CryptContext
from sqlalchemy import create_engine
from main import app
from db import User
from fastapi import status
from sqlalchemy.orm import Session, sessionmaker, declarative_base
from passlib.hash import pbkdf2_sha256

client = TestClient(app)

DATABASE_URL = "postgresql://biba:Ubuntu1@localhost/test_todo"

engine = create_engine(DATABASE_URL, echo=False)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

@pytest.fixture
def get_test_db():
    db = TestingSessionLocal()
    return db

@pytest.fixture
def test_user(get_test_db: Session):
    password_hash = pbkdf2_sha256.hash("testpassword")
    user = User(username="testuser3", password=password_hash)
    get_test_db.add(user)
    get_test_db.commit()

    # Get the user's access token
    response = client.post("/login", data={"username": "testuser3", "password": "testpassword"})
    access_token = response.json()["access_token"]

    # Return the user data
    return {"id": user.id, "username": user.username, "access_token": access_token}

def test_login_for_access_token(get_test_db: Session):
    # Create a test user
    password_hash = pbkdf2_sha256.hash("testpassword")
    user = User(username="testuser3", password=password_hash)
    get_test_db.add(user)
    get_test_db.commit()

    response = client.post("/login", data={"username": "testuser3", "password": "testpassword"})
    assert response.status_code == status.HTTP_200_OK
    assert "access_token" in response.json()

def test_register(get_test_db: Session):
    response = client.post("/register", data={"username": "testuser3", "password": "testpassword"})
    assert response.status_code == status.HTTP_200_OK
    assert response.json() == {"username": "testuser3"}

    # Try to register the same user again
    response = client.post("/register", data={"username": "testuser3", "password": "testpassword"})
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.json() == {"detail": "Username already taken"}

def test_create_task(get_test_db: Session, test_user):
    response = client.post("/tasks", data={"title": "Test Task", "description": "Test Description"}, headers={"Authorization": f"Bearer {test_user['access_token']}"})
    assert response.status_code == status.HTTP_200_OK
    assert response.json()["title"] == "Test Task"
    assert response.json()["description"] == "Test Description"

def test_assign_task_permission(get_test_db: Session, test_user, test_task):
    response = client.post(f"/tasks/{test_task['id']}/permissions", json={"user_id": test_user['id'], "permission": "чтение"}, headers={"Authorization": f"Bearer {test_user['access_token']}"})
    assert response.status_code == status.HTTP_200_OK
    assert response.json() == {"message": "Permission assigned"}

    # Try to assign a permission to a non-existent user
    response = client.post(f"/tasks/{test_task['id']}/permissions", json={"user_id": 999, "permission": "чтение"}, headers={"Authorization": f"Bearer {test_user['access_token']}"})
    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.json() == {"detail": "Task not found"}

def test_revoke_task_permission(get_test_db: Session, test_user, test_task):
    # First, assign a permission
    client.post(f"/tasks/{test_task['id']}/permissions", json={"user_id": test_user['id'], "permission": "чтение"}, headers={"Authorization": f"Bearer {test_user['access_token']}"})

    response = client.delete(f"/tasks/{test_task['id']}/permissions/{test_user['id']}", headers={"Authorization": f"Bearer {test_user['access_token']}"})
    assert response.status_code == status.HTTP_200_OK
    assert response.json() == {"message": "Permission revoked"}

    # Try to revoke a permission that does not exist
    response = client.delete(f"/tasks/{test_task['id']}/permissions/999", headers={"Authorization": f"Bearer {test_user['access_token']}"})
    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.json() == {"detail": "Task not found"}