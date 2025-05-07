"""
Апи для веб приложения генерацации расписания для КПК
"""
from datetime import datetime, timedelta, timezone
from typing import Annotated, Dict, Any, Optional
import jwt
import peewee
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jwt.exceptions import InvalidTokenError
from pydantic import BaseModel
from up import User, Role, db

app = FastAPI()

SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
OAUTH2_SCHEME = OAuth2PasswordBearer(tokenUrl="token")


class Token(BaseModel):
    """Модель для представления токена доступа."""

    access_token: str
    token_type: str


class TokenData(BaseModel):
    """Модель для хранения данных токена."""
    username: str | None = None


class TeacherInfo(BaseModel):
    """Модель для информации о преподавателе."""

    name: str
    password: str


class UserInfo(BaseModel):
    """Модель для информации о пользователе."""

    name: str
    password: str


async def get_current_user(token: Annotated[str, Depends(OAUTH2_SCHEME)]):
    """Получает текущего пользователя из токена."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        with db:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            username: str | None = payload.get("sub")
            if username is None:
                raise credentials_exception
            user = User.get(User.username == username)
            return user
    except InvalidTokenError as exc:
        raise credentials_exception from exc
    except peewee.DoesNotExist as exc:
        raise credentials_exception from exc
    except Exception as exc:
        print(f"Ошибка при получении пользователя: {exc}")
        raise credentials_exception from exc


async def get_current_active_user(
    current_user: Annotated[
        User,
        Depends(get_current_user)
        ]):
    """Возвращает активного пользователя."""
    return current_user


async def get_user_from_db(username: str):
    """Получает пользователя из базы данных по имени пользователя."""
    try:
        with db:
            user = User.get(User.username == username)
            return user
    except peewee.DoesNotExist:
        return None
    except peewee.OperationalError as exc:
        print(f"Ошибка подключения к базе данных: {exc}")
        return None


async def create_access_token(
        data: Dict[str, Any],
        expires_delta: Optional[timedelta] = None) -> str:
    """Создает токен доступа."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(
            minutes=ACCESS_TOKEN_EXPIRE_MINUTES
            )
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


@app.post("/register/")
async def create_user(user: UserInfo):
    """Регистрируем нового пользователя"""
    try:
        with db:
            student_role = Role.get(Role.name == 'Студент')
            new_user = User(
                username=user.name,
                role=student_role)
            new_user.set_password(user.password)
            new_user.save()
            return {"message": "Пользователь успешно создан"}
    except peewee.IntegrityError as exc:
        print(f"Ошибка peewee.IntegrityError при создании пользователя: {exc}")
        raise HTTPException(
            status_code=400,
            detail="Имя пользователя уже занято"
        ) from exc
    except Exception as exc:
        print(f"Ошибка при создании пользователя: {exc}")
        raise HTTPException(
            status_code=500,
            detail="Произошла ошибка"
        ) from exc


@app.post("/add_teacher/", response_model=Dict[str, str])
async def add_teacher(
    teacher: TeacherInfo,
    current_user: Annotated[User, Depends(
        get_current_active_user
        )],
) -> Dict[str, str]:
    """Добавляет нового преподавателя
    (только для сотрудников учебного отдела)"""
    try:
        with db:
            if current_user.role.name != "Сотрудник учебного отдела":
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="""Только сотрудники учебного отдела
                     могут добавлять преподавателей""",
                )
            teacher_role = Role.get(Role.name == "Преподаватель")
            new_user = User(
                username=teacher.name,
                role=teacher_role
            )
            new_user.set_password(teacher.password)
            new_user.save()
            return {"message": "Преподаватель успешно добавлен"}
    except peewee.DoesNotExist as exc:
        raise HTTPException(
            status_code=400,
            detail="Роль 'преподаватель' не найдена") from exc
    except peewee.IntegrityError as exc:
        raise HTTPException(
            status_code=400,
            detail="Имя пользователя уже занято") from exc
    except Exception as exc:
        print(f"Ошибка при добавлении преподавателя: {exc}")
        raise HTTPException(
            status_code=500,
            detail=f"Произошла ошибка: {exc}") from exc


@app.post("/token", response_model=Token)
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()]
) -> Token:
    """Создает токен доступа для аутентифицированного пользователя."""
    try:
        with db:
            user = await get_user_from_db(form_data.username)
            if not user or not user.check_password(form_data.password):

                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Incorrect username or password",
                    headers={"WWW-Authenticate": "Bearer"},)
            access_token_expires = timedelta(
                minutes=ACCESS_TOKEN_EXPIRE_MINUTES
            )
            access_token = create_access_token(
                data={"sub": user.username}, expires_delta=access_token_expires
            )
            return Token(
                access_token=access_token,
                token_type="bearer"
            )

    except peewee.DoesNotExist as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


@app.get("/users/me/", response_model=UserInfo)
async def read_users_me(
    current_user: Annotated[User, Depends(get_current_active_user)]
) -> UserInfo:
    """Возвращает информацию о текущем пользователе."""
    try:
        return UserInfo(name=current_user.username, password="")
    except Exception as exc:
        print(f"Ошибка при получении данных пользователя: {exc}")
        raise HTTPException(
            status_code=500,
            detail=f"Ошибка при получении данных пользователя: {exc}") from exc


@app.get("/users/me/", response_model=UserInfo)
async def read_me(
    current_user: Annotated[User, Depends(get_current_active_user)]
) -> UserInfo:
    """Возвращает информацию о текущем пользователе, включая роль."""
    try:
        return UserInfo(
            name=current_user.username,
            password="",
            role=current_user.role.name,
        )
    except Exception as exc:
        print(f"Ошибка при получении данных пользователя: {exc}")
        raise HTTPException(
            status_code=500,
            detail=f"Ошибка при получении данных пользователя: {exc}"
        ) from exc
