from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from loguru import logger
from pydantic import BaseModel
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ...core.db import get_db
from ...core.security import hash_password
from ...models.user import User
from ...services.events import add_audit
from ..deps import require_role

router = APIRouter()

ROLES = ("admin", "operator", "viewer")
MIN_PASSWORD = 8


class UserCreateIn(BaseModel):
    email: str
    password: str
    role: str = "viewer"


class UserPatchIn(BaseModel):
    role: str | None = None
    is_active: bool | None = None


class PasswordIn(BaseModel):
    password: str


def _row(u: User) -> dict:
    return {
        "id": u.id,
        "email": u.email,
        "role": u.role,
        "is_active": u.is_active,
        "created_at": u.created_at.isoformat() if u.created_at else None,
    }


def _audit(db: Session, actor: str, action: str, detail: str) -> None:
    try:
        add_audit(db, actor=actor, action=action, ip=None, detail=detail)
    except Exception as exc:  # аудит не должен ломать уже выполненную операцию
        logger.warning("audit failed: {}", exc)


def _other_active_admins(db: Session, user_id: int) -> int:
    return (
        db.query(User)
        .filter(User.role == "admin", User.is_active.is_(True), User.id != user_id)
        .count()
    )


def _get(db: Session, user_id: int) -> User:
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Пользователь не найден")
    return user


@router.get("")
def list_users(
    _: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
) -> list[dict]:
    return [_row(u) for u in db.query(User).order_by(User.id).all()]


@router.post("", status_code=status.HTTP_201_CREATED)
def create_user(
    payload: UserCreateIn,
    admin: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
) -> dict:
    login = payload.email.strip()
    if not login or len(login) > 255:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Некорректный логин")
    if payload.role not in ROLES:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Неизвестная роль")
    if len(payload.password) < MIN_PASSWORD:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, f"Пароль не короче {MIN_PASSWORD} символов"
        )
    if db.query(User).filter(User.email == login).first():
        raise HTTPException(status.HTTP_409_CONFLICT, "Такой пользователь уже есть")
    user = User(
        email=login,
        hashed_password=hash_password(payload.password),
        role=payload.role,
        is_active=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    _audit(db, admin.email, "user.create", f"{login} role={payload.role}")
    return _row(user)


@router.patch("/{user_id}")
def patch_user(
    user_id: int,
    payload: UserPatchIn,
    admin: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
) -> dict:
    user = _get(db, user_id)
    if payload.role is not None and payload.role not in ROLES:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Неизвестная роль")
    if user.id == admin.id:
        if payload.is_active is False:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Нельзя отключить самого себя")
        if payload.role is not None and payload.role != user.role:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Нельзя менять собственную роль")
    loses_admin = user.role == "admin" and user.is_active and (
        (payload.role is not None and payload.role != "admin") or payload.is_active is False
    )
    if loses_admin and _other_active_admins(db, user.id) == 0:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, "Нельзя лишить доступа последнего администратора"
        )
    if payload.role is not None:
        user.role = payload.role
    if payload.is_active is not None:
        user.is_active = payload.is_active
    db.commit()
    db.refresh(user)
    _audit(db, admin.email, "user.update", f"{user.email} role={user.role} active={user.is_active}")
    return _row(user)


@router.post("/{user_id}/reset-password")
def reset_password(
    user_id: int,
    payload: PasswordIn,
    admin: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
) -> dict[str, bool]:
    user = _get(db, user_id)
    if len(payload.password) < MIN_PASSWORD:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, f"Пароль не короче {MIN_PASSWORD} символов"
        )
    user.hashed_password = hash_password(payload.password)
    db.commit()
    _audit(db, admin.email, "user.reset_password", user.email)
    return {"ok": True}


@router.delete("/{user_id}")
def delete_user(
    user_id: int,
    admin: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
) -> dict[str, bool]:
    user = _get(db, user_id)
    if user.id == admin.id:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Нельзя удалить самого себя")
    if user.role == "admin" and user.is_active and _other_active_admins(db, user.id) == 0:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Нельзя удалить последнего администратора")
    email = user.email
    try:
        db.delete(user)
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status.HTTP_409_CONFLICT, "Пользователь связан с другими данными, лучше отключите его"
        )
    _audit(db, admin.email, "user.delete", email)
    return {"ok": True}
