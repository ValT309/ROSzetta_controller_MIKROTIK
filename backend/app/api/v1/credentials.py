from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ...core.db import get_db
from ...core.security import encrypt_secret
from ...models.credential import CredentialProfile
from ...models.user import User
from ..deps import require_role

router = APIRouter()


class CredentialIn(BaseModel):
    name: str
    username: str
    password: str


def _row(c: CredentialProfile) -> dict:
    # пароль наружу не отдаётся никогда
    return {
        "id": c.id,
        "name": c.name,
        "username": c.username,
        "created_at": c.created_at.isoformat() if c.created_at else None,
    }


def _clean(value: str, field: str, max_len: int) -> str:
    v = value.strip()
    if not v or len(v) > max_len or any(ord(ch) < 32 for ch in v):
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            f"{field}: от 1 до {max_len} символов, без управляющих символов",
        )
    return v


@router.get("")
def list_credentials(
    _: User = Depends(require_role("admin", "operator")),
    db: Session = Depends(get_db),
) -> list[dict]:
    return [_row(c) for c in db.query(CredentialProfile).order_by(CredentialProfile.name).all()]


@router.post("", status_code=status.HTTP_201_CREATED)
def create_credential(
    payload: CredentialIn,
    _: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
) -> dict:
    name = _clean(payload.name, "Название", 128)
    username = _clean(payload.username, "Логин", 64)
    pwd = payload.password
    if not pwd or len(pwd) > 128 or any(ord(ch) < 32 for ch in pwd):
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "Пароль: от 1 до 128 символов, без управляющих символов",
        )
    if db.query(CredentialProfile).filter(CredentialProfile.name == name).first():
        raise HTTPException(status.HTTP_409_CONFLICT, "Запись с таким названием уже есть")
    c = CredentialProfile(name=name, username=username, password_enc=encrypt_secret(pwd))
    db.add(c)
    db.commit()
    db.refresh(c)
    return _row(c)


@router.delete("/{cred_id}", status_code=status.HTTP_204_NO_CONTENT, response_class=Response)
def delete_credential(
    cred_id: int,
    _: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
) -> Response:
    c = db.get(CredentialProfile, cred_id)
    if not c:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Запись не найдена")
    db.delete(c)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
