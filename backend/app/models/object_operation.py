"""Constructor audit events contain metadata only, never config or credentials."""
from datetime import datetime
from sqlalchemy import DateTime, Integer, String, func
from sqlalchemy.orm import Mapped, mapped_column
from ..core.db import Base

class ObjectOperation(Base):
    __tablename__ = 'object_constructor_operations'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    owner_id: Mapped[int] = mapped_column(Integer, index=True, nullable=False)
    device_id: Mapped[int] = mapped_column(Integer, index=True, nullable=False)
    target_host: Mapped[str | None] = mapped_column(String(64), nullable=True)
    action: Mapped[str] = mapped_column(String(32), nullable=False)
    outcome: Mapped[str] = mapped_column(String(32), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
