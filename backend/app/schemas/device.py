from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class DeviceBase(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    host: str
    port: int = Field(default=8729, ge=1, le=65535)
    use_tls: bool = True
    username: str
    kind: str = "router"
    group_name: str | None = None


class DeviceCreate(DeviceBase):
    username: str = ""
    password: str = ""
    tls_fingerprint: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    credential_id: int | None = None   # сохранённая учётная запись вместо логина/пароля
    # пусто = взять из system identity (при недоступности устройства: host)
    name: str = Field(default="", max_length=128)


class DeviceUpdate(BaseModel):
    tls_fingerprint: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    name: str | None = None
    host: str | None = None
    port: int | None = Field(default=None, ge=1, le=65535)
    use_tls: bool | None = None
    username: str | None = None
    password: str | None = None
    kind: str | None = None
    group_name: str | None = None
    monitored_interfaces: str | None = None
    uplink_interfaces: str | None = None
    interface_history_hours: int | None = None


class DeviceInventory(BaseModel):
    location: str | None = Field(default=None, max_length=256)
    purpose: str | None = Field(default=None, max_length=256)
    inventory_number: str | None = Field(default=None, max_length=128)
    comment: str | None = Field(default=None, max_length=4000)

    model_config = {"extra": "forbid"}


class DeviceOut(DeviceBase, DeviceInventory):
    id: int
    tls_fingerprint: str | None = None
    identity: str | None = None
    model: str | None = None
    serial: str | None = None
    ros_version: str | None = None
    architecture: str | None = None
    status: str
    last_error: str | None = None
    last_seen: datetime | None = None
    internet_ok: bool | None = None
    last_uptime_seconds: int | None = None
    abnormal_reboot: bool = False
    last_log_warning: str | None = None
    monitored_interfaces: str | None = None
    uplink_interfaces: str | None = None
    interface_history_hours: int = 24
    created_at: datetime

    class Config:
        from_attributes = True


class DeviceResource(BaseModel):
    """Срез `/system/resource`."""
    cpu_load: int | None = None
    free_memory: int | None = None
    total_memory: int | None = None
    uptime: str | None = None
    version: str | None = None
    board_name: str | None = None
    architecture_name: str | None = None
