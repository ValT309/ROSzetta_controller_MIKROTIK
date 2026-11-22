"""Idempotent additive migration, executed before any device jobs start."""
from sqlalchemy import text

COLUMNS = {"location": "VARCHAR(256)", "purpose": "VARCHAR(256)",
           "inventory_number": "VARCHAR(128)", "comment": "TEXT"}


def ensure_inventory_columns(engine):
    with engine.begin() as conn:
        for field, sql_type in COLUMNS.items():
            conn.execute(text(f"ALTER TABLE devices ADD COLUMN IF NOT EXISTS {field} {sql_type}"))


def normalize_inventory(data):
    if set(data) - COLUMNS.keys():
        raise ValueError("Unexpected inventory field")
    return {k: (v.strip() or None) if v is not None else None for k, v in data.items()}
