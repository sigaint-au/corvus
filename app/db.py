"""Database connections and JWT helpers for RLS."""
import json
import time

import jwt
import psycopg
from psycopg.rows import dict_row

from config import DATABASE_ADMIN_URL, DATABASE_URL, JWT_SECRET


def connect(autocommit=False):
    return psycopg.connect(DATABASE_URL, row_factory=dict_row, autocommit=autocommit)


def connect_admin(autocommit=True):
    return psycopg.connect(DATABASE_ADMIN_URL, row_factory=dict_row, autocommit=autocommit)


def jwt_json(claims: dict) -> str:
    return json.dumps(claims)


def as_user(user_id: str):
    """Connection with JWT claims set so RLS matches PostgREST."""
    conn = connect()
    claims = {"sub": str(user_id), "role": "authenticated"}
    with conn.cursor() as cur:
        cur.execute("SET ROLE authenticated")
        cur.execute("SELECT set_config('request.jwt.claims', %s, false)", (jwt_json(claims),))
    return conn


def make_jwt(user_id: str, hours=24) -> str:
    return jwt.encode(
        {
            "sub": str(user_id),
            "role": "authenticated",
            "exp": int(time.time()) + hours * 3600,
        },
        JWT_SECRET,
        algorithm="HS256",
    )
