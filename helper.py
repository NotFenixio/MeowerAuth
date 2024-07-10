import random
import string
from typing import List
from uuid import UUID
from secrets import token_urlsafe
import requests as r
from pydantic import BaseModel


async def generate_private_code(len: int) -> str:
    return str(token_urlsafe(len))


class TimestampModel(BaseModel):
    d: str
    e: int
    h: str
    mi: str
    mo: str
    s: str
    y: str


class PostModel(BaseModel):
    _id: UUID
    attachments: List[object]
    isDeleted: bool
    p: str
    pinned: bool
    post_id: UUID
    post_origin: UUID
    t: TimestampModel


async def generate_public_code() -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=8))


async def is_valid_code(code: str) -> bool:
    return len(code) == 8 and all(
        c in string.ascii_lowercase + string.digits for c in code
    )

async def get_meower_token(username: str, password: str):
    return r.post("https://api.meower.org/auth/login", json={"username": username, "password": password}, headers={"Content-Type": "application/json"}).json()["token"]