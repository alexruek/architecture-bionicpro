"""Хранилище сессий и незавершенных входов в Redis.

Ключ сессии - SHA-256 от session id, сам id в Redis не хранится.
Токены в записи сессии зашифрованы TokenCipher.
"""

import hashlib
import json
import secrets
import time
from dataclasses import dataclass, field

from redis.asyncio import Redis
from redis.exceptions import WatchError

from .crypto import TokenCipher

SESSION_PREFIX = "bionicpro:session:"
LOGIN_PREFIX = "bionicpro:login:"


def new_session_id() -> str:
    return secrets.token_urlsafe(32)


def _session_key(session_id: str) -> str:
    return SESSION_PREFIX + hashlib.sha256(session_id.encode("utf-8")).hexdigest()


@dataclass
class TokenSet:
    access_token: str
    refresh_token: str
    id_token: str
    access_expires_at: float
    refresh_expires_at: float

    @classmethod
    def from_response(cls, data: dict, now: float | None = None) -> "TokenSet":
        now = time.time() if now is None else now
        return cls(
            access_token=data["access_token"],
            refresh_token=data["refresh_token"],
            id_token=data.get("id_token", ""),
            access_expires_at=now + int(data["expires_in"]),
            refresh_expires_at=now + int(data.get("refresh_expires_in") or 0),
        )


@dataclass
class Session:
    tokens: TokenSet
    user: dict
    created_at: float = field(default_factory=time.time)


@dataclass
class Resolved:
    session_id: str
    session: Session
    raw: bytes
    # True, если пришел старый id в окне после ротации: повторно не ротируем.
    via_grace: bool


class SessionStore:
    def __init__(self, redis: Redis, cipher: TokenCipher, ttl_seconds: int, grace_seconds: int):
        self._redis = redis
        self._cipher = cipher
        self._ttl = ttl_seconds
        self._grace = grace_seconds

    # Незавершенный вход: state -> code_verifier и nonce.

    async def put_login(self, state: str, data: dict, ttl_seconds: int) -> None:
        payload = self._cipher.encrypt(json.dumps(data))
        await self._redis.set(LOGIN_PREFIX + state, payload, ex=ttl_seconds)

    async def pop_login(self, state: str) -> dict | None:
        raw = await self._redis.getdel(LOGIN_PREFIX + state)
        if raw is None:
            return None
        plain = self._cipher.decrypt(raw.decode("ascii"))
        return json.loads(plain) if plain else None

    # Сессии.

    def ttl_for(self, session: Session) -> int:
        left = int(session.tokens.refresh_expires_at - time.time())
        if session.tokens.refresh_expires_at <= 0:
            left = self._ttl
        return max(1, min(self._ttl, left))

    def _encode(self, session: Session) -> str:
        t = session.tokens
        return json.dumps(
            {
                "access_token": self._cipher.encrypt(t.access_token),
                "refresh_token": self._cipher.encrypt(t.refresh_token),
                "id_token": self._cipher.encrypt(t.id_token) if t.id_token else "",
                "access_expires_at": t.access_expires_at,
                "refresh_expires_at": t.refresh_expires_at,
                "user": session.user,
                "created_at": session.created_at,
            }
        )

    def _decode(self, raw: bytes) -> Session | str | None:
        data = json.loads(raw)
        if "rotated_to" in data:
            return self._cipher.decrypt(data["rotated_to"])
        access = self._cipher.decrypt(data["access_token"])
        refresh = self._cipher.decrypt(data["refresh_token"])
        if access is None or refresh is None:
            return None
        id_token = self._cipher.decrypt(data["id_token"]) if data["id_token"] else ""
        return Session(
            tokens=TokenSet(
                access_token=access,
                refresh_token=refresh,
                id_token=id_token or "",
                access_expires_at=data["access_expires_at"],
                refresh_expires_at=data["refresh_expires_at"],
            ),
            user=data["user"],
            created_at=data["created_at"],
        )

    async def create(self, session: Session) -> str:
        session_id = new_session_id()
        await self._redis.set(_session_key(session_id), self._encode(session), ex=self.ttl_for(session))
        return session_id

    async def resolve(self, session_id: str) -> Resolved | None:
        raw = await self._redis.get(_session_key(session_id))
        if raw is None:
            return None
        decoded = self._decode(raw)
        if isinstance(decoded, Session):
            return Resolved(session_id, decoded, raw, via_grace=False)
        if isinstance(decoded, str):
            # Отметка о ротации: следуем ровно один шаг.
            raw_new = await self._redis.get(_session_key(decoded))
            if raw_new is None:
                return None
            new = self._decode(raw_new)
            if isinstance(new, Session):
                return Resolved(decoded, new, raw_new, via_grace=True)
        return None

    async def save(self, session_id: str, session: Session) -> None:
        await self._redis.set(_session_key(session_id), self._encode(session), ex=self.ttl_for(session))

    async def rotate(self, resolved: Resolved, session: Session) -> str | None:
        """Переносит сессию на новый id, старый id становится отметкой на время grace.

        Возвращает новый id или None, если запись успели изменить параллельно.
        """
        old_key = _session_key(resolved.session_id)
        new_id = new_session_id()
        new_key = _session_key(new_id)
        marker = json.dumps({"rotated_to": self._cipher.encrypt(new_id)})
        async with self._redis.pipeline(transaction=True) as pipe:
            try:
                await pipe.watch(old_key)
                current = await pipe.get(old_key)
                if current != resolved.raw:
                    await pipe.unwatch()
                    return None
                pipe.multi()
                pipe.set(new_key, self._encode(session), ex=self.ttl_for(session))
                pipe.set(old_key, marker, ex=self._grace)
                await pipe.execute()
            except WatchError:
                return None
        return new_id

    async def delete(self, session_id: str) -> None:
        await self._redis.delete(_session_key(session_id))
