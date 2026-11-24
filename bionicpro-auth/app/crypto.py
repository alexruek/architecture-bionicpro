"""Шифрование токенов перед записью в Redis."""

import logging

from cryptography.fernet import Fernet, InvalidToken

logger = logging.getLogger(__name__)


class TokenCipher:
    def __init__(self, key: str):
        if not key:
            # Без ключа сервис работает с ключом в памяти процесса:
            # после перезапуска сохраненные сессии не расшифровать, нужен повторный вход.
            logger.warning("TOKEN_ENCRYPTION_KEY is not set, using an ephemeral key")
            key = Fernet.generate_key().decode("ascii")
        self._fernet = Fernet(key.encode("ascii"))

    def encrypt(self, value: str) -> str:
        return self._fernet.encrypt(value.encode("utf-8")).decode("ascii")

    def decrypt(self, value: str) -> str | None:
        try:
            return self._fernet.decrypt(value.encode("ascii")).decode("utf-8")
        except (InvalidToken, ValueError):
            return None
