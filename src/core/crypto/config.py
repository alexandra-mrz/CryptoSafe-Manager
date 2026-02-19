# ARC-2: Менеджер конфигураций
# Обрабатывает: путь к БД, настройки шифрования, предпочтения пользователя.
# Готов к: таймаут буфера, авто-блокировка (CFG-3 — окружения dev/prod).

import os

# Окружение: development / production
ENV = os.environ.get("CRYPTOSAFE_ENV", "development")


class Config:
    """Единая точка конфигурации приложения."""

    def __init__(self):
        self._db_path = None
        self._encryption_params = {}
        self._user_prefs = {}

    @property
    def db_path(self):
        if self._db_path is None:
            base = os.path.expanduser("~")
            if ENV == "development":
                base = os.path.join(base, ".cryptosafe_dev")
            else:
                base = os.path.join(base, ".cryptosafe")
            os.makedirs(base, exist_ok=True)
            self._db_path = os.path.join(base, "vault.db")
        return self._db_path

    @db_path.setter
    def db_path(self, value):
        self._db_path = value

    @property
    def encryption_params(self):
        return self._encryption_params

    def set_encryption_param(self, key, value):
        self._encryption_params[key] = value

    @property
    def user_prefs(self):
        return self._user_prefs

    def set_pref(self, key, value):
        self._user_prefs[key] = value

    def get_pref(self, key, default=None):
        return self._user_prefs.get(key, default)


# Глобальный экземпляр (загружается из БД при старте)
_config = None


def get_config():
    global _config
    if _config is None:
        _config = Config()
    return _config
