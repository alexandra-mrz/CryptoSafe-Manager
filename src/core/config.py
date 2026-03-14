from __future__ import annotations

import json
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any


CONFIG_FILE_NAME = "config.json"


@dataclass
class AppConfig:
    # объект конфигурации для настроек, которые хранятся в локальном файле, а не в базе данных

    db_path: str = "data/cryptosafe.db"

    encryption_enabled: bool = True
    encryption_algorithm: str = "AES-256-GCM"

    clipboard_timeout_seconds: int = 30
    auto_lock_minutes: int = 5


class ConfigManager:
    def __init__(self, config_path: str | Path | None = None) -> None:
        if config_path is None:
            self._config_path = Path(CONFIG_FILE_NAME)
        else:
            self._config_path = Path(config_path)

        self.config = AppConfig()
        self.load()

    def load(self) -> None:
        if not self._config_path.is_file():
            return

        try:
            raw = self._config_path.read_text(encoding="utf-8")
            data = json.loads(raw)
        except Exception:
            return

        self.config = AppConfig(
            db_path=data.get("db_path", self.config.db_path),
            encryption_enabled=data.get(
                "encryption_enabled", self.config.encryption_enabled
            ),
            encryption_algorithm=data.get(
                "encryption_algorithm", self.config.encryption_algorithm
            ),
            clipboard_timeout_seconds=data.get(
                "clipboard_timeout_seconds", self.config.clipboard_timeout_seconds
            ),
            auto_lock_minutes=data.get(
                "auto_lock_minutes", self.config.auto_lock_minutes
            ),
        )

    def save(self) -> None:
        self._config_path.parent.mkdir(parents=True, exist_ok=True)
        data = asdict(self.config)
        text = json.dumps(data, indent=4, sort_keys=True)
        self._config_path.write_text(text, encoding="utf-8")

    def get(self, name: str) -> Any:
        return getattr(self.config, name)

    def set(self, name: str, value: Any) -> None:
        if not hasattr(self.config, name):
            raise AttributeError(f"unknown config field: {name}")

        setattr(self.config, name, value)
        self.save()


def get_default_config_manager() -> ConfigManager:
    return ConfigManager()

