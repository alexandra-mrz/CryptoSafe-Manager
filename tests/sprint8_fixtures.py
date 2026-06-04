from __future__ import annotations

# Sprint 8: общие фикстуры для pytest (TEST-1 / TEST-2)

import tempfile
from pathlib import Path
from typing import Iterator
from unittest.mock import patch

import pytest

from src.core.crypto.authentication import set_master_password, unlock_session
from src.core.audit.log_signer import cache_audit_signing_key
from src.core.vault.entry_manager import EntryManager
from src.database import models
from src.database.db import Database

MASTER_PASSWORD = "Sprint8!Fixture1"


@pytest.fixture
def temp_db_path(tmp_path: Path) -> Path:
    """Путь к временной SQLite с полной схемой (миграции Sprint 6)."""
    path = tmp_path / "fixture.db"
    models.initialize_database(path)
    return path


@pytest.fixture
def temp_database(temp_db_path: Path) -> Iterator[Database]:
    """Изолированная БД без пула (для unit-тестов)."""
    yield Database(temp_db_path, use_pool=False)


@pytest.fixture
def patched_io_db(temp_database: Database) -> Iterator[Database]:
    """Патч get_default_database для io_storage и key_storage."""
    with patch("src.database.io_storage.get_default_database", return_value=temp_database), patch(
        "src.core.crypto.key_storage.get_default_database", return_value=temp_database
    ):
        yield temp_database


@pytest.fixture
def vault_key() -> bytes:
    return b"\x42" * 32


@pytest.fixture
def entry_manager(temp_database: Database, vault_key: bytes) -> Iterator[EntryManager]:
    """EntryManager с разблокированной сессией и фиксированным ключом шифрования."""
    patchers = [
        patch("src.core.vault.entry_manager.is_session_unlocked", return_value=True),
        patch("src.core.key_manager.KeyManager.get_vault_encryption_key", return_value=vault_key),
        patch("src.core.crypto.authentication.verify_master_password", return_value=True),
        patch("src.core.import_export.exporter.get_event_bus"),
        patch("src.core.import_export.importer.get_event_bus"),
        patch("src.core.import_export.sharing_service.get_event_bus"),
    ]
    for p in patchers:
        p.start()
    set_master_password(MASTER_PASSWORD)
    unlock_session(MASTER_PASSWORD)
    cache_audit_signing_key(MASTER_PASSWORD)
    mgr = EntryManager(db=temp_database)
    yield mgr
    for p in reversed(patchers):
        p.stop()


@pytest.fixture
def temp_dir_context() -> Iterator[tempfile.TemporaryDirectory[str]]:
    tmp = tempfile.TemporaryDirectory()
    yield tmp
    tmp.cleanup()
