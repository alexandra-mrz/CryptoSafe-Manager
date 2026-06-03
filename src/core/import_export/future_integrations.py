from __future__ import annotations

# Sprint 6: заготовки интеграций (INT-4 — бонус, пока не реализовано)


class CloudSyncAdapter:
    # INT-4: облачная синхронизация (бонус) — пока не реализовано
    """Публичный класс CloudSyncAdapter."""
    def __init__(self) -> None:
        self.enabled = False

    def upload_vault_package(self, package_path: str) -> None:
        # загрузить пакет экспорта в облако
        """Upload vault package."""
        raise NotImplementedError("cloud sync — будущий спринт")

    def download_vault_package(self, remote_id: str) -> str:
        # скачать пакет по id
        """Download vault package."""
        raise NotImplementedError("cloud sync — будущий спринт")


class NetworkShareAdapter:
    # INT-4: сетевой обмен — пока не реализовано
    """Публичный класс NetworkShareAdapter."""
    def __init__(self) -> None:
        self.enabled = False

    def send_share_over_network(self, package: dict, recipient_host: str) -> None:
        # отправить share по сети
        """Send share over network."""
        raise NotImplementedError("network sharing — будущий спринт")
