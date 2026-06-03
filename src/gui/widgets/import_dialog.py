from __future__ import annotations

# Sprint 6 / UI-2: диалог импорта vault

import json
from pathlib import Path

from PyQt6.QtWidgets import (
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QFileDialog,
    QMessageBox,
)

from src.core.import_export.import_errors import (
    MANUAL_IMPORT_FORMATS,
    RECOVERY_MANUAL_FORMAT,
    RECOVERY_RESUME_CHECKPOINT,
    FormatDetectionError,
)
from src.core.import_export.importer import (
    DUP_SKIP,
    DUP_UPDATE,
    ImportSandbox,
    MODE_DRY_RUN,
    MODE_MERGE,
    MODE_REPLACE,
    VaultImporter,
)
from src.gui.ux_helpers import show_exception, show_user_error
from src.gui.widgets.password_entry import PasswordEntry


class ImportDialog(QDialog):
    # файл, формат, режим merge/replace и предпросмотр

    """Публичный класс ImportDialog."""
    def __init__(self, parent=None) -> None:
        # форма: файл, режим, пароль файла, таблица предпросмотра
        super().__init__(parent)
        self.setWindowTitle("Импорт в хранилище")
        self.resize(620, 480)
        self._importer = VaultImporter()
        self._file_path = ""
        self._detected_fmt = ""

        root = QVBoxLayout(self)

        file_row = QHBoxLayout()
        self.file_edit = QLineEdit(self)
        self.browse_btn = QPushButton("Обзор...", self)
        self.browse_btn.clicked.connect(self._browse_file)
        file_row.addWidget(self.file_edit)
        file_row.addWidget(self.browse_btn)
        root.addLayout(file_row)

        self.format_label = QLabel("Формат: не выбран", self)
        root.addWidget(self.format_label)

        self.format_combo = QComboBox(self)
        self.format_combo.addItem("Автоопределение", "")
        for name in MANUAL_IMPORT_FORMATS:
            self.format_combo.addItem(name, name)
        self.format_combo.currentIndexChanged.connect(self._on_manual_format_changed)
        root.addWidget(self.format_combo)

        opts = QGroupBox("Параметры", self)
        form = QFormLayout(opts)
        self.mode_combo = QComboBox(opts)
        self.mode_combo.addItem("Объединить (merge)", MODE_MERGE)
        self.mode_combo.addItem("Заменить vault (replace)", MODE_REPLACE)
        self.mode_combo.addItem("Предпросмотр (dry-run)", MODE_DRY_RUN)
        self.dup_combo = QComboBox(opts)
        self.dup_combo.addItem("Пропускать дубликаты", DUP_SKIP)
        self.dup_combo.addItem("Обновлять дубликаты", DUP_UPDATE)
        self.import_password = PasswordEntry(opts)
        form.addRow("Режим:", self.mode_combo)
        form.addRow("Дубликаты:", self.dup_combo)
        form.addRow("Пароль файла:", self.import_password)
        root.addWidget(opts)

        self.summary_label = QLabel("Сводка: —", self)
        self.summary_label.setWordWrap(True)
        root.addWidget(self.summary_label)

        root.addWidget(QLabel("Предпросмотр записей:", self))
        self.preview_table = QTableWidget(self)
        self.preview_table.setColumnCount(3)
        self.preview_table.setHorizontalHeaderLabels(["Действие", "Название", "Логин"])
        root.addWidget(self.preview_table)

        btn_row = QHBoxLayout()
        self.preview_btn = QPushButton("Предпросмотр", self)
        self.preview_btn.clicked.connect(self._run_preview)
        btn_row.addWidget(self.preview_btn)
        btn_row.addStretch(1)
        root.addLayout(btn_row)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel,
            self,
        )
        buttons.button(QDialogButtonBox.StandardButton.Ok).setText("Импорт")
        buttons.accepted.connect(self._on_import)
        buttons.rejected.connect(self.reject)
        root.addWidget(buttons)

    def _browse_file(self) -> None:
        # выбор файла и автоопределение формата
        path, _ = QFileDialog.getOpenFileName(self, "Файл импорта", "", "JSON/CSV (*.json *.csv);;Все (*)")
        if not path:
            return
        self.file_edit.setText(path)
        self._file_path = path
        self._detect_format()

    def _on_manual_format_changed(self) -> None:
        # ERR-3: ручной выбор формата
        manual = str(self.format_combo.currentData() or "")
        if manual:
            self._detected_fmt = manual
            self.format_label.setText(f"Формат (вручную): {manual}")

    def _detect_format(self) -> None:
        # IMP-1: автоопределение по содержимому файла
        if not self._file_path:
            return
        try:
            raw = Path(self._file_path).read_bytes()
            package, _auto = self._importer.load_package_from_bytes(raw, ImportSandbox())
            fmt = self._importer.resolve_import_format(
                package,
                raw_text=raw.decode("utf-8", errors="replace"),
                manual_fmt="",
            )
        except FormatDetectionError as exc:
            # ERR-3: предложить ручной выбор
            self._detected_fmt = ""
            self.format_label.setText(f"Формат не определён — выберите вручную ({exc})")
            QMessageBox.information(
                self,
                "Формат",
                "Не удалось определить формат автоматически.\nВыберите тип файла в списке ниже.",
            )
            return
        except Exception as exc:
            show_exception(self, exc, code="import_failed")
            return
        self._detected_fmt = fmt
        self.format_label.setText(f"Формат (авто): {fmt}")

    def _selected_format(self) -> str:
        # ручной формат или авто
        manual = str(self.format_combo.currentData() or "")
        return manual or self._detected_fmt

    def _run_preview(self) -> None:
        # dry-run без записи в БД
        master = ask_master_password(self)
        if master is None:
            return
        if not self._file_path:
            QMessageBox.warning(self, "Ошибка", "Выберите файл.")
            return
        try:
            result = self._importer.import_from_file(
                self._file_path,
                master_password=master,
                import_password=self.import_password.text(),
                mode=MODE_DRY_RUN,
                on_duplicate=self.dup_combo.currentData(),
                fmt=self._selected_format(),
            )
            self._fill_preview(result)
            self.summary_label.setText(
                f"Сводка: добавить {result.get('added', 0)}, "
                f"обновить {result.get('updated', 0)}, "
                f"пропустить {result.get('skipped', 0)}"
            )
        except Exception as exc:
            show_exception(self, exc, code="import_failed")

    def _fill_preview(self, result: dict) -> None:
        # таблица: действие, название, логин
        rows = result.get("preview") or []
        self.preview_table.setRowCount(len(rows))
        for i, row in enumerate(rows):
            if not isinstance(row, dict):
                continue
            self.preview_table.setItem(i, 0, QTableWidgetItem(str(row.get("action", ""))))
            self.preview_table.setItem(i, 1, QTableWidgetItem(str(row.get("title", ""))))
            self.preview_table.setItem(i, 2, QTableWidgetItem(str(row.get("username", ""))))

    def _on_import(self) -> None:
        # импорт с отчётом об ошибках и resume checkpoint
        master = ask_master_password(self)
        if master is None:
            return
        if not self._file_path:
            QMessageBox.warning(self, "Ошибка", "Выберите файл.")
            return
        mode = self.mode_combo.currentData()
        if mode == MODE_REPLACE:
            answer = QMessageBox.question(
                self,
                "Подтверждение",
                "Режим «Заменить» удалит все текущие записи. Продолжить?",
            )
            if answer != QMessageBox.StandardButton.Yes:
                return
        result = self._importer.import_from_file_safe(
            self._file_path,
            master_password=master,
            import_password=self.import_password.text(),
            mode=mode,
            on_duplicate=self.dup_combo.currentData(),
            fmt=self._selected_format(),
            resume=False,
        )
        if not result.get("success"):
            opts = ", ".join(result.get("recovery_options", []))
            msg = f"{result.get('message', 'ошибка')}\n\nВарианты: {opts}"
            if RECOVERY_RESUME_CHECKPOINT in result.get("recovery_options", []):
                answer = QMessageBox.question(
                    self,
                    "Частичный импорт",
                    msg + "\n\nПродолжить с checkpoint?",
                )
                if answer == QMessageBox.StandardButton.Yes:
                    result = self._importer.import_from_file_safe(
                        self._file_path,
                        master_password=master,
                        import_password=self.import_password.text(),
                        mode=mode,
                        on_duplicate=self.dup_combo.currentData(),
                        fmt=self._selected_format(),
                        resume=True,
                        checkpoint_path=result.get("checkpoint_path", ""),
                    )
                    if result.get("success"):
                        QMessageBox.information(
                            self,
                            "Импорт",
                            f"Добавлено: {result.get('added', 0)}\n"
                            f"Обновлено: {result.get('updated', 0)}",
                        )
                        self.accept()
                return
            if RECOVERY_MANUAL_FORMAT in result.get("recovery_options", []):
                show_user_error(self, "import_failed", result.get("message"))
            else:
                show_user_error(self, "import_failed", result.get("message"))
            return
        QMessageBox.information(
            self,
            "Импорт",
            f"Добавлено: {result.get('added', 0)}\n"
            f"Обновлено: {result.get('updated', 0)}\n"
            f"Пропущено: {result.get('skipped', 0)}",
        )
        self.accept()
