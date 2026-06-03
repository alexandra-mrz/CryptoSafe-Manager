from __future__ import annotations

# Sprint 8 / POL-1, POL-3, POL-4: polish & edge cases

import unittest

from src.gui import ux_helpers


class TestSprint8PolishUxHelpers(unittest.TestCase):
    def test_unsafe_traceback_stripped_from_ui(self) -> None:
        raw = 'Traceback (most recent call last):\n  File "src/core/x.py", line 1'
        self.assertEqual(ux_helpers._safe_message(raw), "")

    def test_exception_to_code_permission(self) -> None:
        self.assertEqual(ux_helpers.exception_to_code(PermissionError("locked")), "vault_locked")

    def test_exception_to_code_wrong_password_value_error(self) -> None:
        self.assertEqual(ux_helpers.exception_to_code(ValueError("неверный мастер-пароль")), "wrong_password")

    def test_user_hints_cover_pol4(self) -> None:
        for code in ("empty_vault", "wrong_password", "no_selection", "vault_locked", "audit_access_denied"):
            self.assertIn(code, ux_helpers.USER_HINTS)


class TestSprint8PolishEdgeCases(unittest.TestCase):
    def test_import_error_report_not_shown_as_traceback(self) -> None:
        from src.core.import_export.import_errors import build_error_report, FormatDetectionError

        report = build_error_report(FormatDetectionError("не удалось определить формат"))
        self.assertEqual(report.error_code, "format_detection_failed")
        self.assertNotIn("Traceback", report.message)
