from __future__ import annotations

# Sprint 7 / §13: PLAT-1 … PLAT-3

import platform
import unittest

from src.core.security.platform_security import (
    FeatureImplementation,
    delete_secret_from_keychain,
    describe_platform_features,
    keychain_available,
    linux_apparmor_enabled,
    linux_mlock,
    linux_munlock,
    linux_selinux_enabled,
    linux_systemd_available,
    load_secret_from_keychain,
    macos_gatekeeper_notarization_status,
    prompt_with_secure_desktop_fallback,
    store_secret_in_keychain,
    windows_credential_guard_available,
    windows_secure_desktop_available,
    windows_virtual_lock,
    windows_virtual_lock_available,
    windows_virtual_unlock,
)


class TestPlatFeatureCatalog(unittest.TestCase):
    def test_describe_platform_features_non_empty(self) -> None:
        features = describe_platform_features()
        self.assertTrue(features)
        for item in features:
            self.assertTrue(item.feature_id.startswith("PLAT-"))
            self.assertIn(item.implementation, FeatureImplementation)

    def test_prompt_fallback_runs_dialog(self) -> None:
        calls: list[str] = []

        def _dialog() -> int:
            calls.append("ok")
            return 1

        used, code = prompt_with_secure_desktop_fallback(_dialog)
        self.assertEqual(code, 1)
        self.assertEqual(calls, ["ok"])
        self.assertIsInstance(used, bool)


class TestPlat1Windows(unittest.TestCase):
    @unittest.skipUnless(platform.system() == "Windows", "PLAT-1: только Windows")
    def test_virtual_lock_available(self) -> None:
        self.assertTrue(windows_virtual_lock_available())

    @unittest.skipUnless(platform.system() == "Windows", "PLAT-1: только Windows")
    def test_credential_guard_available(self) -> None:
        self.assertIsInstance(windows_credential_guard_available(), bool)

    @unittest.skipUnless(platform.system() == "Windows", "PLAT-1: только Windows")
    def test_secure_desktop_probe(self) -> None:
        self.assertIsInstance(windows_secure_desktop_available(), bool)

    @unittest.skipUnless(platform.system() == "Windows", "PLAT-1: только Windows")
    def test_virtual_lock_unlock(self) -> None:
        buf = bytearray(b"secret-data")
        locked = windows_virtual_lock(buf)
        self.assertIsInstance(locked, bool)
        if locked:
            unlocked = windows_virtual_unlock(buf)
            self.assertIsInstance(unlocked, bool)

    @unittest.skipUnless(platform.system() == "Windows", "PLAT-1: только Windows")
    def test_plat1_features_in_catalog(self) -> None:
        ids = {f.feature_id for f in describe_platform_features()}
        self.assertIn("PLAT-1-secure-desktop", ids)
        self.assertIn("PLAT-1-virtual-lock", ids)


class TestPlat2MacOSKeychain(unittest.TestCase):
    @unittest.skipUnless(platform.system() == "Darwin", "PLAT-2: только macOS")
    @unittest.skipUnless(keychain_available(), "keyring недоступен")
    def test_store_load_delete_keychain(self) -> None:
        key_id = "_test_sprint7_plat2_key"
        secret = "test-secret-value"
        try:
            self.assertTrue(store_secret_in_keychain(key_id, secret))
            self.assertEqual(load_secret_from_keychain(key_id), secret)
        finally:
            delete_secret_from_keychain(key_id)
        self.assertIsNone(load_secret_from_keychain(key_id))

    @unittest.skipUnless(platform.system() == "Darwin", "PLAT-2: только macOS")
    def test_gatekeeper_status_string(self) -> None:
        status = macos_gatekeeper_notarization_status()
        self.assertIn(status, {"accepted", "rejected", "unknown", "stub", "not_applicable"})


class TestPlat3Linux(unittest.TestCase):
    @unittest.skipUnless(platform.system() == "Linux", "PLAT-3: только Linux")
    def test_mlock_munlock(self) -> None:
        buf = bytearray(b"secret-data")
        locked = linux_mlock(buf)
        self.assertIsInstance(locked, bool)
        if locked:
            unlocked = linux_munlock(buf)
            self.assertIsInstance(unlocked, bool)

    @unittest.skipUnless(platform.system() == "Linux", "PLAT-3: только Linux")
    @unittest.skipUnless(keychain_available(), "keyring недоступен")
    def test_keychain_store_load_delete(self) -> None:
        key_id = "_test_sprint7_plat3_key"
        secret = "test-secret-value"
        try:
            self.assertTrue(store_secret_in_keychain(key_id, secret))
            self.assertEqual(load_secret_from_keychain(key_id), secret)
        finally:
            delete_secret_from_keychain(key_id)
        self.assertIsNone(load_secret_from_keychain(key_id))

    @unittest.skipUnless(platform.system() == "Linux", "PLAT-3: только Linux")
    def test_linux_stubs_return_bool(self) -> None:
        self.assertIsInstance(linux_systemd_available(), bool)
        self.assertIsInstance(linux_selinux_enabled(), bool)
        self.assertIsInstance(linux_apparmor_enabled(), bool)


if __name__ == "__main__":
    unittest.main()
