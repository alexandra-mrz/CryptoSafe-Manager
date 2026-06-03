from __future__ import annotations

# Sprint 7: security hardening layer (ARC-1)

from src.core.security.activity_monitor import ActivityMonitor
from src.core.security.memory_guard import SecureMemory, secure_wipe, stack_canary_ok, wipe_local
from src.core.security.panic_mode import PanicMode
from src.core.security.security_config import (
    PROFILE_ENHANCED,
    PROFILE_PARANOID,
    PROFILE_STANDARD,
    SecuritySettings,
    apply_profile,
    validate_settings,
)
from src.core.security.side_channel_protection import constant_time_compare
from src.core.security.platform_security import (
    keychain_available,
    lock_memory,
    unlock_memory,
    store_secret_in_keychain,
    load_secret_from_keychain,
    describe_platform_features,
    prompt_with_secure_desktop_fallback,
)

__all__ = [
    "ActivityMonitor",
    "PanicMode",
    "SecureMemory",
    "SecuritySettings",
    "PROFILE_STANDARD",
    "PROFILE_ENHANCED",
    "PROFILE_PARANOID",
    "apply_profile",
    "constant_time_compare",
    "secure_wipe",
    "stack_canary_ok",
    "wipe_local",
    "validate_settings",
    "keychain_available",
    "lock_memory",
    "unlock_memory",
    "store_secret_in_keychain",
    "load_secret_from_keychain",
    "describe_platform_features",
    "prompt_with_secure_desktop_fallback",
]
