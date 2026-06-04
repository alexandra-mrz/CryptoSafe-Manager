# CryptoSafe Manager — Test Report (Sprint 8)

Generated: 2026-06-03 20:43 UTC

## Test summary

- Exit code: `0`
- Result line: `=== 127 passed, 6 skipped, 2 deselected, 1154 warnings in 102.83s (0:01:42) ===`
- Passed: **127**
- Failed: **0**
- Skipped: **6**

## Coverage

- **Total: 80.4%** (target ≥ 80%; `pytest --cov=src` + `.coveragerc`)
- Scope: all `src/` except GUI, entrypoints, stubs, QR/OS adapters (see `.coveragerc`).
- Full run: all functional tests except 2 perf micro-benchmarks.

| Module | Coverage | Covered / Total |
|--------|----------|-----------------|
| `src/__init__.py` | 100.0% | 1/1 |
| `src/core/__init__.py` | 100.0% | 1/1 |
| `src/core/audit/__init__.py` | 100.0% | 5/5 |
| `src/core/audit/audit_compliance.py` | 83.6% | 51/61 |
| `src/core/audit/audit_logger.py` | 92.2% | 94/102 |
| `src/core/audit/audit_security.py` | 78.9% | 45/57 |
| `src/core/audit/log_entry.py` | 85.8% | 109/127 |
| `src/core/audit/log_export.py` | 71.4% | 100/140 |
| `src/core/audit/log_formatters.py` | 16.9% | 11/65 |
| `src/core/audit/log_integrity.py` | 94.6% | 122/129 |
| `src/core/audit/log_signer.py` | 76.7% | 89/116 |
| `src/core/audit/log_storage.py` | 19.5% | 15/77 |
| `src/core/audit/log_verifier.py` | 95.3% | 61/64 |
| `src/core/clipboard/__init__.py` | 100.0% | 4/4 |
| `src/core/clipboard/clipboard_monitor.py` | 86.5% | 32/37 |
| `src/core/clipboard/clipboard_service.py` | 84.6% | 297/351 |
| `src/core/config.py` | 88.4% | 38/43 |
| `src/core/crypto/__init__.py` | 100.0% | 1/1 |
| `src/core/crypto/abstract.py` | 53.8% | 7/13 |
| `src/core/crypto/authentication.py` | 79.4% | 81/102 |
| `src/core/crypto/key_derivation.py` | 74.5% | 35/47 |
| `src/core/crypto/key_storage.py` | 72.3% | 94/130 |
| `src/core/crypto/memory.py` | 100.0% | 4/4 |
| `src/core/crypto/placeholder.py` | 88.2% | 15/17 |
| `src/core/events.py` | 93.0% | 40/43 |
| `src/core/import_export/__init__.py` | 100.0% | 9/9 |
| `src/core/import_export/exporter.py` | 76.5% | 199/260 |
| `src/core/import_export/formats/__init__.py` | 100.0% | 7/7 |
| `src/core/import_export/formats/bw_json_format.py` | 89.3% | 25/28 |
| `src/core/import_export/formats/csv_format.py` | 80.3% | 49/61 |
| `src/core/import_export/formats/json_format.py` | 95.0% | 19/20 |
| `src/core/import_export/formats/lastpass_csv_format.py` | 96.3% | 26/27 |
| `src/core/import_export/formats/native_json_format.py` | 76.5% | 26/34 |
| `src/core/import_export/formats/share_json_format.py` | 74.3% | 26/35 |
| `src/core/import_export/import_checkpoint.py` | 95.0% | 19/20 |
| `src/core/import_export/import_errors.py` | 97.9% | 46/47 |
| `src/core/import_export/import_security.py` | 90.0% | 18/20 |
| `src/core/import_export/importer.py` | 74.9% | 325/434 |
| `src/core/import_export/io_integration.py` | 78.5% | 102/130 |
| `src/core/import_export/io_keys.py` | 84.8% | 28/33 |
| `src/core/import_export/key_exchange.py` | 94.9% | 129/136 |
| `src/core/import_export/share_crypto.py` | 72.5% | 148/204 |
| `src/core/import_export/share_package_codec.py` | 83.3% | 20/24 |
| `src/core/import_export/sharing_service.py` | 77.7% | 167/215 |
| `src/core/key_manager.py` | 71.4% | 10/14 |
| `src/core/security/__init__.py` | 100.0% | 8/8 |
| `src/core/security/activity_monitor.py` | 84.0% | 68/81 |
| `src/core/security/integration.py` | 91.2% | 31/34 |
| `src/core/security/memory_guard.py` | 74.7% | 65/87 |
| `src/core/security/panic_mode.py` | 72.0% | 113/157 |
| `src/core/security/security_config.py` | 70.1% | 54/77 |
| `src/core/security/side_channel_protection.py` | 100.0% | 11/11 |
| `src/core/state_manager.py` | 98.4% | 123/125 |
| `src/core/vault/encryption_service.py` | 88.9% | 32/36 |
| `src/core/vault/entry_manager.py` | 87.4% | 194/222 |
| `src/core/vault/password_generator.py` | 82.8% | 82/99 |
| `src/core/vault/search_index.py` | 83.3% | 5/6 |
| `src/database/__init__.py` | 100.0% | 1/1 |
| `src/database/db.py` | 80.0% | 68/85 |
| `src/database/io_storage.py` | 97.9% | 142/145 |
| `src/database/models.py` | 84.0% | 199/237 |

## Artifacts

- `pytest_report.html` — pytest HTML report
- `coverage_html/index.html` — interactive coverage
- `coverage.json` — machine-readable coverage
- `pytest_console.txt` — full console log
