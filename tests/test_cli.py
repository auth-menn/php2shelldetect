"""
test_cli.py
===========

Test untuk cli.py — sebelumnya file ini tidak ada sama sekali (lihat
Temuan 6 di audit). Fokus pertama: memverifikasi perbaikan Temuan 1
(--error-threshold yang dulu diam-diam diabaikan).

Trik penting: `main()` sengaja menerima parameter `argv` opsional, jadi
test bisa memanggil `main(["--log", ...])` langsung sebagai pemanggilan
fungsi Python biasa — TIDAK perlu benar-benar membuka subprocess/terminal
baru. Ini jauh lebih cepat dan lebih mudah di-debug daripada menguji lewat
`subprocess.run(["python", "-m", ...])`.
"""

from pathlib import Path

import pytest

from php2shell_detect.cli import main

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "sample_access.log"


def test_main_returns_error_code_for_missing_log_file(tmp_path, capsys):
    missing = tmp_path / "tidak_ada.log"
    exit_code = main(["--log", str(missing)])

    assert exit_code == 1
    captured = capsys.readouterr()
    assert "tidak ditemukan" in captured.err


def test_main_rejects_zero_or_negative_error_threshold(capsys):
    exit_code = main(["--log", str(FIXTURE_PATH), "--error-threshold", "0"])

    assert exit_code == 1
    captured = capsys.readouterr()
    assert "error_threshold" in captured.err.lower() or "threshold" in captured.err.lower()


def test_error_threshold_actually_changes_detection_result(tmp_path, capsys):
    """Ini test REGRESI untuk Temuan 1: sebelum perbaikan, mengubah
    --error-threshold TIDAK mengubah apa pun pada hasil (karena nilainya
    diam-diam diabaikan). Test ini akan GAGAL kalau bug itu muncul lagi.
    """
    json_low = tmp_path / "low_threshold.json"
    json_high = tmp_path / "high_threshold.json"

    # Fixture punya IP 198.51.100.23 dengan 6 error 404 berturut-turut.
    main(["--log", str(FIXTURE_PATH), "--error-threshold", "3", "--json-out", str(json_low)])
    main(["--log", str(FIXTURE_PATH), "--error-threshold", "100", "--json-out", str(json_high)])

    import json

    findings_low = json.loads(json_low.read_text(encoding="utf-8"))
    findings_high = json.loads(json_high.read_text(encoding="utf-8"))

    rules_low = {f["rule"] for f in findings_low}
    rules_high = {f["rule"] for f in findings_high}

    # Dengan threshold 3: 6 error >= 3 -> rule ikut muncul.
    assert "high_error_rate" in rules_low
    # Dengan threshold 100: 6 error < 100 -> rule TIDAK boleh muncul lagi.
    assert "high_error_rate" not in rules_high


def test_main_succeeds_on_valid_fixture(tmp_path, capsys):
    json_out = tmp_path / "out.json"
    exit_code = main(["--log", str(FIXTURE_PATH), "--json-out", str(json_out)])

    assert exit_code == 0
    assert json_out.exists()
    captured = capsys.readouterr()
    assert "Baris log terbaca: 13" in captured.out
