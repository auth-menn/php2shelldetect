"""
test_detectors.py
==================

Test untuk setiap rule deteksi di detectors.py, pakai data sintetis
(bukan dari sistem nyata). Setiap test fokus menguji SATU rule saja,
supaya kalau ada yang gagal, kita langsung tahu rule mana yang bermasalah.
"""

from datetime import datetime, timedelta, timezone
from pathlib import Path

from php2shell_detect.detectors import (
    detect_high_error_rate,
    detect_known_shell_paths,
    detect_scanner_user_agent,
    detect_suspicious_query_params,
    run_all_detectors,
    run_all_detectors_streaming,
)
from php2shell_detect.log_parser import LogEntry, iter_log_entries

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "sample_access.log"


def _make_entry(ip: str, path: str, status: int, timestamp: datetime, **overrides) -> LogEntry:
    """Helper untuk membuat LogEntry langsung di memori (tanpa file log),
    supaya test skenario khusus (mis. error tersebar jauh di waktu) tidak
    perlu menambah baris ke fixture file bersama.
    """
    defaults = dict(
        method="GET",
        size=0,
        referer="-",
        user_agent="Mozilla/5.0",
        raw_line="(synthetic entry for test)",
    )
    defaults.update(overrides)
    return LogEntry(ip=ip, timestamp=timestamp, path=path, status=status, **defaults)


def _load_entries():
    return list(iter_log_entries(FIXTURE_PATH))


def test_detect_known_shell_paths_finds_shell_php_and_adminer():
    entries = _load_entries()
    findings = detect_known_shell_paths(entries)
    paths_found = {f.path for f in findings}

    assert "/uploads/shell.php" in paths_found
    assert "/adminer.php" in paths_found
    # Request normal tidak boleh ikut ter-flag (no false positive di fixture ini)
    assert "/index.php" not in paths_found


def test_detect_known_shell_paths_does_not_flag_legitimate_upload_feature():
    """Regression test untuk Temuan 2: dulu hint 'upload.php' membuat
    fitur upload LEGIT (mis. endpoint upload foto profil) ikut ter-flag
    severity 'high'. Setelah hint itu dihapus, path seperti ini harus
    lolos tanpa temuan.
    """
    entry = _make_entry(
        ip="192.0.2.1",
        path="/profile/image_upload.php",
        status=200,
        timestamp=datetime(2026, 10, 21, 9, 0, 0, tzinfo=timezone.utc),
    )
    findings = detect_known_shell_paths([entry])
    assert findings == []


def test_detect_suspicious_query_params_finds_system_call():
    entries = _load_entries()
    findings = detect_suspicious_query_params(entries)

    assert len(findings) == 1
    assert "system(whoami)" in findings[0].path


def test_detect_high_error_rate_flags_scanning_ip():
    entries = _load_entries()
    findings = detect_high_error_rate(entries, threshold=5)

    assert len(findings) == 1
    assert findings[0].ip == "198.51.100.23"
    assert findings[0].evidence_count == 6


def test_detect_high_error_rate_respects_threshold():
    entries = _load_entries()
    # Threshold dinaikkan di atas jumlah error asli (6) -> tidak ada temuan.
    findings = detect_high_error_rate(entries, threshold=10)
    assert findings == []


def test_detect_high_error_rate_includes_timestamp():
    """Regression test untuk Temuan 3: Finding sekarang wajib membawa
    timestamp kejadian, bukan cuma ip/path tanpa konteks waktu.
    """
    entries = _load_entries()
    findings = detect_high_error_rate(entries, threshold=5)

    assert len(findings) == 1
    assert findings[0].timestamp is not None
    # Timestamp yang dilaporkan harus berupa salah satu timestamp error asli
    # dari IP tersebut (bukan nilai default/placeholder yang asal ditaruh).
    assert findings[0].timestamp.year == 2026


def test_detect_high_error_rate_burst_within_window_is_high_severity():
    """Temuan 5 - skenario BURST: 5 error dari IP yang sama, semuanya
    terjadi dalam rentang 2 menit -> harus severity 'high'.
    """
    base = datetime(2026, 10, 21, 10, 0, 0, tzinfo=timezone.utc)
    entries = [
        _make_entry("203.0.113.50", f"/notfound{i}", 404, base + timedelta(seconds=i * 10))
        for i in range(5)
    ]
    findings = detect_high_error_rate(entries, threshold=5, window_minutes=5)

    assert len(findings) == 1
    assert findings[0].severity == "high"
    assert findings[0].evidence_count == 5


def test_detect_high_error_rate_diffuse_errors_stay_medium_severity():
    """Temuan 5 - skenario TERSEBAR: 5 error dari IP yang sama, tapi
    masing-masing berjarak 1 hari (bukan burst) -> harus tetap severity
    'medium', BUKAN 'high', walaupun totalnya memenuhi threshold.
    Ini membuktikan pemisahan indikator-lemah vs bukti-kuat benar-benar
    berfungsi, bukan cuma total count yang dihitung.
    """
    base = datetime(2026, 10, 1, 10, 0, 0, tzinfo=timezone.utc)
    entries = [
        _make_entry("203.0.113.60", f"/notfound{i}", 404, base + timedelta(days=i))
        for i in range(5)
    ]
    findings = detect_high_error_rate(entries, threshold=5, window_minutes=5)

    assert len(findings) == 1
    assert findings[0].severity == "medium"
    assert findings[0].evidence_count == 5


def test_detect_high_error_rate_legacy_behavior_without_window():
    """Tanpa window_minutes sama sekali (default None), perilaku lama
    dipertahankan: severity selalu 'medium' walaupun errornya burst.
    Ini membuktikan perubahan Temuan 5 tidak merusak kompatibilitas mundur.
    """
    base = datetime(2026, 10, 21, 10, 0, 0, tzinfo=timezone.utc)
    entries = [
        _make_entry("203.0.113.70", f"/notfound{i}", 404, base + timedelta(seconds=i))
        for i in range(5)
    ]
    findings = detect_high_error_rate(entries, threshold=5)  # window_minutes=None

    assert len(findings) == 1
    assert findings[0].severity == "medium"


def test_detect_scanner_user_agent_flags_sqlmap_and_empty_ua():
    entries = _load_entries()
    findings = detect_scanner_user_agent(entries)
    ips_found = {f.ip for f in findings}

    assert "198.51.100.23" in ips_found  # sqlmap UA
    assert "203.0.113.77" in ips_found   # UA kosong ("-")


def test_write_json_report_creates_missing_parent_dir(tmp_path):
    """Regression test: write_json_report dulu pernah crash (FileNotFoundError)
    kalau folder tujuan belum ada. `tmp_path` adalah fixture bawaan pytest:
    folder temporary unik yang otomatis dibersihkan setelah test selesai —
    jadi kita tidak mengotori filesystem asli.
    """
    from php2shell_detect.report import write_json_report
    from php2shell_detect.detectors import Finding

    target = tmp_path / "nested" / "that" / "does_not_exist_yet" / "out.json"
    findings = [
        Finding(
            rule="x",
            severity="low",
            ip="1.2.3.4",
            path="/a",
            detail="d",
            timestamp=datetime(2026, 10, 21, 9, 0, 0, tzinfo=timezone.utc),
        )
    ]

    write_json_report(findings, target)

    assert target.exists()


def test_run_all_detectors_combines_every_rule():
    entries = _load_entries()
    findings = run_all_detectors(entries)

    rules_triggered = {f.rule for f in findings}
    assert rules_triggered == {
        "known_shell_path",
        "suspicious_query_param",
        "high_error_rate",
        "scanner_user_agent",
    }


def test_run_all_detectors_streaming_matches_list_based_result():
    """Regression test untuk Temuan 4: versi streaming (satu kali iterasi,
    cocok untuk generator) harus menghasilkan temuan yang SAMA PERSIS
    dengan versi list-based lama, hanya cara bacanya yang berbeda.
    """
    findings_list_based = run_all_detectors(_load_entries(), error_threshold=5)
    findings_streaming = run_all_detectors_streaming(
        iter_log_entries(FIXTURE_PATH),  # generator asli, BUKAN list
        error_threshold=5,
    )

    # Urutan bisa sedikit berbeda (dict tidak selalu seurutan list), jadi
    # kita bandingkan sebagai himpunan pasangan (rule, ip, path), bukan
    # urutan list mentah.
    def _fingerprint(findings):
        return sorted((f.rule, f.ip, f.path) for f in findings)

    assert _fingerprint(findings_list_based) == _fingerprint(findings_streaming)


def test_run_all_detectors_streaming_only_reads_entries_once():
    """Pembuktian eksplisit bahwa run_all_detectors_streaming benar-benar
    hanya butuh SATU kali baca: generator yang sudah habis dipakai sekali
    tidak akan menyebabkan error atau hasil kosong yang tidak terduga
    kalau diberikan langsung (bukan generator yang sudah "mati").
    """

    def _single_use_generator():
        """Generator biasa: begitu habis diiterasi, tidak bisa diulang."""
        yield from iter_log_entries(FIXTURE_PATH)

    findings = run_all_detectors_streaming(_single_use_generator(), error_threshold=5)
    rules_triggered = {f.rule for f in findings}
    assert rules_triggered == {
        "known_shell_path",
        "suspicious_query_param",
        "high_error_rate",
        "scanner_user_agent",
    }
