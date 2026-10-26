"""
test_log_parser.py
===================

Unit test untuk log_parser.py. Memakai `pytest`, framework testing Python
yang paling umum dipakai — padanannya di dunia PHP adalah PHPUnit/Pest.

Perbedaan gaya penting: pytest TIDAK mengharuskan class. Cukup fungsi biasa
yang namanya diawali `test_`, dan assertion cukup pakai keyword `assert`
bawaan Python (bukan `$this->assertEquals(...)` seperti PHPUnit).
"""

from pathlib import Path

from php2shell_detect.log_parser import iter_log_entries, parse_line

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "sample_access.log"


def test_parse_line_valid_entry():
    line = (
        '203.0.113.9 - - [21/Oct/2026:10:15:32 +0700] '
        '"GET /index.php HTTP/1.1" 200 512 "-" "Mozilla/5.0"'
    )
    entry = parse_line(line)

    assert entry is not None
    assert entry.ip == "203.0.113.9"
    assert entry.method == "GET"
    assert entry.path == "/index.php"
    assert entry.status == 200
    assert entry.size == 512
    assert entry.user_agent == "Mozilla/5.0"


def test_parse_line_invalid_returns_none():
    # Baris acak yang bukan access log sama sekali.
    assert parse_line("ini bukan baris log yang valid") is None


def test_parse_line_handles_dash_size():
    line = (
        '198.51.100.1 - - [21/Oct/2026:10:00:00 +0700] '
        '"GET /ping HTTP/1.1" 204 - "-" "-"'
    )
    entry = parse_line(line)
    assert entry is not None
    assert entry.size == 0  # "-" harus dikonversi jadi 0, bukan error


def test_iter_log_entries_reads_fixture_file():
    entries = list(iter_log_entries(FIXTURE_PATH))
    # Fixture berisi 13 baris, semuanya harus valid terparse.
    assert len(entries) == 13
    assert entries[0].ip == "203.0.113.9"
    assert entries[-1].path == "/adminer.php"
