"""
log_parser.py
=============

Modul ini bertugas membaca file access log web server (format "combined log
format" ala Apache/Nginx) dan mengubah setiap baris teks menjadi objek
Python yang terstruktur (LogEntry), supaya modul lain (detectors.py) bisa
memproses datanya tanpa perlu tahu soal regex atau format teks mentah.

Analogi untuk kamu yang dari Laravel: file ini mirip sebuah "Form Request"
atau "DTO mapper" — tugasnya cuma mengubah data mentah (string) menjadi
objek yang sudah divalidasi bentuknya, sebelum dipakai oleh business logic.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterator, Optional

# --- 1. Pola regex untuk combined log format -------------------------------
# Contoh baris log yang ingin kita baca:
# 203.0.113.9 - - [21/Oct/2026:10:15:32 +0700] "GET /index.php HTTP/1.1" 200 512 "-" "Mozilla/5.0"
#
# Di PHP, kamu mungkin terbiasa pakai preg_match() dengan named group
# (?P<nama>...). Python punya fitur yang SAMA PERSIS lewat module `re`.
_LOG_PATTERN = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<path>\S+) \S+" '
    r'(?P<status>\d{3}) (?P<size>\d+|-) '
    r'"(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)"'
)

_TIME_FORMAT = "%d/%b/%Y:%H:%M:%S %z"


@dataclass
class LogEntry:
    """Representasi satu baris access log yang sudah diparse.

    `@dataclass` di Python itu seperti membuat class dengan properti publik
    plus constructor otomatis — mirip kalau di PHP 8 kamu pakai
    `readonly class` + constructor promotion:

        final class LogEntry {
            public function __construct(
                public readonly string $ip,
                public readonly DateTime $timestamp,
                ...
            ) {}
        }

    Python men-generate __init__, __repr__, dan __eq__ secara otomatis dari
    daftar field di bawah ini — kita tidak perlu menulis constructor manual.
    """

    ip: str
    timestamp: datetime
    method: str
    path: str
    status: int
    size: int
    referer: str
    user_agent: str
    raw_line: str  # baris asli, disimpan untuk keperluan audit/pelaporan


def parse_line(line: str) -> Optional[LogEntry]:
    """Parse satu baris log menjadi LogEntry.

    Parameter
    ---------
    line : str
        Satu baris mentah dari file access log.

    Return
    ------
    LogEntry | None
        Mengembalikan None (bukan exception) kalau baris tidak cocok
        formatnya — ini keputusan desain: log dari dunia nyata sering
        berisi baris rusak/terpotong, dan satu baris jelek tidak boleh
        menghentikan seluruh proses analisis.

    Contoh
    ------
    >>> entry = parse_line(
    ...     '203.0.113.9 - - [21/Oct/2026:10:15:32 +0700] '
    ...     '"GET /index.php HTTP/1.1" 200 512 "-" "Mozilla/5.0"'
    ... )
    >>> entry.ip
    '203.0.113.9'
    >>> entry.status
    200
    """
    match = _LOG_PATTERN.search(line)
    if match is None:
        return None

    data = match.groupdict()
    try:
        timestamp = datetime.strptime(data["time"], _TIME_FORMAT)
    except ValueError:
        return None

    size_raw = data["size"]
    size = 0 if size_raw == "-" else int(size_raw)

    return LogEntry(
        ip=data["ip"],
        timestamp=timestamp,
        method=data["method"],
        path=data["path"],
        status=int(data["status"]),
        size=size,
        referer=data["referer"],
        user_agent=data["user_agent"],
        raw_line=line.rstrip("\n"),
    )


def iter_log_entries(file_path: str | Path) -> Iterator[LogEntry]:
    """Generator yang membaca file log baris demi baris dan menghasilkan LogEntry.

    Ini adalah konsep Python yang TIDAK ADA padanan langsungnya di PHP klasik:
    *generator function*. Karena ada kata kunci `yield` (lihat di bawah),
    fungsi ini tidak langsung membaca seluruh file ke memori. Ia membaca
    satu baris, memprosesnya, "memberikan" (yield) hasilnya ke pemanggil,
    lalu BERHENTI SEJENAK sampai pemanggil minta baris berikutnya.

    Kenapa ini penting untuk file log berukuran besar (gigabyte)?
    Karena kalau pakai `read().splitlines()` biasa, seluruh file masuk ke
    RAM sekaligus. Dengan generator, memori yang dipakai tetap kecil dan
    konstan, berapa pun ukuran filenya — karena hanya satu baris yang
    diproses pada satu waktu.

    Parameter
    ---------
    file_path : str | Path
        Lokasi file access log di disk.

    Yield
    -----
    LogEntry
        Satu per satu, hanya untuk baris yang berhasil diparse.
    """
    path = Path(file_path)
    # "with" adalah context manager: menjamin file ditutup otomatis
    # walaupun terjadi exception di tengah proses — mirip try/finally
    # otomatis. Di PHP kamu biasanya menulis fclose() manual atau
    # mengandalkan garbage collector; di Python, `with` membuatnya eksplisit
    # dan aman.
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for raw_line in handle:
            entry = parse_line(raw_line)
            if entry is not None:
                yield entry
