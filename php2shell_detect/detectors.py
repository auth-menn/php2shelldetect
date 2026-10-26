"""
detectors.py
============

Modul ini berisi heuristik DETEKSI (bukan eksploitasi). Semua fungsi di
sini bersifat read-only: menerima daftar LogEntry, lalu mengembalikan
daftar Finding (temuan) kalau ada pola yang mencurigakan.

Prinsip desain: setiap detector adalah fungsi kecil dan independen (mirip
single-responsibility di Laravel), supaya mudah ditambah/diuji satu per
satu tanpa mengganggu yang lain.

PENTING (batasan proyek): modul ini sengaja TIDAK memuat payload,
exploit, atau mekanisme serangan apa pun. Pola yang dicari di sini adalah
indikator permukaan (surface-level indicators) yang lazim dipakai di
rule WAF/IDS publik (ModSecurity CRS, Suricata, dll.) — bukan cara
melakukan serangan, melainkan cara MENGENALI jejaknya di log.
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Iterable
from urllib.parse import urlparse, parse_qs

from .log_parser import LogEntry


@dataclass
class Finding:
    """Satu temuan hasil deteksi.

    Mirip exception custom di PHP (`class SuspiciousRequestFound extends
    Exception`), tapi di sini kita pakai sebagai *data*, bukan untuk
    dilempar (throw) — cukup dikumpulkan dalam list dan dilaporkan.

    PERBAIKAN (audit Temuan 3): field `timestamp` ditambahkan karena
    sebelumnya laporan JSON/CSV sama sekali tidak mencatat KAPAN request
    mencurigakan terjadi — padahal LogEntry sudah punya info ini sejak
    awal, cuma tidak pernah diteruskan ke Finding.
    """

    rule: str              # nama rule yang memicu, misalnya "known_shell_path"
    severity: str           # "low" | "medium" | "high"
    ip: str
    path: str
    detail: str
    timestamp: datetime
    evidence_count: int = 1

    def to_dict(self) -> dict:
        """Ubah jadi dict biasa, supaya mudah di-serialize ke JSON.

        `datetime.isoformat()` mengubah objek datetime jadi string standar
        ISO 8601 (mis. "2026-10-21T10:15:32+07:00"), karena json.dump()
        bawaan Python tidak tahu cara menyerialisasi objek datetime secara
        langsung — ini setara dengan `$dt->format(DATE_ATOM)` di PHP.
        """
        return {
            "rule": self.rule,
            "severity": self.severity,
            "ip": self.ip,
            "path": self.path,
            "detail": self.detail,
            "timestamp": self.timestamp.isoformat(),
            "evidence_count": self.evidence_count,
        }


# --- Daftar indikator (signature) sederhana --------------------------------
# Ini adalah pola permukaan yang umum dipublikasikan di rule WAF open-source,
# dipakai untuk MENGENALI jejak di log — bukan instruksi untuk membuatnya.
#
# PERBAIKAN (audit Temuan 2): "upload.php" DIHAPUS dari daftar ini. Ia
# terlalu umum sebagai substring (cocok dengan "fileupload.php",
# "image_upload.php", dst — fitur upload yang benar-benar legit di banyak
# aplikasi Laravel), sehingga menyebabkan false positive tinggi. Nama
# file di bawah ini jauh lebih spesifik/jarang muncul di aplikasi legit.
_SUSPICIOUS_PATH_HINTS = (
    "cmd.php", "shell.php", "adminer.php", "phpinfo.php",
)
_SUSPICIOUS_QUERY_FUNCS = (
    "system", "exec", "passthru", "shell_exec", "eval", "base64_decode",
    "assert", "proc_open",
)
_SCANNER_UA_HINTS = ("sqlmap", "nikto", "nmap", "masscan", "acunetix", "")

# Compile sekali di level modul (bukan di dalam fungsi) supaya tidak
# dikompilasi ulang setiap kali fungsi dipanggil — penting karena fungsi
# per-entry di bawah ini akan dipanggil sekali untuk SETIAP baris log.
_SUSPICIOUS_QUERY_PATTERN = re.compile(
    r"(" + "|".join(re.escape(f) for f in _SUSPICIOUS_QUERY_FUNCS) + r")\s*\(",
    re.IGNORECASE,
)


# --- Fungsi "per-entry": mengecek SATU LogEntry, hasilnya Finding | None ---
# PERBAIKAN (audit Temuan 4): logika pencocokan di tiga rule ini diekstrak
# jadi fungsi kecil berdiri sendiri, supaya bisa dipakai BERSAMA oleh dua
# gaya pemanggilan tanpa duplikasi kode:
#   1. detect_known_shell_paths(entries) dkk. di bawah -- gaya lama,
#      menerima list, dipakai oleh test yang sudah ada.
#   2. run_all_detectors_streaming() -- gaya baru, memproses satu entry
#      sekali lewat tanpa pernah menyimpan seluruh log ke memori.


def _check_known_shell_path(entry: LogEntry) -> Finding | None:
    lowered = entry.path.lower()
    for hint in _SUSPICIOUS_PATH_HINTS:
        if hint in lowered:
            return Finding(
                rule="known_shell_path",
                severity="high",
                ip=entry.ip,
                path=entry.path,
                detail=f"Path mengandung indikator dikenal: '{hint}'",
                timestamp=entry.timestamp,
            )
    return None


def _check_suspicious_query_param(entry: LogEntry) -> Finding | None:
    parsed = urlparse(entry.path)
    query_params = parse_qs(parsed.query)
    for _, values in query_params.items():
        for value in values:
            if _SUSPICIOUS_QUERY_PATTERN.search(value):
                return Finding(
                    rule="suspicious_query_param",
                    severity="high",
                    ip=entry.ip,
                    path=entry.path,
                    detail="Query string berisi pola fungsi PHP sensitif",
                    timestamp=entry.timestamp,
                )
    return None


def _check_scanner_user_agent(entry: LogEntry) -> Finding | None:
    ua_lower = entry.user_agent.lower()
    for hint in _SCANNER_UA_HINTS:
        if hint and hint in ua_lower:
            return Finding(
                rule="scanner_user_agent",
                severity="low",
                ip=entry.ip,
                path=entry.path,
                detail=f"User-Agent mengandung indikator tool: '{hint}'",
                timestamp=entry.timestamp,
            )
    if ua_lower.strip() in ("", "-"):
        return Finding(
            rule="scanner_user_agent",
            severity="low",
            ip=entry.ip,
            path=entry.path,
            detail="User-Agent kosong/tidak wajar",
            timestamp=entry.timestamp,
        )
    return None


def detect_known_shell_paths(entries: Iterable[LogEntry]) -> list[Finding]:
    """Rule 1: path request mengandung nama file yang umum dipakai webshell.

    Ini setara dengan signature-based detection paling dasar: mencocokkan
    string, seperti `str_contains($path, 'shell.php')` di PHP.
    """
    findings: list[Finding] = []
    for entry in entries:
        result = _check_known_shell_path(entry)
        if result is not None:
            findings.append(result)
    return findings


def detect_suspicious_query_params(entries: Iterable[LogEntry]) -> list[Finding]:
    """Rule 2: query string berisi nama fungsi PHP berbahaya.

    Contoh: GET /index.php?cmd=system(whoami) -> query param 'cmd' berisi
    literal teks "system(" yang mencurigakan.

    Fungsi Python yang dipakai: `urllib.parse.urlparse` dan `parse_qs`
    untuk membongkar query string, analog dengan `parse_url()` +
    `parse_str()` di PHP.
    """
    findings: list[Finding] = []
    for entry in entries:
        result = _check_suspicious_query_param(entry)
        if result is not None:
            findings.append(result)
    return findings


def _max_errors_in_window(
    timestamps: list[datetime], window: timedelta
) -> int:
    """Hitung jumlah MAKSIMUM error yang terjadi dalam satu rentang waktu
    sepanjang `window`, dari daftar timestamp satu IP.

    Teknik ini namanya "sliding window dua-pointer": `timestamps` diurutkan
    dulu, lalu kita gerakkan dua penunjuk (`left` dan `right`) menyusuri
    daftar itu. `right` selalu maju satu per satu; `left` HANYA maju kalau
    jarak waktu antara `timestamps[left]` dan `timestamps[right]` sudah
    melebihi `window` — artinya elemen di `left` sudah "kedaluwarsa" dan
    boleh dikeluarkan dari jendela yang sedang dihitung.

    Karena `left` dan `right` masing-masing hanya bergerak maju (tidak
    pernah mundur), total langkah keduanya maksimal 2 x panjang data —
    jauh lebih cepat daripada mengecek semua pasangan kemungkinan jendela
    satu per satu (yang perlu memeriksa setiap pasangan titik, jauh lebih
    lambat untuk data besar).

    Contoh nilai bertahap untuk timestamps = [t0, t1, t2, t3, t4] dengan
    t0..t2 berdekatan (dalam window) tapi t3, t4 jauh di depan:
        right=0: left=0, lebar jendela=1
        right=1: left=0, lebar jendela=2
        right=2: left=0, lebar jendela=3   <- max_count jadi 3
        right=3: left maju ke 1 (t0 sudah kedaluwarsa), lebar jendela=3
        right=4: left maju lagi, lebar jendela tetap kecil
    """
    if not timestamps:
        return 0

    timestamps = sorted(timestamps)
    left = 0
    max_count = 0
    for right in range(len(timestamps)):
        while timestamps[right] - timestamps[left] > window:
            left += 1
        current_count = right - left + 1
        max_count = max(max_count, current_count)
    return max_count


def _accumulate_error_record(
    errors_by_ip: dict[str, list[tuple[datetime, str]]], entry: LogEntry
) -> None:
    """Simpan satu LogEntry ke dalam akumulator error per-IP, KALAU
    status-nya 404/500. Dipisah dari detect_high_error_rate supaya bisa
    dipanggil satu entry per satu waktu dari loop streaming (Temuan 4),
    bukan hanya dari list penuh.
    """
    if entry.status in (404, 500):
        errors_by_ip[entry.ip].append((entry.timestamp, entry.path))


def _finalize_high_error_rate(
    errors_by_ip: dict[str, list[tuple[datetime, str]]],
    threshold: int,
    window_minutes: int | None,
) -> list[Finding]:
    """Ubah akumulator error per-IP menjadi daftar Finding.

    PERBAIKAN (audit Temuan 5): parameter `window_minutes`, bersifat
    opsional:

    - `window_minutes=None` (default) -> perilaku LAMA dipertahankan apa
      adanya: hitung total error sepanjang seluruh data, severity selalu
      "medium". Ini demi kompatibilitas mundur — siapa pun yang sudah
      bergantung ke perilaku lama tidak akan mendadak hasilnya berubah.
    - `window_minutes=N` -> dipakai sliding window: kita cek apakah ada
      rentang waktu N menit yang berisi >= threshold error. Kalau ya,
      severity dinaikkan jadi "high" (burst terkonsentrasi = indikasi
      kuat automated scanning, bukan sekadar kebetulan error tersebar).
      Kalau total error memenuhi threshold TAPI tersebar di luar window
      manapun, severity tetap "medium" (indikator lemah, perlu
      dikorelasikan dengan rule lain) — inilah pemisahan "indikator" vs
      "bukti kuat" yang diminta di audit.
    """
    findings: list[Finding] = []
    for ip, records in errors_by_ip.items():
        total_count = len(records)
        if total_count < threshold:
            continue  # belum memenuhi threshold sama sekali, lewati IP ini

        timestamps = [ts for ts, _ in records]
        latest_timestamp = max(timestamps)
        sample_path = records[-1][1]

        if window_minutes is not None:
            burst_count = _max_errors_in_window(
                timestamps, timedelta(minutes=window_minutes)
            )
            if burst_count >= threshold:
                findings.append(
                    Finding(
                        rule="high_error_rate",
                        severity="high",
                        ip=ip,
                        path=sample_path,
                        detail=(
                            f"{burst_count} response error (404/500) dalam "
                            f"rentang {window_minutes} menit dari IP ini "
                            f"(burst terkonsentrasi -> indikasi kuat scanning)"
                        ),
                        timestamp=latest_timestamp,
                        evidence_count=burst_count,
                    )
                )
                continue  # sudah dilaporkan sebagai "high", jangan dobel

        # Baik window_minutes=None, maupun window diaktifkan tapi burst
        # tidak ditemukan dalam jendela manapun: tetap laporkan, tapi
        # sebagai indikator yang lebih lemah ("medium").
        findings.append(
            Finding(
                rule="high_error_rate",
                severity="medium",
                ip=ip,
                path=sample_path,
                detail=(
                    f"{total_count} response error (404/500) dari IP ini "
                    f"(tersebar sepanjang periode log, bukan burst)"
                ),
                timestamp=latest_timestamp,
                evidence_count=total_count,
            )
        )
    return findings


def detect_high_error_rate(
    entries: Iterable[LogEntry],
    threshold: int = 5,
    window_minutes: int | None = None,
) -> list[Finding]:
    """Rule 3: satu IP menghasilkan banyak response 404/500 (indikasi scanning).

    Fungsi ini sekarang cuma "pembungkus" tipis: akumulasi lewat
    `_accumulate_error_record`, lalu ubah jadi Finding lewat
    `_finalize_high_error_rate`. Dipisah begini supaya logika yang sama
    persis bisa dipakai juga oleh `run_all_detectors_streaming` tanpa
    duplikasi kode (lihat audit Temuan 4).
    """
    errors_by_ip: dict[str, list[tuple[datetime, str]]] = defaultdict(list)
    for entry in entries:
        _accumulate_error_record(errors_by_ip, entry)
    return _finalize_high_error_rate(errors_by_ip, threshold, window_minutes)


def detect_scanner_user_agent(entries: Iterable[LogEntry]) -> list[Finding]:
    """Rule 4: User-Agent kosong atau mengandung nama tool scanning dikenal.

    Catatan edukasi: ini low-confidence indicator. Tool seperti curl/sqlmap
    juga dipakai untuk keperluan sah (misalnya tim QA kamu sendiri), jadi
    severity-nya sengaja "low" — bukan bukti pasti serangan, cuma sinyal
    tambahan yang perlu dikorelasikan dengan rule lain.
    """
    findings: list[Finding] = []
    for entry in entries:
        result = _check_scanner_user_agent(entry)
        if result is not None:
            findings.append(result)
    return findings


# Daftar semua detector aktif. CLI akan memanggil semua fungsi di list ini.
# Menambah rule baru di masa depan cukup: tulis fungsinya, lalu daftarkan
# di sini — tidak perlu mengubah cli.py sama sekali (Open/Closed Principle).
ALL_DETECTORS = (
    detect_known_shell_paths,
    detect_suspicious_query_params,
    detect_high_error_rate,
    detect_scanner_user_agent,
)


def run_all_detectors(
    entries: list[LogEntry],
    error_threshold: int = 5,
    window_minutes: int | None = None,
) -> list[Finding]:
    """Jalankan seluruh detector terhadap satu kumpulan log yang sama.

    Parameter `entries` sengaja bertipe `list` (bukan generator/Iterator)
    di sini, karena beberapa detector (mis. detect_high_error_rate) perlu
    membaca ulang seluruh data, sedangkan generator hanya bisa dibaca
    sekali lalu habis.

    Parameter `error_threshold` diteruskan KHUSUS ke `detect_high_error_rate`,
    karena itu satu-satunya rule yang punya konsep "ambang batas yang bisa
    diatur". Detector lain di ALL_DETECTORS tetap dipanggil dengan signature
    seragam (entries saja) — jadi menambah rule baru nanti tetap tidak perlu
    mengubah fungsi ini, KECUALI rule itu juga butuh parameter konfigurasi
    sendiri (ikuti pola `if detector is ...` di bawah untuk kasus itu).

    PERBAIKAN (lihat audit Temuan 1): sebelumnya fungsi ini mengabaikan
    threshold sama sekali — CLI menerima argumen --error-threshold tapi
    nilainya tidak pernah benar-benar dipakai. Sekarang sudah tersambung.
    """
    if error_threshold < 1:
        raise ValueError(
            f"error_threshold harus >= 1, diterima: {error_threshold}"
        )

    all_findings: list[Finding] = []
    for detector in ALL_DETECTORS:
        if detector is detect_high_error_rate:
            all_findings.extend(
                detector(
                    entries,
                    threshold=error_threshold,
                    window_minutes=window_minutes,
                )
            )
        else:
            all_findings.extend(detector(entries))
    return all_findings


def run_all_detectors_streaming(
    entries: Iterable[LogEntry],
    error_threshold: int = 5,
    window_minutes: int | None = None,
) -> list[Finding]:
    """Versi HEMAT MEMORI dari run_all_detectors.

    PERBAIKAN (audit Temuan 4): `run_all_detectors` di atas menerima
    `entries: list[...]` dan memanggil tiap detector dengan list yang
    sama berulang kali (4 kali total) — supaya itu bisa jalan, `cli.py`
    versi lama terpaksa memuat SELURUH file log ke memori dulu lewat
    `list(iter_log_entries(...))`, sehingga manfaat generator di
    log_parser.py (hemat memori) hilang sama sekali untuk file besar.

    Fungsi ini sebagai gantinya HANYA melakukan SATU kali iterasi atas
    `entries`. Untuk setiap baris: tiga rule "per-entry" (known_shell_path,
    suspicious_query_param, scanner_user_agent) langsung dicek saat itu
    juga lewat fungsi _check_*; hanya baris yang statusnya 404/500 yang
    disimpan sementara (lewat _accumulate_error_record) untuk dianalisis
    setelah loop selesai lewat _finalize_high_error_rate.

    Hasilnya: `entries` BOLEH berupa generator langsung dari
    `iter_log_entries()` tanpa pernah di-list()-kan — penggunaan memori
    sekarang proporsional dengan JUMLAH ERROR 404/500 (biasanya jauh
    lebih sedikit dari total baris log), bukan dengan total baris log.

    Perilaku hasil (Finding apa saja yang muncul) identik dengan
    `run_all_detectors` untuk input yang sama — ini diverifikasi oleh
    test `test_run_all_detectors_streaming_matches_list_based_result`.
    """
    if error_threshold < 1:
        raise ValueError(
            f"error_threshold harus >= 1, diterima: {error_threshold}"
        )

    findings: list[Finding] = []
    errors_by_ip: dict[str, list[tuple[datetime, str]]] = defaultdict(list)

    per_entry_checks = (
        _check_known_shell_path,
        _check_suspicious_query_param,
        _check_scanner_user_agent,
    )

    for entry in entries:
        for check in per_entry_checks:
            result = check(entry)
            if result is not None:
                findings.append(result)
        _accumulate_error_record(errors_by_ip, entry)

    findings.extend(
        _finalize_high_error_rate(errors_by_ip, error_threshold, window_minutes)
    )
    return findings
