"""
cli.py
======

Entry point program ini. File ini yang kamu jalankan dari terminal, mirip
`artisan` command di Laravel, atau skrip `php bin/console.php` yang
menerima argumen.

Cara menjalankan (setelah kamu approve):
    python -m php2shell_detect.cli --log tests/fixtures/sample_access.log \
        --json-out outputs/findings.json --csv-out outputs/findings.csv
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Iterable, Iterator

from .detectors import run_all_detectors_streaming
from .log_parser import LogEntry, iter_log_entries
from .report import summarize, write_csv_report, write_json_report


def _count_while_yielding(
    entries: Iterable[LogEntry], counter: list[int]
) -> Iterator[LogEntry]:
    """Generator pembungkus: meneruskan tiap LogEntry apa adanya, sambil
    menambah `counter[0]` setiap kali satu entry lewat.

    Kenapa butuh ini? Karena `run_all_detectors_streaming` (Temuan 4)
    sengaja HANYA membaca `entries` satu kali tanpa pernah mengubahnya
    jadi list — jadi kita tidak bisa lagi memakai `len(entries)` seperti
    sebelumnya untuk menghitung "berapa baris log terbaca". Counter
    dibungkus dalam list satu elemen (`counter[0]`) karena closure di
    Python tidak bisa menulis ulang variabel int biasa dari fungsi luar
    tanpa `nonlocal` — pakai list yang isinya di-mutate adalah trik umum
    untuk menghindari itu.
    """
    for entry in entries:
        counter[0] += 1
        yield entry


def build_arg_parser() -> argparse.ArgumentParser:
    """Definisikan argumen CLI.

    `argparse` adalah standard library Python untuk parsing argumen CLI,
    setara dengan Symfony Console / Laravel Artisan Input::option() tapi
    bawaan tanpa dependency tambahan.
    """
    parser = argparse.ArgumentParser(
        prog="php2shell-detect",
        description=(
            "Toolkit deteksi defensif: analisis access log untuk indikator "
            "aktivitas mencurigakan (read-only, tidak mengirim request apa pun)."
        ),
    )
    parser.add_argument(
        "--log",
        required=True,
        type=Path,
        help="Path ke file access log (combined log format).",
    )
    parser.add_argument(
        "--json-out",
        type=Path,
        default=None,
        help="Path output laporan JSON (opsional).",
    )
    parser.add_argument(
        "--csv-out",
        type=Path,
        default=None,
        help="Path output laporan CSV (opsional).",
    )
    parser.add_argument(
        "--error-threshold",
        type=int,
        default=5,
        help="Ambang jumlah error 404/500 per IP untuk rule high_error_rate (default: 5).",
    )
    parser.add_argument(
        "--time-window-minutes",
        type=int,
        default=None,
        help=(
            "Opsional. Kalau diisi, rule high_error_rate memakai sliding "
            "window: error yang MENUMPUK dalam N menit dilaporkan sebagai "
            "severity 'high' (burst = indikasi kuat scanning). Kalau "
            "dikosongkan, rule memakai perilaku lama: hitung total error "
            "sepanjang seluruh file, severity selalu 'medium'."
        ),
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Fungsi utama. Return code 0 = sukses, bukan 0 = ada error.

    Konvensi ini SAMA dengan exit code di PHP CLI (`exit(0)` vs `exit(1)`).
    `argv: list[str] | None = None` adalah type hint: parameter boleh berupa
    list string atau None; kalau None, argparse akan otomatis membaca
    `sys.argv` (argumen asli dari terminal). Pola ini memudahkan testing,
    karena unit test bisa memanggil `main(["--log", "contoh.log"])` tanpa
    benar-benar menjalankan proses dari shell.
    """
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    if not args.log.exists():
        print(f"Error: file log tidak ditemukan: {args.log}", file=sys.stderr)
        return 1

    if args.error_threshold < 1:
        print(
            f"Error: --error-threshold harus >= 1, diterima: {args.error_threshold}",
            file=sys.stderr,
        )
        return 1

    # PERBAIKAN (audit Temuan 4): baris log TIDAK LAGI dimuat sekaligus
    # ke list sebelum deteksi. `iter_log_entries` tetap generator murni,
    # dibungkus `_count_while_yielding` supaya kita masih bisa melaporkan
    # jumlah baris terbaca, lalu diteruskan LANGSUNG ke
    # `run_all_detectors_streaming` yang memprosesnya satu-per-satu.
    # Untuk log berukuran puluhan juta baris, ini artinya penggunaan
    # memori program sekarang kira-kira konstan, bukan tumbuh sebesar
    # ukuran file.
    line_counter = [0]
    counted_entries = _count_while_yielding(
        iter_log_entries(args.log), line_counter
    )

    findings = run_all_detectors_streaming(
        counted_entries,
        error_threshold=args.error_threshold,
        window_minutes=args.time_window_minutes,
    )

    if line_counter[0] == 0:
        print("Peringatan: tidak ada baris log yang berhasil diparse.", file=sys.stderr)

    print(f"Baris log terbaca: {line_counter[0]}")
    print(summarize(findings))

    if args.json_out:
        write_json_report(findings, args.json_out)
        print(f"Laporan JSON ditulis ke: {args.json_out}")

    if args.csv_out:
        write_csv_report(findings, args.csv_out)
        print(f"Laporan CSV ditulis ke: {args.csv_out}")

    return 0


if __name__ == "__main__":
    # Baris ini adalah idiom Python yang sangat umum: kode di dalamnya
    # HANYA dijalankan kalau file ini dieksekusi langsung (python cli.py),
    # bukan ketika file ini di-import sebagai modul dari file lain.
    # Tidak ada padanan langsung di PHP karena PHP tidak membedakan
    # "dijalankan langsung" vs "di-include" dengan cara ini.
    sys.exit(main())
