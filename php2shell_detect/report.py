"""
report.py
=========

Modul ini mengubah daftar `Finding` menjadi file laporan: JSON dan CSV.
Dipisah dari detectors.py supaya tanggung jawabnya jelas: detectors.py
MENEMUKAN masalah, report.py MENYAJIKAN hasilnya. Ini prinsip yang sama
seperti memisahkan Controller dan Resource/Presenter di Laravel.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path

from .detectors import Finding


def write_json_report(findings: list[Finding], output_path: str | Path) -> None:
    """Tulis findings sebagai JSON array.

    `json.dump` adalah standard library Python untuk serialisasi —
    padanannya di PHP adalah `json_encode()` + `file_put_contents()`.
    """
    data = [f.to_dict() for f in findings]
    path = Path(output_path)
    # mkdir(parents=True, exist_ok=True): buat folder induk kalau belum ada,
    # dan jangan error kalau ternyata sudah ada. Setara dengan PHP:
    #   if (!is_dir($dir)) { mkdir($dir, 0777, true); }
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2, ensure_ascii=False)


def write_csv_report(findings: list[Finding], output_path: str | Path) -> None:
    """Tulis findings sebagai CSV, satu baris per temuan.

    `csv.DictWriter` otomatis menulis header dari key dictionary pertama,
    mirip fungsi bantu fputcsv() di PHP tapi dengan penanganan header
    otomatis.
    """
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = ["rule", "severity", "ip", "path", "detail", "timestamp", "evidence_count"]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for finding in findings:
            writer.writerow(finding.to_dict())


def summarize(findings: list[Finding]) -> str:
    """Buat ringkasan teks singkat untuk ditampilkan di terminal.

    f-string (`f"..."`) adalah cara Python menyisipkan variabel ke dalam
    string, setara dengan interpolasi string PHP: `"Total: {$total}"`.
    """
    total = len(findings)
    by_severity: dict[str, int] = {}
    for f in findings:
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1

    lines = [f"Total temuan: {total}"]
    for severity in ("high", "medium", "low"):
        if severity in by_severity:
            lines.append(f"  - {severity}: {by_severity[severity]}")
    return "\n".join(lines)
