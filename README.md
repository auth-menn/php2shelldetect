# php2shell_detect — Log Analyzer and Passive Metadata Assessment

Toolkit defensif untuk membaca log web server PHP/Laravel dan melakukan
assessment metadata HTTP pasif terhadap satu target publik yang telah
diotorisasi pengguna. Analisis log tetap lokal dan tidak membuat request.
Assessment target hanya mengambil metadata dari URL yang diberikan; tidak
melakukan crawling, eksploitasi, port scanning, atau endpoint discovery.

Target assessment membatasi request hingga lima termasuk redirect yang
divalidasi, memeriksa semua alamat DNS sebelum terhubung, dan mem-pin koneksi
ke IP publik yang divalidasi. Skor adalah rekomendasi hardening dari metadata
pasif, bukan bukti adanya kerentanan.

## Menjalankan

```bash
pip install pytest
python -m pytest tests/ -v   # harus: 22 passed

python -m php2shell_detect.cli \
  --log tests/fixtures/sample_access.log \
  --json-out outputs/findings.json \
  --csv-out outputs/findings.csv \
  --error-threshold 5 \
  --time-window-minutes 5
```

GUI:

```powershell
python .\gui.py
```

Pada tab **Periksa Domain**, masukkan domain, URL `http://`/`https://`, atau
alamat IP publik (IPv6 dapat ditulis langsung atau dalam tanda kurung siku pada
URL). HTTPS ditambahkan hanya jika skema tidak diberikan. **Validasi Target**
hanya memeriksa DNS dan ruang alamat; **Periksa Domain** meminta konfirmasi
otorisasi dan cakupan sebelum request dimulai. Hasil menampilkan *Observations*,
*Potential hardening recommendations*, dan *Hardening Score*.

Penilaian terbatas pada metadata dari satu set request yang dibatasi dan tidak
memastikan kerentanan. Banner versi dapat spoof/generik dan tidak dipetakan ke
CVE. Nilai cookie tidak disimpan atau diekspor; hanya nama dan atributnya.
Ekspor JSON/CSV mencakup target, URL final, score, findings, timestamp, dan
disclaimer.

`--time-window-minutes` opsional. Tanpa diisi, rule `high_error_rate`
memakai perilaku lama (hitung total error, severity selalu "medium").
Dengan diisi, error yang menumpuk dalam N menit dilaporkan sebagai
severity "high" (burst = indikasi kuat scanning otomatis).

## Struktur

- `php2shell_detect/log_parser.py` — parsing access log (generator, hemat memori) -> LogEntry
- `php2shell_detect/detectors.py` — 4 rule deteksi + versi streaming satu-pass
- `php2shell_detect/report.py` — output JSON/CSV (termasuk kolom timestamp) + ringkasan teks
- `php2shell_detect/cli.py` — entry point (argparse), streaming penuh dari file ke laporan
- `php2shell_detect/domain_check.py` — parsing target, validasi IP publik, koneksi IP-pinned, dan pengumpulan metadata terbatas
- `php2shell_detect/scoring.py` — aturan severity dan Hardening Score deterministik (terpisah dari engine log)
- `php2shell_detect/assessment_report.py` — ekspor JSON/CSV untuk assessment metadata
- `tests/fixtures/sample_access.log` — data log SINTETIS untuk testing
- `tests/` — unit tests log dan assessment; assessment menggunakan DNS/jaringan mock (tanpa request publik)

## Riwayat perbaikan (hasil audit)

| # | Temuan | Status |
|---|---|---|
| 1 | `--error-threshold` CLI tidak pernah dipakai (dead argument) | Diperbaiki + regression test |
| 2 | Hint path `"upload.php"` terlalu umum, berisiko false positive | Dihapus dari daftar hint + regression test |
| 3 | `Finding` tidak menyimpan timestamp kejadian | Field `timestamp` ditambahkan, muncul di JSON & CSV |
| 4 | Generator kehilangan manfaat memori karena `list()` di CLI | CLI sekarang full-streaming lewat `run_all_detectors_streaming` |
| 5 | `high_error_rate` tidak punya jendela waktu / pemisahan indicator vs evidence | Sliding window opsional (`--time-window-minutes`), severity high vs medium |
| 6 | Tidak ada test untuk `cli.py` | `tests/test_cli.py` ditambahkan (4 test) |

## Rule yang diimplementasikan (semua defensif, bukan exploit)

| Rule | Severity | Deskripsi |
|---|---|---|
| known_shell_path | high | path mengandung nama file webshell spesifik (cmd.php, shell.php, adminer.php, phpinfo.php) |
| suspicious_query_param | high | query string berisi pola fungsi PHP sensitif (system, eval, dst) |
| high_error_rate | medium (tersebar) / high (burst dalam window) | satu IP menghasilkan banyak 404/500 |
| scanner_user_agent | low | User-Agent kosong atau mengandung nama tool scanner dikenal |

## Batasan yang disengaja (by design)

- Analisis file log tidak mengirim HTTP request.
- Assessment target hanya mengirim GET untuk URL yang dimasukkan pengguna, setelah validasi DNS/IP publik; jumlah request maksimum lima termasuk redirect.
- Tidak ada payload/exploit code.
- Severity "low" pada scanner_user_agent sengaja rendah karena false-positive-prone.
- Evasion encoding ganda pada query param (double URL-encoding) belum ditangani — batasan yang diketahui, belum masuk prioritas perbaikan saat ini.
