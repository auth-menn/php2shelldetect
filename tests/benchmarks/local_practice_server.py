"""
local_practice_server.py
=========================

Server HTTP SANGAT sederhana untuk latihan lokal, pakai modul standard
library `http.server` (TIDAK perlu Nginx/Apache/Docker/install apa pun
tambahan — cuma Python bawaan).

Tujuannya: menghasilkan access log ASLI (bukan sintetis buatan generator)
dalam format combined log format yang PERSIS sama seperti yang dihasilkan
Nginx/Apache sungguhan, supaya kamu bisa latihan alur lengkap:
    buka URL di browser -> server catat ke file -> jalankan CLI kita
    terhadap file itu -> lihat temuannya.

Cara pakai:
    python local_practice_server.py
    (lalu buka beberapa URL di browser, lihat instruksi yang dicetak)

Konsep Python baru di sini:
- `http.server.BaseHTTPRequestHandler` -- class dasar untuk menangani satu
  request HTTP. Kita bikin subclass dan override method tertentu, sama
  seperti bikin Controller yang extends base Controller di Laravel.
- override `log_message()` -- method bawaan yang NORMALNYA cuma print ke
  terminal, kita timpa (override) supaya menulis ke FILE dengan format
  sesuai kebutuhan kita, bukan format log default Python.
- `socketserver.TCPServer` -- "mesin" di belakang layar yang menerima
  koneksi TCP mentah dan menyerahkannya ke handler kita.
"""

from __future__ import annotations

import http.server
import socketserver
from datetime import datetime
from pathlib import Path

LOG_PATH = Path(__file__).parent / "local_practice_access.log"
PORT = 8099


class LoggingHandler(http.server.BaseHTTPRequestHandler):
    """Handler yang melayani request SANGAT sederhana, dan mencatat setiap
    request ke file log dalam combined log format.
    """

    def do_GET(self) -> None:
        # Halaman utama kasih instruksi; path lain semua dianggap 404,
        # supaya kamu bisa coba path mencurigakan apa pun tanpa perlu
        # server benar-benar punya endpoint itu.
        if self.path == "/":
            body = (
                b"<h1>Server latihan php2shell_detect</h1>"
                b"<p>Coba buka beberapa URL ini satu-satu di tab baru:</p>"
                b"<ul>"
                b"<li>/adminer.php</li>"
                b"<li>/index.php?cmd=system(whoami)</li>"
                b"<li>/notfound1 , /notfound2 , ... /notfound6 (ulangi beberapa kali cepat)</li>"
                b"</ul>"
            )
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"404 Not Found (ini normal, memang disengaja)")

    def log_message(self, format: str, *args) -> None:  # noqa: A002 (nama param ikut API bawaan)
        """Override method bawaan: alih-alih print ke terminal, tulis satu
        baris combined log format ke LOG_PATH.

        `args` di sini datang dari pemanggilan internal `log_request()`
        bawaan `http.server`, isinya (requestline, status_code, size) —
        kita ambil status_code dari situ (args[1]).
        """
        ip = self.client_address[0]
        # .astimezone() PENTING: mengubah datetime "naive" (tanpa info
        # zona waktu) jadi "aware" (ada info zona waktu), supaya %z di
        # strftime menghasilkan offset yang benar (mis. +0700), bukan
        # string kosong.
        timestamp = datetime.now().astimezone().strftime("%d/%b/%Y:%H:%M:%S %z")
        status = args[1] if len(args) > 1 else "-"
        user_agent = self.headers.get("User-Agent", "-")
        line = (
            f'{ip} - - [{timestamp}] "{self.requestline}" '
            f'{status} - "-" "{user_agent}"\n'
        )
        with LOG_PATH.open("a", encoding="utf-8") as handle:
            handle.write(line)


def main() -> None:
    with socketserver.TCPServer(("127.0.0.1", PORT), LoggingHandler) as httpd:
        print(f"Server latihan jalan di: http://127.0.0.1:{PORT}")
        print(f"Log ditulis ke        : {LOG_PATH}")
        print()
        print("Buka beberapa URL ini di browser (satu-satu, boleh berurutan):")
        print(f"  http://127.0.0.1:{PORT}/")
        print(f"  http://127.0.0.1:{PORT}/adminer.php")
        print(f"  http://127.0.0.1:{PORT}/index.php?cmd=system(whoami)")
        for i in range(1, 7):
            print(f"  http://127.0.0.1:{PORT}/notfound{i}")
        print()
        print("Tekan Ctrl+C di terminal ini untuk menghentikan server.")
        httpd.serve_forever()


if __name__ == "__main__":
    main()