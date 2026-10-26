"""Static, read-only manual verification guidance for passive findings."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from .domain_check import ValidatedTarget, normalize_url

GUIDE_VERSION = "1.0"
SAFETY_NOTE = (
    "Panduan ini hanya untuk verifikasi pasif dalam scope program yang diizinkan. "
    "Hasil bukan bukti kerentanan. Tool ini hanya menampilkan dan menyalin perintah; "
    "tool tidak menjalankannya. Pastikan semua langkah sesuai rules of engagement."
)
VERIFICATION_STATUSES = (
    "Belum Diverifikasi",
    "Terkonfirmasi",
    "False Positive",
    "Perlu Cek Lanjutan",
)

REFERENCE_URLS = {
    "owasp": "https://owasp.org/www-project-secure-headers/",
    "https": "https://developer.mozilla.org/en-US/docs/Glossary/HTTPS",
    "hsts": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
    "csp": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy",
    "xcto": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options",
    "xfo": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options",
    "referrer": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy",
    "permissions": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy",
    "cookies": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie",
    "tls": "https://www.rfc-editor.org/rfc/rfc8446",
    "http": "https://www.rfc-editor.org/rfc/rfc9110",
}

_COMMON_FALSE_POSITIVES = (
    "CDN, WAF, or load balancer may add or remove headers differently from the origin.",
    "A header may be configured only for some paths or authenticated pages.",
    "HEAD and GET responses can differ; compare only with a single read-only request to the same validated URL.",
    "Cached responses may reflect an older configuration; record cache headers and re-check later.",
    "Responses may vary by User-Agent or geographic region.",
    "A redirect may end on a different host; assess that host only if it is in the authorized scope.",
    "A documented policy exception (including a security.txt-style scope or endpoint exception) may explain the behavior.",
)
_URL_SAFE = re.compile(r"^[A-Za-z0-9:/?._~=\-\[\]]+$")
_HOST_SAFE = re.compile(r"^[A-Za-z0-9.:\-\[\]]+$")
_PORT_SAFE = re.compile(r"^[0-9]{1,5}$")
_TEMPLATE_SAFE = re.compile(r'^[A-Za-z0-9 .:/?_"\'=\-\[\]]+$')


@dataclass(frozen=True)
class Step:
    title: str
    tool: str
    instructions: str
    command_template: str | None = None

    def to_dict(self) -> dict[str, str | None]:
        return {
            "title": self.title,
            "tool": self.tool,
            "instructions": self.instructions,
            "command_template": self.command_template,
        }


@dataclass(frozen=True)
class VerificationGuide:
    finding_id: str
    summary: str
    why_it_matters: str
    manual_steps: list[Step]
    expected_if_confirmed: str
    expected_if_false_positive: str
    common_false_positives: tuple[str, ...]
    report_tips: str
    references: tuple[str, ...]
    safety_note: str = SAFETY_NOTE

    def to_dict(self) -> dict:
        return {
            "finding_id": self.finding_id,
            "summary": self.summary,
            "why_it_matters": self.why_it_matters,
            "manual_steps": [step.to_dict() for step in self.manual_steps],
            "expected_if_confirmed": self.expected_if_confirmed,
            "expected_if_false_positive": self.expected_if_false_positive,
            "common_false_positives": list(self.common_false_positives),
            "report_tips": self.report_tips,
            "references": list(self.references),
            "safety_note": self.safety_note,
        }


@dataclass(frozen=True)
class VerificationState:
    status: str = VERIFICATION_STATUSES[0]
    note: str = ""


def _command_steps(instructions: str) -> tuple[Step, Step]:
    return (
        Step(
            "Periksa header dengan curl.exe",
            "curl.exe (Command Prompt / PowerShell)",
            instructions,
            'curl.exe -sI --max-time 5 "{url}"',
        ),
        Step(
            "Periksa header dengan PowerShell",
            "PowerShell",
            instructions,
            "Invoke-WebRequest -Method Head -Uri '{url}' -MaximumRedirection 0",
        ),
    )


def _guide(
    finding_id: str,
    summary: str,
    why: str,
    inspect: str,
    confirmed: str,
    false_positive: str,
    references: tuple[str, ...],
    *,
    commands: bool = True,
    special_steps: tuple[Step, ...] = (),
) -> VerificationGuide:
    steps = (
        Step(
            "Periksa respons di browser",
            "Browser DevTools",
            f"Buka hanya URL assessment yang sama, lalu pilih Network → main document → Response Headers. {inspect}",
        ),
    )
    if commands:
        steps += _command_steps(f"Kirim satu permintaan HEAD ke URL yang sama. {inspect}")
    steps += special_steps
    return VerificationGuide(
        finding_id=finding_id,
        summary=summary,
        why_it_matters=why,
        manual_steps=list(steps),
        expected_if_confirmed=confirmed,
        expected_if_false_positive=false_positive,
        common_false_positives=_COMMON_FALSE_POSITIVES,
        report_tips=(
            "Catat URL yang diperiksa, waktu dan zona waktu, status respons, serta header mentah yang relevan. "
            "Lampirkan screenshot DevTools bila membantu; hapus nilai cookie, token, dan data akun sebelum membagikan bukti. "
            "Dalam draft laporan, tuliskan observasi dan kondisi pemeriksaan, dampak yang benar-benar terverifikasi, "
            "serta batasan/kemungkinan false positive; jangan menyatakan kerentanan hanya dari metadata."
        ),
        references=references,
    )


_HTTP_STEPS = (
    Step(
        "Periksa redirect HTTP ke HTTPS",
        "curl.exe (Command Prompt / PowerShell)",
        "Gunakan satu HEAD ke URL HTTP assessment. Periksa status redirect dan header Location; jangan ikuti redirect di luar scope.",
        'curl.exe -sI --max-time 5 "{url}"',
    ),
    Step(
        "Periksa redirect dengan PowerShell",
        "PowerShell",
        "Jalankan satu HEAD ke URL HTTP assessment. Periksa status dan Location tanpa mengikuti redirect otomatis.",
        "Invoke-WebRequest -Method Head -Uri '{url}' -MaximumRedirection 0",
    ),
)
_CERTIFICATE_STEPS = (
    Step(
        "Lihat sertifikat di browser",
        "Browser",
        "Pilih ikon gembok/peringatan pada URL assessment → detail sertifikat. Periksa masa berlaku, nama host pada SAN, dan rantai sertifikat.",
    ),
    Step(
        "Periksa handshake TLS",
        "openssl (Command Prompt / PowerShell)",
        "Jalankan perintah baca-saja untuk host dan port URL yang divalidasi. Periksa verify return code, masa berlaku, SAN, dan rantai.",
        "openssl s_client -connect {host}:{port} -servername {host}",
    ),
)

_GUIDE_DEFINITIONS = (
    _guide(
        "transport.http",
        "Assessment menemukan HTTP tanpa enkripsi pada URL atau salah satu hop redirect.",
        "HTTP tidak mengenkripsi transport. Periksa apakah HTTP beralih ke HTTPS dan apakah seluruh host yang terlibat termasuk scope.",
        "Periksa status dan Location. Pastikan tujuan HTTPS sama dengan URL/host yang memang diizinkan.",
        "HEAD menunjukkan redirect ke HTTPS untuk target yang sama, atau konfigurasi yang mengharuskan HTTP memang tidak diterapkan.",
        "Respons hanya berada pada hop HTTP awal menuju HTTPS dan kebijakan program tidak mensyaratkan redirect.",
        (REFERENCE_URLS["https"], REFERENCE_URLS["http"]),
        commands=False,
        special_steps=_HTTP_STEPS,
    ),
    _guide(
        "transport.certificate",
        "Validasi sertifikat TLS gagal pada koneksi assessment.",
        "Sertifikat yang tidak cocok atau tidak dipercaya dapat membuat identitas host sulit diverifikasi.",
        "Periksa expiry, hostname/SAN, dan chain. Proxy perusahaan atau inspeksi TLS antivirus dapat mengubah hasil lokal.",
        "Browser dan pemeriksaan TLS independen pada jaringan normal menunjukkan sertifikat kedaluwarsa, nama tidak cocok, atau chain tidak dipercaya.",
        "Kesalahan hanya muncul pada perangkat/jaringan dengan corporate proxy atau antivirus TLS interception, sementara koneksi independen valid.",
        (REFERENCE_URLS["tls"], REFERENCE_URLS["https"]),
        commands=False,
        special_steps=_CERTIFICATE_STEPS,
    ),
    _guide(
        "transport.certificate_not_assessed",
        "Status sertifikat tidak tersedia dari metadata assessment.",
        "Tanpa hasil TLS yang bisa divalidasi, status sertifikat belum dapat dinilai.",
        "Buka URL HTTPS yang sama dan lihat detail sertifikat pada browser. Jika assessment memakai HTTP, TLS memang tidak dinilai.",
        "Detail sertifikat browser menunjukkan status valid dan nama host cocok.",
        "Target assessment memakai HTTP, atau jaringan lokal menghalangi pengambilan detail sertifikat.",
        (REFERENCE_URLS["tls"], REFERENCE_URLS["https"]),
        commands=False,
        special_steps=_CERTIFICATE_STEPS[:1],
    ),
    _guide(
        "headers.metadata_not_assessed",
        "Header response tidak tersedia untuk dianalisis.",
        "Tanpa response HTTP, aturan header tidak dapat dinilai.",
        "Buka URL assessment yang sama pada Network panel dan lihat apakah respons dokumen utama memiliki response headers.",
        "Response headers tersedia pada response final dari URL yang sama.",
        "Tidak ada respons HTTP, atau browser/tool menampilkan respons perantara yang berbeda.",
        (REFERENCE_URLS["http"],),
    ),
    _guide(
        "cookies.metadata_not_assessed",
        "Atribut cookie tidak tersedia untuk dianalisis.",
        "Tidak ada informasi cookie yang cukup untuk menilai atributnya.",
        "DevTools → Application/Storage → Cookies untuk host yang sama. Jangan salin atau bagikan nilai cookie.",
        "Daftar cookie dan atribut tersedia pada host yang sedang diperiksa.",
        "Respons HEAD tidak mengirim Set-Cookie, sementara cookie hanya dibuat setelah alur browser tertentu.",
        (REFERENCE_URLS["cookies"],),
        commands=False,
    ),
    _guide(
        "disclosure.metadata_not_assessed",
        "Banner teknologi tidak tersedia untuk dianalisis.",
        "Tanpa response header, informasi banner tidak dapat diamati.",
        "Periksa response headers pada main document di DevTools untuk URL yang sama.",
        "Header Server atau X-Powered-By terlihat pada respons yang sama.",
        "Header tidak dikirim pada jalur ini atau lapisan perantara menghapusnya.",
        (REFERENCE_URLS["owasp"], REFERENCE_URLS["http"]),
    ),
    _guide(
        "headers.hsts",
        "Strict-Transport-Security tidak terlihat atau tidak memiliki max-age positif.",
        "HSTS meminta browser memakai HTTPS pada kunjungan berikutnya; kebijakan hanya berlaku dari HTTPS.",
        "Cari Strict-Transport-Security pada response HTTPS final. HSTS mungkin hanya dipasang pada host final.",
        "Header Strict-Transport-Security dengan max-age positif terlihat pada respons HTTPS final.",
        "Header hadir pada host final/response lain, atau URL yang diperiksa bukan HTTPS.",
        (REFERENCE_URLS["hsts"], REFERENCE_URLS["owasp"]),
    ),
    _guide(
        "headers.csp",
        "Content-Security-Policy tidak terlihat pada response header assessment.",
        "CSP membatasi sumber konten yang dapat dimuat browser. Ketiadaannya bukan bukti kerentanan.",
        "Periksa Content-Security-Policy pada main document. CSP juga dapat disampaikan melalui elemen meta; header dapat berbeda pada halaman autentikasi.",
        "Header CSP terlihat pada response yang sama, atau policy meta yang sesuai menjelaskan temuan.",
        "CSP dipasang sebagai meta policy atau hanya pada halaman/path berbeda.",
        (REFERENCE_URLS["csp"], REFERENCE_URLS["owasp"]),
    ),
    _guide(
        "headers.csp_weak",
        "CSP terlihat kosong atau memuat directive/sumber yang berpotensi terlalu luas.",
        "Policy yang terlalu permisif mungkin memberi pembatasan lebih sedikit; tinjau sesuai kebutuhan aplikasi.",
        "Periksa seluruh nilai Content-Security-Policy pada main document dan policy meta. Bandingkan dengan dokumentasi aplikasi.",
        "Directive wildcard atau unsafe yang dilaporkan memang aktif pada respons yang sama dan tidak diperlukan.",
        "Nilai berasal dari report-only/meta policy, konfigurasi lain, atau penggunaan directive tersebut memang disengaja dan terdokumentasi.",
        (REFERENCE_URLS["csp"], REFERENCE_URLS["owasp"]),
    ),
    _guide(
        "headers.content_type_options",
        "X-Content-Type-Options tidak terlihat dengan nilai nosniff.",
        "nosniff membantu browser menghormati MIME type yang dinyatakan untuk resource tertentu.",
        "Periksa X-Content-Type-Options pada response headers main document.",
        "Header berulang kali tidak ada atau nilainya bukan nosniff pada target/path yang sama.",
        "Header disetel hanya untuk tipe/path tertentu atau respons HEAD berbeda dari GET.",
        (REFERENCE_URLS["xcto"], REFERENCE_URLS["owasp"]),
    ),
    _guide(
        "headers.frame_protection",
        "Header X-Frame-Options atau directive CSP frame-ancestors yang dikenali tidak terlihat.",
        "Kontrol frame dapat membatasi embedding halaman oleh origin lain.",
        "Periksa X-Frame-Options dan directive frame-ancestors pada seluruh nilai CSP.",
        "Keduanya tidak ada pada response halaman yang perlu dilindungi.",
        "Perlindungan disediakan oleh frame-ancestors CSP atau hanya berlaku pada halaman tertentu.",
        (REFERENCE_URLS["xfo"], REFERENCE_URLS["csp"], REFERENCE_URLS["owasp"]),
    ),
    _guide(
        "headers.referrer_policy",
        "Referrer-Policy tidak terlihat atau bernilai unsafe-url.",
        "Kebijakan ini mengatur informasi referrer yang dapat dikirim saat navigasi.",
        "Periksa nilai Referrer-Policy pada response headers dan dokumentasi konfigurasi situs.",
        "Header hilang pada respons yang sama atau kebijakan unsafe-url digunakan tanpa kebutuhan yang jelas.",
        "Policy disetel pada tag meta atau berlaku berbeda pada halaman/path tertentu.",
        (REFERENCE_URLS["referrer"], REFERENCE_URLS["owasp"]),
    ),
    _guide(
        "headers.permissions_policy",
        "Permissions-Policy tidak terlihat pada response headers.",
        "Policy dapat membatasi fitur browser yang tidak diperlukan aplikasi.",
        "Periksa Permissions-Policy pada response headers main document.",
        "Header tidak ada pada respons/path yang sama.",
        "Policy hanya diterapkan pada halaman tertentu atau dikelola oleh lapisan perantara.",
        (REFERENCE_URLS["permissions"], REFERENCE_URLS["owasp"]),
    ),
    _guide(
        "cookies.secure",
        "Cookie yang teramati tidak memiliki atribut Secure pada HTTPS.",
        "Secure membatasi pengiriman cookie ke koneksi HTTPS.",
        "DevTools → Application/Storage → Cookies dan periksa kolom Secure; atau periksa atribut Set-Cookie tanpa membagikan nilainya.",
        "Cookie yang sama terlihat tanpa Secure pada URL HTTPS.",
        "Cookie berbeda dari yang dievaluasi, atau aplikasi hanya menetapkan Secure pada alur/path lain.",
        (REFERENCE_URLS["cookies"],),
    ),
    _guide(
        "cookies.secure_not_assessed",
        "Atribut Secure tidak dinilai karena response final tidak menggunakan HTTPS.",
        "Secure relevan untuk cookie yang hanya boleh dikirim melalui HTTPS.",
        "Buka versi HTTPS yang sudah termasuk scope lalu periksa atribut cookie di DevTools.",
        "Pada respons HTTPS, cookie yang relevan tetap tidak memiliki Secure.",
        "Cookie memiliki Secure pada alur HTTPS, atau target yang dinilai hanya HTTP dan tidak menetapkan cookie terkait.",
        (REFERENCE_URLS["cookies"], REFERENCE_URLS["https"]),
        commands=False,
    ),
    _guide(
        "cookies.httponly",
        "Cookie yang teramati tidak memiliki atribut HttpOnly.",
        "HttpOnly mencegah akses cookie melalui API script browser untuk cookie yang sesuai.",
        "DevTools → Application/Storage → Cookies dan periksa kolom HttpOnly. Fokus pada cookie sesi/autentikasi.",
        "Cookie sesi/autentikasi yang sama terlihat tanpa HttpOnly.",
        "Cookie bukan cookie sesi/auth dan memang diperlukan oleh script, atau cookie yang dinilai berbeda.",
        (REFERENCE_URLS["cookies"],),
    ),
    _guide(
        "cookies.samesite",
        "Cookie yang teramati tidak memiliki atribut SameSite.",
        "SameSite mengatur kapan browser mengirim cookie dalam konteks navigasi lintas situs.",
        "DevTools → Application/Storage → Cookies dan periksa kolom SameSite. Fokus pada cookie sesi/auth.",
        "Cookie relevan tetap tidak memiliki SameSite pada respons yang sama.",
        "Cookie tidak terkait sesi/auth atau browser menampilkan default yang berlaku berbeda.",
        (REFERENCE_URLS["cookies"],),
    ),
    _guide(
        "disclosure.server",
        "Header Server mengekspos banner teknologi yang dapat generik atau tidak akurat.",
        "Banner memberi petunjuk teknologi tetapi dapat diubah oleh CDN, proxy, atau konfigurasi server.",
        "Lihat nilai Server pada response headers. Jangan menyimpulkan versi aktual hanya dari banner.",
        "Header berulang kali menunjukkan nilai yang sama pada host/path assessment.",
        "Nilai generik, spoofed, atau berasal dari CDN/WAF/load balancer, bukan origin.",
        (REFERENCE_URLS["owasp"], REFERENCE_URLS["http"]),
    ),
    _guide(
        "disclosure.powered_by",
        "Header X-Powered-By mengekspos informasi framework/runtime yang belum tentu akurat.",
        "Banner dapat memberi petunjuk teknologi tetapi bukan bukti versi aktual.",
        "Lihat X-Powered-By pada response headers. Konfirmasi versi sebenarnya dengan pemilik aset atau dokumentasi yang berwenang.",
        "Nilai banner muncul berulang dan dokumentasi pemilik aset mengonfirmasi informasi tersebut.",
        "Header berasal dari proxy/CDN, generik, spoofed, atau tidak mewakili versi runtime.",
        (REFERENCE_URLS["owasp"], REFERENCE_URLS["http"]),
    ),
)

GUIDES = {guide.finding_id: guide for guide in _GUIDE_DEFINITIONS}


def guide_for_finding(finding_id: str) -> VerificationGuide | None:
    return GUIDES.get(finding_id)


def verification_key(finding_id: str, occurrence: int) -> str:
    """Stable session key for findings whose rule ID can occur more than once."""
    return f"{finding_id}::{occurrence}"


def render_command(step: Step, validated_target: ValidatedTarget) -> str:
    """Render a catalog command for a validated target, rejecting shell metacharacters."""
    if not isinstance(step, Step) or step.command_template is None:
        raise ValueError("This manual step has no command to copy.")
    if not isinstance(validated_target, ValidatedTarget):
        raise ValueError("A validated target is required.")
    if (
        not isinstance(validated_target.url, str)
        or not isinstance(validated_target.host, str)
        or not isinstance(validated_target.port, int)
        or not isinstance(validated_target.scheme, str)
        or not isinstance(validated_target.addresses, tuple)
    ):
        raise ValueError("The validated target metadata is malformed.")

    normalized = validated_target.url
    try:
        if normalize_url(normalized) != normalized:
            raise ValueError("The target URL is not normalized.")
    except ValueError as exc:
        raise ValueError("The validated target is malformed.") from exc
    try:
        parsed = urlsplit(normalized)
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError as exc:
        raise ValueError("The validated target is malformed.") from exc
    try:
        ip = ipaddress.ip_address(parsed.hostname or "")
    except ValueError:
        ip = None
    if parsed.scheme not in ("http", "https") or parsed.username or parsed.password:
        raise ValueError("The validated target is not a supported public URL.")

    raw_host = parsed.hostname or ""
    if (
        validated_target.host.casefold() != raw_host.casefold()
        or validated_target.port != port
        or validated_target.scheme != parsed.scheme
    ):
        raise ValueError("The validated target metadata does not match its URL.")
    host = (
        f"[{ip.compressed}]"
        if isinstance(ip, ipaddress.IPv6Address)
        else raw_host
    )
    authority = parsed.netloc
    url = normalized
    if (
        not _HOST_SAFE.fullmatch(host)
        or not _PORT_SAFE.fullmatch(str(port))
        or not _URL_SAFE.fullmatch(url)
        or any(char in url for char in (";", "&", "|", "`", "$", "'", '"', "%", "(", ")", "\\", "\r", "\n", " "))
    ):
        raise ValueError("The validated target contains characters unsafe for shell display.")
    if not validated_target.addresses:
        raise ValueError("The target has no validated public IP address.")
    for address in validated_target.addresses:
        try:
            parsed_ip = ipaddress.ip_address(address)
        except ValueError as exc:
            raise ValueError("The target contains an invalid validated IP address.") from exc
        if (
            not parsed_ip.is_global
            or parsed_ip.is_private
            or parsed_ip.is_loopback
            or str(parsed_ip) != address
        ):
            raise ValueError("The target contains a non-public IP address.")
    if authority != (f"[{raw_host}]" if ":" in raw_host else raw_host) and not authority.endswith(
        f":{port}"
    ):
        # Preserve custom ports; urlsplit/normalize_url has already validated the authority.
        if parsed.port is not None:
            raise ValueError("The target authority does not match its validated port.")

    template = step.command_template
    catalog_templates = {
        catalog_step.command_template
        for guide in GUIDES.values()
        for catalog_step in guide.manual_steps
        if catalog_step.command_template is not None
    }
    if template not in catalog_templates:
        raise ValueError("The command template is not part of the fixed guide catalog.")
    checked_template = re.sub(r"\{(?:host|url|port)\}", "", template)
    if not _TEMPLATE_SAFE.fullmatch(checked_template):
        raise ValueError("The catalog command template contains unsupported characters.")
    try:
        if ip is not None:
            template = template.replace(" -servername {host}", "")
        return template.format(host=host, url=url, port=port)
    except (KeyError, ValueError) as exc:
        raise ValueError("The catalog command template is invalid.") from exc
