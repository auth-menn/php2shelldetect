"""
gui.py
======

Antarmuka desktop sederhana untuk php2shell_detect, pakai Tkinter
(standard library Python — TIDAK perlu `pip install` apa pun tambahan).

Tab "Analisis Log" hanya membaca file yang dipilih. Tab "Periksa Domain"
melakukan assessment metadata pasif yang dibatasi terhadap satu target
publik, setelah validasi DNS/IP dan konfirmasi otorisasi.

Cara pakai:
    python gui.py

Konsep Python baru di sini:
- `tkinter` -- GUI toolkit bawaan Python. Mirip kalau di web development
  kamu bikin form HTML + event handler JS, tapi ini native desktop app,
  tanpa browser.
- `threading` -- menjalankan analisis di THREAD TERPISAH dari UI utama,
  supaya window tidak "freeze" (not responding) saat memproses file log
  besar. Konsep ini baru untukmu: sebelumnya semua kode kita jalan
  berurutan (synchronous); di sini, UI thread dan worker thread jalan
  BERSAMAAN.
- `queue.Queue` -- cara AMAN untuk mengirim data dari worker thread balik
  ke UI thread. Tkinter TIDAK boleh diupdate langsung dari thread lain
  (bisa crash/corrupt), jadi worker taruh hasil ke queue, lalu UI thread
  polling queue itu secara berkala lewat `after()`.
"""

from __future__ import annotations

import queue
import threading
import tkinter as tk
import webbrowser
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from php2shell_detect.detectors import Finding, run_all_detectors_streaming
from php2shell_detect.assessment_report import (
    write_csv_report as write_assessment_csv_report,
)
from php2shell_detect.assessment_report import (
    write_json_report as write_assessment_json_report,
)
from php2shell_detect.assessment_report import (
    write_markdown_report as write_assessment_markdown_report,
)
from php2shell_detect.domain_check import (
    ASSESSMENT_SCOPE,
    HttpResponseError,
    NetworkError,
    ValidationError,
    check_domain,
    normalize_url,
    validate_target,
)
from php2shell_detect.log_parser import iter_log_entries
from php2shell_detect.report import write_csv_report, write_json_report
from php2shell_detect.scoring import AssessmentResult, Finding as AssessmentFinding, evaluate
from php2shell_detect.verification_guide import (
    GUIDE_VERSION,
    REFERENCE_URLS,
    VERIFICATION_STATUSES,
    Step,
    VerificationGuide,
    VerificationState,
    guide_for_finding,
    render_command,
    verification_key,
)

SEVERITY_COLORS = {
    "high": "#f8d7da",
    "medium": "#fff3cd",
    "low": "#d1ecf1",
}

ASSESSMENT_SEVERITY_COLORS = {
    "high": "#f8d7da",
    "medium": "#fff3cd",
    "low": "#d1ecf1",
    "info": "#f0f0f0",
}


def assessment_finding_to_row(finding: AssessmentFinding) -> tuple[str, ...]:
    return (
        finding.severity,
        finding.category,
        f"{finding.status}: {sanitize_display_text(finding.observation)}",
        sanitize_display_text(finding.evidence),
        finding.confidence,
        sanitize_display_text(finding.recommendation),
    )


def sanitize_display_text(value: str, limit: int = 500) -> str:
    cleaned = "".join(
        character
        for character in value
        if ord(character) >= 32 and ord(character) != 127
    )
    return cleaned[:limit] + ("…" if len(cleaned) > limit else "")


def select_finding_guide(finding_id: str) -> VerificationGuide | None:
    return guide_for_finding(finding_id)


def filter_assessment_findings(
    findings: tuple[AssessmentFinding, ...], severity: str
) -> tuple[AssessmentFinding, ...]:
    if severity == "All":
        return findings
    return tuple(finding for finding in findings if finding.severity == severity)


def run_analysis(
    log_path: Path, error_threshold: int, window_minutes: int | None
) -> tuple[list[Finding], int]:
    """Logika INTI, terpisah dari Tkinter sama sekali.

    Dipisah sengaja (bukan ditulis langsung di dalam method class GUI)
    supaya: (1) bisa dites tanpa perlu membuka window GUI sama sekali,
    (2) kalau nanti mau bikin frontend lain (web, mis.), logika ini bisa
    dipakai ulang tanpa diketik ulang -- sama seperti cli.py dan gui.py
    sama-sama akan memanggil fungsi yang sama ini.
    """
    line_count = 0

    def _counted(entries):
        nonlocal line_count
        for entry in entries:
            line_count += 1
            yield entry

    findings = run_all_detectors_streaming(
        _counted(iter_log_entries(log_path)),
        error_threshold=error_threshold,
        window_minutes=window_minutes,
    )
    return findings, line_count


class App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("php2shell_detect")
        self.geometry("960x640")

        self._findings: list[Finding] = []
        self._result_queue: queue.Queue = queue.Queue()

        self._domain_result: AssessmentResult | None = None
        self._domain_queue: queue.Queue = queue.Queue()
        self._domain_active = False
        self._domain_action = "validate"
        self._domain_pending_raw = ""
        self._domain_sort_reverse: dict[str, bool] = {}
        self._validated_target = None
        self._finding_rows: dict[str, tuple[AssessmentFinding, str]] = {}
        self._verification_states: dict[str, VerificationState] = {}
        self._selected_finding_key: str | None = None

        notebook = ttk.Notebook(self)
        notebook.pack(fill="both", expand=True)

        log_tab = ttk.Frame(notebook)
        domain_tab = ttk.Frame(notebook)
        notebook.add(log_tab, text="Analisis Log")
        notebook.add(domain_tab, text="Periksa Domain")

        self._build_form(log_tab)
        self._build_results_table(log_tab)
        self._build_domain_tab(domain_tab)
        self._build_status_bar()

    # --- UI construction: tab "Analisis Log" (TIDAK DIUBAH logikanya) --

    def _build_form(self, parent: ttk.Frame) -> None:
        frame = ttk.Frame(parent, padding=10)
        frame.pack(fill="x")

        ttk.Label(frame, text="Nama/Domain server (label laporan saja, opsional):").grid(
            row=0, column=0, sticky="w", pady=2
        )
        self.label_var = tk.StringVar()
        ttk.Entry(frame, textvariable=self.label_var, width=50).grid(
            row=0, column=1, columnspan=2, sticky="we", pady=2
        )

        ttk.Label(frame, text="File log:").grid(row=1, column=0, sticky="w", pady=2)
        self.log_path_var = tk.StringVar()
        ttk.Entry(frame, textvariable=self.log_path_var, width=50).grid(
            row=1, column=1, sticky="we", pady=2
        )
        ttk.Button(frame, text="Pilih File...", command=self._pick_file).grid(
            row=1, column=2, padx=(5, 0)
        )

        ttk.Label(frame, text="Error threshold:").grid(row=2, column=0, sticky="w", pady=2)
        self.threshold_var = tk.StringVar(value="5")
        ttk.Entry(frame, textvariable=self.threshold_var, width=10).grid(
            row=2, column=1, sticky="w", pady=2
        )

        ttk.Label(frame, text="Time window (menit, kosongkan = mode lama):").grid(
            row=3, column=0, sticky="w", pady=2
        )
        self.window_var = tk.StringVar(value="5")
        ttk.Entry(frame, textvariable=self.window_var, width=10).grid(
            row=3, column=1, sticky="w", pady=2
        )

        self.run_button = ttk.Button(
            frame, text="Jalankan Analisis", command=self._on_run_clicked
        )
        self.run_button.grid(row=4, column=0, pady=10, sticky="w")

        self.progress = ttk.Progressbar(frame, mode="indeterminate", length=200)
        self.progress.grid(row=4, column=1, sticky="w", padx=(10, 0))

        frame.columnconfigure(1, weight=1)

    def _build_results_table(self, parent: ttk.Frame) -> None:
        container = ttk.Frame(parent, padding=(10, 0, 10, 10))
        container.pack(fill="both", expand=True)

        self.summary_label = ttk.Label(container, text="Belum ada hasil.")
        self.summary_label.pack(anchor="w", pady=(0, 5))

        columns = ("rule", "severity", "ip", "path", "detail", "timestamp", "evidence_count")
        self.tree = ttk.Treeview(container, columns=columns, show="headings", height=15)
        headers = {
            "rule": "Rule",
            "severity": "Severity",
            "ip": "IP",
            "path": "Path",
            "detail": "Detail",
            "timestamp": "Timestamp",
            "evidence_count": "Count",
        }
        widths = {
            "rule": 150, "severity": 70, "ip": 110, "path": 220,
            "detail": 260, "timestamp": 170, "evidence_count": 50,
        }
        for col in columns:
            self.tree.heading(col, text=headers[col])
            self.tree.column(col, width=widths[col], anchor="w")

        vsb = ttk.Scrollbar(container, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")

        for severity, color in SEVERITY_COLORS.items():
            self.tree.tag_configure(severity, background=color)

        export_frame = ttk.Frame(self, padding=(10, 0, 10, 10))
        export_frame.pack(fill="x")
        self.export_json_button = ttk.Button(
            export_frame, text="Export JSON...", command=self._export_json, state="disabled"
        )
        self.export_json_button.pack(side="left")
        self.export_csv_button = ttk.Button(
            export_frame, text="Export CSV...", command=self._export_csv, state="disabled"
        )
        self.export_csv_button.pack(side="left", padx=(5, 0))

    # --- UI construction: tab "Periksa Domain" (BARU) -------------------

    def _build_domain_tab(self, parent: ttk.Frame) -> None:
        form = ttk.Frame(parent, padding=10)
        form.pack(fill="x")

        ttk.Label(form, text="Target (domain, URL, public IP):").grid(
            row=0, column=0, sticky="w", pady=2
        )
        self.domain_var = tk.StringVar()
        self.domain_entry = ttk.Entry(form, textvariable=self.domain_var, width=60)
        self.domain_entry.grid(row=0, column=1, columnspan=2, sticky="we", pady=2)

        self.domain_validate_button = ttk.Button(
            form, text="Validasi Target", command=self._on_domain_validate_clicked
        )
        self.domain_validate_button.grid(row=1, column=0, sticky="w", pady=(6, 2))
        self.domain_check_button = ttk.Button(
            form, text="Periksa Domain", command=self._on_domain_check_clicked
        )
        self.domain_check_button.grid(row=1, column=1, sticky="w", padx=(8, 0), pady=(6, 2))

        self.domain_progress = ttk.Progressbar(form, mode="indeterminate", length=200)
        self.domain_progress.grid(row=1, column=2, sticky="w", padx=(10, 0), pady=(6, 2))

        form.columnconfigure(1, weight=1)

        preview = ttk.LabelFrame(parent, text="Target validation and assessment scope", padding=8)
        preview.pack(fill="x", padx=10, pady=(2, 4))
        self.domain_normalized_var = tk.StringVar(value="Normalized target: not validated")
        self.domain_validation_var = tk.StringVar(value="Validation status: not started")
        self.domain_scope_var = tk.StringVar(value=ASSESSMENT_SCOPE)
        ttk.Label(preview, textvariable=self.domain_normalized_var, wraplength=900).pack(
            anchor="w"
        )
        ttk.Label(preview, textvariable=self.domain_validation_var, wraplength=900).pack(
            anchor="w"
        )
        ttk.Label(preview, textvariable=self.domain_scope_var, wraplength=900).pack(anchor="w")

        container = ttk.Frame(parent, padding=10)
        container.pack(fill="both", expand=True)

        summary = ttk.LabelFrame(container, text="Assessment summary", padding=6)
        summary.pack(fill="x", pady=(0, 5))
        self.domain_summary_label = ttk.Label(summary, text="No assessment yet.", wraplength=900)
        self.domain_summary_label.pack(anchor="w")
        self.domain_observations_label = ttk.Label(
            summary,
            text="Observations: not available",
            wraplength=900,
            justify="left",
        )
        self.domain_observations_label.pack(anchor="w", pady=(4, 0))

        self.domain_panes = ttk.Panedwindow(container, orient="vertical")
        self.domain_panes.pack(fill="both", expand=True)
        results_frame = ttk.Frame(self.domain_panes)
        guide_panel = ttk.LabelFrame(
            self.domain_panes, text="Panduan Verifikasi Manual", padding=8
        )
        self.domain_panes.add(results_frame, weight=3)
        self.domain_panes.add(guide_panel, weight=2)

        filter_frame = ttk.Frame(results_frame)
        filter_frame.pack(fill="x", pady=(0, 4))
        ttk.Label(filter_frame, text="Filter severity:").pack(side="left")
        self.domain_severity_filter = tk.StringVar(value="All")
        self.domain_severity_combo = ttk.Combobox(
            filter_frame,
            textvariable=self.domain_severity_filter,
            values=("All", "High", "Medium", "Low", "Info"),
            state="readonly",
            width=10,
        )
        self.domain_severity_combo.pack(side="left", padx=(6, 0))
        self.domain_severity_combo.bind(
            "<<ComboboxSelected>>", lambda _event: self._populate_domain_table()
        )

        columns = ("severity", "category", "observation", "evidence", "confidence", "recommendation")
        self.domain_tree = ttk.Treeview(
            results_frame, columns=columns, show="headings", height=8
        )
        headers = {
            "severity": "Severity",
            "category": "Category",
            "observation": "Observations",
            "evidence": "Evidence",
            "confidence": "Confidence",
            "recommendation": "Potential hardening recommendations",
        }
        widths = {
            "severity": 75,
            "category": 95,
            "observation": 270,
            "evidence": 210,
            "confidence": 90,
            "recommendation": 350,
        }
        for col in columns:
            self.domain_tree.heading(
                col, text=headers[col], command=lambda column=col: self._sort_domain_table(column)
            )
            self.domain_tree.column(col, width=widths[col], anchor="w")

        vsb = ttk.Scrollbar(results_frame, orient="vertical", command=self.domain_tree.yview)
        hsb = ttk.Scrollbar(results_frame, orient="horizontal", command=self.domain_tree.xview)
        self.domain_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self.domain_tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")
        hsb.pack(side="bottom", fill="x")
        self.domain_tree.bind("<<TreeviewSelect>>", self._on_finding_selected)

        for severity, color in ASSESSMENT_SEVERITY_COLORS.items():
            self.domain_tree.tag_configure(severity, background=color)

        self.domain_disclaimer_label = ttk.Label(
            results_frame,
            text="Observations and potential hardening recommendations only. "
            "Based on passive metadata from a single bounded request set. "
            "A missing header, banner, or HTTP 200 is not proof of a vulnerability.",
            foreground="#555555",
            wraplength=900,
        )
        self.domain_disclaimer_label.pack(anchor="w", pady=(4, 0))

        ttk.Label(
            guide_panel,
            text="Panduan ini hanya untuk verifikasi pasif dalam scope program yang diizinkan. "
            "Hasil bukan bukti kerentanan.",
            foreground="#7a4b00",
            wraplength=900,
        ).pack(anchor="w", pady=(0, 5))
        guide_text_frame = ttk.Frame(guide_panel)
        guide_text_frame.pack(fill="both", expand=True)
        self.domain_guide_text = tk.Text(
            guide_text_frame, wrap="word", height=10, state="disabled"
        )
        guide_scroll = ttk.Scrollbar(
            guide_text_frame, orient="vertical", command=self.domain_guide_text.yview
        )
        self.domain_guide_text.configure(yscrollcommand=guide_scroll.set)
        self.domain_guide_text.pack(side="left", fill="both", expand=True)
        guide_scroll.pack(side="right", fill="y")
        self.domain_guide_commands = ttk.Frame(guide_panel)
        self.domain_guide_commands.pack(fill="x", pady=(4, 2))
        verification_frame = ttk.Frame(guide_panel)
        verification_frame.pack(fill="x", pady=(4, 0))
        ttk.Label(verification_frame, text="Status Verifikasi Manual:").grid(
            row=0, column=0, sticky="w"
        )
        self.verification_status_var = tk.StringVar(value=VERIFICATION_STATUSES[0])
        self.verification_status_combo = ttk.Combobox(
            verification_frame,
            textvariable=self.verification_status_var,
            values=VERIFICATION_STATUSES,
            state="readonly",
            width=22,
        )
        self.verification_status_combo.grid(row=0, column=1, sticky="w", padx=(5, 10))
        self.domain_save_verification_button = ttk.Button(
            verification_frame,
            text="Simpan Status/Catatan",
            command=self._save_current_verification_state,
            state="disabled",
        )
        self.domain_save_verification_button.grid(row=0, column=2, sticky="w")
        ttk.Label(verification_frame, text="Catatan Verifikasi:").grid(
            row=1, column=0, sticky="nw", pady=(4, 0)
        )
        self.verification_note_text = tk.Text(verification_frame, height=2, wrap="word")
        self.verification_note_text.grid(
            row=1, column=1, columnspan=2, sticky="ew", pady=(4, 0)
        )
        verification_frame.columnconfigure(1, weight=1)
        self.domain_reference_button = ttk.Button(
            verification_frame,
            text="Buka Referensi",
            command=self._open_selected_references,
            state="disabled",
        )
        self.domain_reference_button.grid(row=2, column=1, sticky="w", pady=(4, 0))

        export_frame = ttk.Frame(parent, padding=10)
        export_frame.pack(fill="x")
        self.domain_export_json_button = ttk.Button(
            export_frame, text="Export JSON...", command=self._export_domain_json, state="disabled"
        )
        self.domain_export_json_button.pack(side="left")
        self.domain_export_csv_button = ttk.Button(
            export_frame, text="Export CSV...", command=self._export_domain_csv, state="disabled"
        )
        self.domain_export_csv_button.pack(side="left", padx=(5, 0))
        self.domain_export_markdown_button = ttk.Button(
            export_frame,
            text="Ekspor Panduan (Markdown)...",
            command=self._export_domain_markdown,
            state="disabled",
        )
        self.domain_export_markdown_button.pack(side="left", padx=(5, 0))

    def _build_status_bar(self) -> None:
        self.status_var = tk.StringVar(value="Siap.")
        ttk.Label(self, textvariable=self.status_var, relief="sunken", anchor="w").pack(
            fill="x", side="bottom"
        )

    # --- Event handlers --------------------------------------------------

    def _pick_file(self) -> None:
        path = filedialog.askopenfilename(
            title="Pilih file access log",
            filetypes=[("Log files", "*.log *.txt"), ("Semua file", "*.*")],
        )
        if path:
            self.log_path_var.set(path)

    def _on_run_clicked(self) -> None:
        log_path_str = self.log_path_var.get().strip()
        if not log_path_str:
            messagebox.showerror("Error", "Pilih file log terlebih dahulu.")
            return
        log_path = Path(log_path_str)
        if not log_path.exists():
            messagebox.showerror("Error", f"File tidak ditemukan: {log_path}")
            return

        try:
            threshold = int(self.threshold_var.get())
            if threshold < 1:
                raise ValueError
        except ValueError:
            messagebox.showerror("Error", "Error threshold harus berupa angka >= 1.")
            return

        window_str = self.window_var.get().strip()
        window_minutes = None
        if window_str:
            try:
                window_minutes = int(window_str)
                if window_minutes < 1:
                    raise ValueError
            except ValueError:
                messagebox.showerror("Error", "Time window harus kosong atau angka >= 1.")
                return

        # Nonaktifkan tombol & mulai progress bar supaya user tahu proses
        # sedang berjalan (penting untuk file besar yang makan waktu).
        self.run_button.config(state="disabled")
        self.export_json_button.config(state="disabled")
        self.export_csv_button.config(state="disabled")
        self.progress.start(10)
        self.status_var.set("Memproses...")

        # PENTING: analisis dijalankan di thread TERPISAH, supaya window
        # tidak freeze. Worker tidak boleh menyentuh widget Tkinter
        # langsung -- dia cuma taruh hasil ke queue.
        worker = threading.Thread(
            target=self._run_worker,
            args=(log_path, threshold, window_minutes),
            daemon=True,
        )
        worker.start()
        self.after(100, self._poll_queue)

    def _run_worker(
        self, log_path: Path, threshold: int, window_minutes: int | None
    ) -> None:
        try:
            findings, line_count = run_analysis(log_path, threshold, window_minutes)
            self._result_queue.put(("ok", findings, line_count))
        except Exception as exc:  # noqa: BLE001 -- sengaja tangkap semua,
            # supaya error apa pun (file rusak, permission denied, dll)
            # tetap muncul rapi di UI, bukan bikin thread diam-diam mati.
            self._result_queue.put(("error", str(exc), None))

    def _poll_queue(self) -> None:
        try:
            status, payload, line_count = self._result_queue.get_nowait()
        except queue.Empty:
            self.after(100, self._poll_queue)
            return

        self.progress.stop()
        self.run_button.config(state="normal")

        if status == "error":
            self.status_var.set("Gagal.")
            messagebox.showerror("Error", f"Analisis gagal: {payload}")
            return

        self._findings = payload
        self._populate_table(payload)
        self.export_json_button.config(state="normal")
        self.export_csv_button.config(state="normal")

        label = self.label_var.get().strip() or "(tanpa label)"
        self.summary_label.config(
            text=(
                f"Server: {label} | Baris log: {line_count:,} | "
                f"Total temuan: {len(payload)} "
                f"(high: {sum(1 for f in payload if f.severity == 'high')}, "
                f"medium: {sum(1 for f in payload if f.severity == 'medium')}, "
                f"low: {sum(1 for f in payload if f.severity == 'low')})"
            )
        )
        self.status_var.set("Selesai.")

    def _populate_table(self, findings: list[Finding]) -> None:
        self.tree.delete(*self.tree.get_children())
        for f in findings:
            self.tree.insert(
                "", "end",
                values=(f.rule, f.severity, f.ip, f.path, f.detail, f.timestamp.isoformat(), f.evidence_count),
                tags=(f.severity,),
            )

    def _export_json(self) -> None:
        if not self._findings:
            return
        path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON", "*.json")])
        if path:
            write_json_report(self._findings, path)
            self.status_var.set(f"Disimpan: {path}")

    def _export_csv(self) -> None:
        if not self._findings:
            return
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV", "*.csv")])
        if path:
            write_csv_report(self._findings, path)
            self.status_var.set(f"Disimpan: {path}")

    # --- Event handlers: tab "Periksa Domain" ----------------------------

    def _on_domain_validate_clicked(self) -> None:
        self._begin_domain_validation(assess=False)

    def _on_domain_check_clicked(self) -> None:
        self._begin_domain_validation(assess=True)

    def _begin_domain_validation(self, assess: bool) -> None:
        if self._domain_active:
            return
        raw_input = self.domain_var.get()
        try:
            normalized = normalize_url(raw_input)
        except ValidationError as exc:
            self.domain_validation_var.set(f"Validation status: rejected — {exc}")
            messagebox.showerror("Invalid target", str(exc))
            return

        self._domain_active = True
        self._domain_action = "assess" if assess else "validate"
        self._domain_pending_raw = raw_input
        self.domain_entry.config(state="disabled")
        self.domain_validate_button.config(state="disabled")
        self.domain_check_button.config(state="disabled")
        if assess:
            self._domain_result = None
            self.domain_tree.delete(*self.domain_tree.get_children())
            self.domain_summary_label.config(text="Assessment in progress.")
            self.domain_observations_label.config(text="Observations: assessment in progress.")
            self.domain_export_json_button.config(state="disabled")
            self.domain_export_csv_button.config(state="disabled")
        self.domain_normalized_var.set(f"Normalized target: {normalized}")
        transport_warning = (
            " Warning: HTTP is unencrypted."
            if normalized.startswith("http://")
            else ""
        )
        self.domain_validation_var.set(
            f"Validation status: checking DNS and all returned IPs.{transport_warning}"
        )
        self.domain_progress.start(10)
        self.status_var.set("Validating public target; no HTTP request has started.")
        threading.Thread(
            target=self._run_validation_worker,
            args=(normalized,),
            daemon=True,
        ).start()
        self.after(100, self._poll_domain_queue)

    def _run_validation_worker(self, normalized: str) -> None:
        try:
            validated = validate_target(normalized)
            self._domain_queue.put(("validated", validated))
        except (ValidationError, NetworkError) as exc:
            self._domain_queue.put(("error", exc))
        except Exception as exc:
            self._domain_queue.put(("error", exc))

    def _run_domain_worker(self, raw_input: str) -> None:
        try:
            observations = check_domain(raw_input)
            self._domain_queue.put(("ok", evaluate(observations)))
        except (ValidationError, NetworkError, HttpResponseError) as exc:
            self._domain_queue.put(("error", exc))
        except Exception as exc:
            self._domain_queue.put(("error", exc))

    def _poll_domain_queue(self) -> None:
        try:
            status, payload = self._domain_queue.get_nowait()
        except queue.Empty:
            self.after(100, self._poll_domain_queue)
            return

        if status == "validated":
            self._validated_target = payload
            addresses = ", ".join(payload.addresses)
            transport_warning = (
                " Warning: HTTP is unencrypted."
                if payload.scheme == "http"
                else ""
            )
            self.domain_validation_var.set(
                f"Validation status: public target validated ({addresses}).{transport_warning}"
            )
            if self._domain_action == "assess":
                confirmation_text = (
                    f"Target: {payload.url}\n"
                    f"Validated public IPs: {addresses}\n\n"
                    + ("Warning: HTTP is unencrypted.\n\n" if payload.scheme == "http" else "")
                    + f"Scope: {ASSESSMENT_SCOPE}\n\n"
                    + "Continue only if you are authorized to assess this target?"
                )
                confirmed = messagebox.askyesno(
                    "Confirm authorized assessment",
                    confirmation_text,
                )
                if confirmed:
                    self.status_var.set("Running bounded metadata assessment…")
                    threading.Thread(
                        target=self._run_domain_worker,
                        args=(self._domain_pending_raw,),
                        daemon=True,
                    ).start()
                    self.after(100, self._poll_domain_queue)
                    return
                self.domain_validation_var.set(
                    "Validation status: public target validated; assessment canceled."
                )
            self._finish_domain_action()
            return

        if status == "error":
            self.domain_validation_var.set(f"Validation/assessment status: failed — {payload}")
            self.status_var.set("Assessment failed.")
            messagebox.showerror("Assessment failed", str(payload))
            self._finish_domain_action()
            return

        if status == "ok":
            self._domain_result = payload
            self._populate_domain_table()
            self.domain_export_json_button.config(state="normal")
            self.domain_export_csv_button.config(state="normal")
            self.domain_export_markdown_button.config(state="normal")
            result = payload
            metadata = result.observations
            counts = result.severity_counts
            cookie_summaries = [
                f"{sanitize_display_text(cookie.name, 100)}: "
                f"Secure={'present' if cookie.secure else 'missing'}, "
                f"HttpOnly={'present' if cookie.httponly else 'missing'}, "
                f"SameSite={sanitize_display_text(cookie.samesite or 'missing', 100)}"
                for cookie in metadata.cookies
            ]
            header_summaries = [
                f"{sanitize_display_text(name, 100)}: "
                f"{sanitize_display_text(value, 300)}"
                for name, value in metadata.response_headers
            ]
            certificate_status = (
                "Not assessed"
                if metadata.certificate_valid is None
                else "valid"
                if metadata.certificate_valid
                else "validation failed"
            )
            self.domain_observations_label.config(
                text=(
                    "Observations:\n"
                    f"Status code: {metadata.status_code if metadata.status_code is not None else 'Not assessed'}\n"
                    f"Final URL: {sanitize_display_text(metadata.final_url, 500)}\n"
                    f"HTTPS used: {'Yes' if metadata.https_used else 'No'}; "
                    f"HTTP used: {'Yes' if metadata.http_used else 'No'}; "
                    f"certificate validation: {certificate_status}\n"
                    "Response headers:\n"
                    + ("\n".join(header_summaries) if header_summaries else "Not assessed / none available")
                    + "\nCookie attributes (values withheld):\n"
                    + ("\n".join(cookie_summaries) if cookie_summaries else "No cookies observed")
                )
            )
            self.domain_summary_label.config(
                text=(
                    f"Hardening Score: {result.score}/100 | Grade: {result.grade} | "
                    f"High: {counts['High']}  Medium: {counts['Medium']}  "
                    f"Low: {counts['Low']}  Info: {counts['Info']}\n"
                    f"HTTP status: {metadata.status_code if metadata.status_code is not None else 'unavailable'} | "
                    f"Final URL: {metadata.final_url} | Scope: {metadata.scope}\n"
                    f"Timestamp: {metadata.checked_at.isoformat()} | "
                    f"Ruleset: {result.ruleset_version}"
                )
            )
            completed_message = "Validation status: passed; assessment completed."
            if metadata.http_used:
                completed_message += " Warning: HTTP is unencrypted."
            self.domain_validation_var.set(completed_message)
            self.status_var.set("Assessment completed successfully.")
            self._finish_domain_action()

    def _finish_domain_action(self) -> None:
        self._domain_active = False
        self.domain_progress.stop()
        self.domain_entry.config(state="normal")
        self.domain_validate_button.config(state="normal")
        self.domain_check_button.config(state="normal")

    def _populate_domain_table(self) -> None:
        self._save_current_verification_state()
        self.domain_tree.delete(*self.domain_tree.get_children())
        self._finding_rows.clear()
        self._selected_finding_key = None
        if self._domain_result is None:
            return
        occurrences: dict[str, int] = {}
        selected = filter_assessment_findings(
            self._domain_result.findings, self.domain_severity_filter.get()
        )
        selected_ids = {id(finding) for finding in selected}
        for index, finding in enumerate(self._domain_result.findings):
            occurrence = occurrences.get(finding.id, 0)
            occurrences[finding.id] = occurrence + 1
            if id(finding) not in selected_ids:
                continue
            row_id = f"finding-{index:04d}"
            state_key = verification_key(finding.id, occurrence)
            self._finding_rows[row_id] = (finding, state_key)
            self.domain_tree.insert(
                "",
                "end",
                iid=row_id,
                values=assessment_finding_to_row(finding),
                tags=(finding.severity.lower(),),
            )
        self._clear_guide_selection()

    def _clear_guide_selection(self) -> None:
        self._selected_finding_key = None
        self.domain_save_verification_button.config(state="disabled")
        self.domain_reference_button.config(state="disabled")
        self.verification_status_var.set(VERIFICATION_STATUSES[0])
        self.verification_note_text.delete("1.0", tk.END)
        for child in self.domain_guide_commands.winfo_children():
            child.destroy()
        self._set_guide_text("Pilih satu finding untuk melihat panduan verifikasi.")

    def _set_guide_text(self, text: str) -> None:
        self.domain_guide_text.config(state="normal")
        self.domain_guide_text.delete("1.0", tk.END)
        self.domain_guide_text.insert(tk.END, text)
        self.domain_guide_text.config(state="disabled")

    def _on_finding_selected(self, _event=None) -> None:
        self._save_current_verification_state()
        selection = self.domain_tree.selection()
        if not selection:
            self._clear_guide_selection()
            return
        selected = self._finding_rows.get(selection[0])
        if selected is None:
            self._clear_guide_selection()
            return
        finding, state_key = selected
        self._selected_finding_key = state_key
        self.domain_save_verification_button.config(state="normal")
        self.verification_status_var.set(
            self._verification_states.get(
                state_key, VerificationState()
            ).status
        )
        self.verification_note_text.delete("1.0", tk.END)
        self.verification_note_text.insert(
            "1.0", self._verification_states.get(state_key, VerificationState()).note
        )
        guide = select_finding_guide(finding.id)
        self.domain_reference_button.config(
            state="normal" if guide and guide.references else "disabled"
        )
        self._render_verification_guide(finding, guide)

    def _render_verification_guide(
        self, finding: AssessmentFinding, guide: VerificationGuide | None
    ) -> None:
        if guide is None:
            self._set_guide_text(
                "Tidak ada panduan untuk finding ini. Laporkan kekurangan panduan."
            )
            return
        sections = [
            "Ringkasan",
            sanitize_display_text(guide.summary),
            "",
            "Mengapa Penting",
            sanitize_display_text(guide.why_it_matters),
            "",
            "Langkah Verifikasi",
        ]
        for index, step in enumerate(guide.manual_steps, start=1):
            sections.extend(
                (
                    f"{index}. {sanitize_display_text(step.title)} [{sanitize_display_text(step.tool)}]",
                    f"   {sanitize_display_text(step.instructions)}",
                )
            )
            if step.command_template:
                sections.append("   Perintah tersedia pada tombol Salin Perintah.")
        sections.extend(
            (
                "",
                "Hasil yang Diharapkan — Jika Terkonfirmasi",
                sanitize_display_text(guide.expected_if_confirmed),
                "",
                "Hasil yang Diharapkan — Jika False Positive",
                sanitize_display_text(guide.expected_if_false_positive),
                "",
                "Kemungkinan False Positive",
                *[f"- {sanitize_display_text(item)}" for item in guide.common_false_positives],
                "",
                "Tips Laporan",
                sanitize_display_text(guide.report_tips),
                "",
                "Referensi",
                *[sanitize_display_text(url) for url in guide.references],
                "",
                "Catatan Keamanan",
                sanitize_display_text(guide.safety_note),
                "",
                f"Guide version: {GUIDE_VERSION}",
                f"Finding: {sanitize_display_text(finding.id)}",
            )
        )
        self._set_guide_text("\n".join(sections))
        for index, step in enumerate(guide.manual_steps, start=1):
            if step.command_template is None:
                continue
            ttk.Button(
                self.domain_guide_commands,
                text=f"Salin Perintah ({index}. {step.tool})",
                command=lambda current_step=step: self._copy_verification_command(current_step),
            ).pack(side="left", padx=(0, 5))

    def _copy_verification_command(self, step: Step) -> None:
        if self._validated_target is None:
            messagebox.showerror(
                "Target belum divalidasi",
                "Jalankan Validasi Target terlebih dahulu.",
            )
            return
        try:
            command = render_command(step, self._validated_target)
        except ValueError as exc:
            messagebox.showerror("Perintah tidak dapat dibuat", str(exc))
            return
        self.clipboard_clear()
        self.clipboard_append(command)
        self.status_var.set("Perintah disalin; tidak dijalankan oleh aplikasi.")

    def _save_current_verification_state(self) -> None:
        if self._selected_finding_key is None:
            return
        note = self.verification_note_text.get("1.0", "end-1c")
        self._verification_states[self._selected_finding_key] = VerificationState(
            status=self.verification_status_var.get(),
            note=note[:2000],
        )

    def _open_selected_references(self) -> None:
        if self._selected_finding_key is None:
            return
        finding = next(
            (
                finding
                for finding, state_key in self._finding_rows.values()
                if state_key == self._selected_finding_key
            ),
            None,
        )
        guide = select_finding_guide(finding.id) if finding is not None else None
        if guide is None:
            return
        allowed_urls = set(REFERENCE_URLS.values())
        for url in guide.references:
            if url in allowed_urls:
                webbrowser.open(url)

    def _sort_domain_table(self, column: str) -> None:
        reverse = self._domain_sort_reverse.get(column, False)
        rows = [
            (self.domain_tree.set(item, column), item)
            for item in self.domain_tree.get_children("")
        ]
        severity_order = {"High": 0, "Medium": 1, "Low": 2, "Info": 3}
        if column == "severity":
            rows.sort(key=lambda row: severity_order.get(row[0], 4), reverse=reverse)
        else:
            rows.sort(key=lambda row: row[0].casefold(), reverse=reverse)
        for index, (_value, item) in enumerate(rows):
            self.domain_tree.move(item, "", index)
        self._domain_sort_reverse[column] = not reverse

    def _export_domain_json(self) -> None:
        if not self._domain_result:
            return
        self._save_current_verification_state()
        path = filedialog.asksaveasfilename(
            defaultextension=".json", filetypes=[("JSON", "*.json")]
        )
        if path:
            try:
                write_assessment_json_report(
                    self._domain_result,
                    path,
                    self._verification_states,
                    self._validated_target,
                )
            except OSError as exc:
                messagebox.showerror("Export failed", str(exc))
                return
            self.status_var.set(f"Saved: {path}")

    def _export_domain_csv(self) -> None:
        if not self._domain_result:
            return
        self._save_current_verification_state()
        path = filedialog.asksaveasfilename(
            defaultextension=".csv", filetypes=[("CSV", "*.csv")]
        )
        if path:
            try:
                write_assessment_csv_report(
                    self._domain_result,
                    path,
                    self._verification_states,
                    self._validated_target,
                )
            except OSError as exc:
                messagebox.showerror("Export failed", str(exc))
                return
            self.status_var.set(f"Saved: {path}")

    def _export_domain_markdown(self) -> None:
        if not self._domain_result:
            return
        self._save_current_verification_state()
        path = filedialog.asksaveasfilename(
            defaultextension=".md", filetypes=[("Markdown", "*.md")]
        )
        if path:
            try:
                write_assessment_markdown_report(
                    self._domain_result,
                    path,
                    self._verification_states,
                    self._validated_target,
                )
            except OSError as exc:
                messagebox.showerror("Export failed", str(exc))
                return
            self.status_var.set(f"Saved: {path}")


if __name__ == "__main__":
    App().mainloop()
