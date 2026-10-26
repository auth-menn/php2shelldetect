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
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from php2shell_detect.detectors import Finding, run_all_detectors_streaming
from php2shell_detect.assessment_report import (
    write_csv_report as write_assessment_csv_report,
)
from php2shell_detect.assessment_report import (
    write_json_report as write_assessment_json_report,
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
        f"{finding.status}: {finding.observation}",
        finding.evidence,
        finding.confidence,
        finding.recommendation,
    )


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
        self._domain_sort_reverse: dict[str, bool] = {}

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
        ttk.Entry(form, textvariable=self.domain_var, width=60).grid(
            row=0, column=1, sticky="we", pady=2
        )

        self.domain_validate_button = ttk.Button(
            form, text="Validasi Target", command=self._on_domain_validate_clicked
        )
        self.domain_validate_button.grid(row=1, column=0, sticky="w", pady=(6, 2))
        self.domain_check_button = ttk.Button(
            form, text="Periksa Domain", command=self._on_domain_check_clicked
        )
        self.domain_check_button.grid(row=1, column=1, sticky="w", padx=(8, 0), pady=(6, 2))

        self.domain_progress = ttk.Progressbar(form, mode="indeterminate", length=200)
        self.domain_progress.grid(row=1, column=1, sticky="w", padx=(170, 0), pady=(6, 2))

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

        filter_frame = ttk.Frame(container)
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
        self.domain_tree = ttk.Treeview(container, columns=columns, show="headings", height=13)
        headers = {
            "severity": "Severity",
            "category": "Category",
            "observation": "Observation",
            "evidence": "Evidence",
            "confidence": "Confidence",
            "recommendation": "Potential hardening recommendation",
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

        vsb = ttk.Scrollbar(container, orient="vertical", command=self.domain_tree.yview)
        self.domain_tree.configure(yscrollcommand=vsb.set)
        self.domain_tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")

        for severity, color in ASSESSMENT_SEVERITY_COLORS.items():
            self.domain_tree.tag_configure(severity, background=color)

        self.domain_disclaimer_label = ttk.Label(
            container,
            text="Observations and potential hardening recommendations only. "
            "A missing header, banner, or HTTP 200 is not proof of a vulnerability.",
            foreground="#555555",
            wraplength=900,
        )
        self.domain_disclaimer_label.pack(anchor="w", pady=(4, 0))

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
        self.domain_validate_button.config(state="disabled")
        self.domain_check_button.config(state="disabled")
        self.domain_export_json_button.config(state="disabled")
        self.domain_export_csv_button.config(state="disabled")
        self.domain_normalized_var.set(f"Normalized target: {normalized}")
        self.domain_validation_var.set("Validation status: checking DNS and all returned IPs…")
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
            addresses = ", ".join(payload.addresses)
            self.domain_validation_var.set(
                f"Validation status: public target validated ({addresses})"
            )
            if self._domain_action == "assess":
                confirmed = messagebox.askyesno(
                    "Confirm authorized assessment",
                    f"Target: {payload.url}\n"
                    f"Validated public IPs: {addresses}\n\n"
                    f"Scope: {ASSESSMENT_SCOPE}\n\n"
                    "Continue only if you are authorized to assess this target?",
                )
                if confirmed:
                    self.status_var.set("Running bounded metadata assessment…")
                    threading.Thread(
                        target=self._run_domain_worker,
                        args=(self.domain_var.get(),),
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
            result = payload
            metadata = result.observations
            counts = result.severity_counts
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
            self.domain_validation_var.set("Validation status: passed; assessment completed.")
            self.status_var.set("Assessment completed successfully.")
            self._finish_domain_action()

    def _finish_domain_action(self) -> None:
        self._domain_active = False
        self.domain_progress.stop()
        self.domain_validate_button.config(state="normal")
        self.domain_check_button.config(state="normal")

    def _populate_domain_table(self) -> None:
        self.domain_tree.delete(*self.domain_tree.get_children())
        if self._domain_result is None:
            return
        selected = filter_assessment_findings(
            self._domain_result.findings, self.domain_severity_filter.get()
        )
        for finding in selected:
            self.domain_tree.insert(
                "",
                "end",
                values=assessment_finding_to_row(finding),
                tags=(finding.severity.lower(),),
            )

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
        path = filedialog.asksaveasfilename(
            defaultextension=".json", filetypes=[("JSON", "*.json")]
        )
        if path:
            write_assessment_json_report(self._domain_result, path)
            self.status_var.set(f"Saved: {path}")

    def _export_domain_csv(self) -> None:
        if not self._domain_result:
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".csv", filetypes=[("CSV", "*.csv")]
        )
        if path:
            write_assessment_csv_report(self._domain_result, path)
            self.status_var.set(f"Saved: {path}")


if __name__ == "__main__":
    App().mainloop()
