import os
import csv
import socket
import threading
import time
from operator import itemgetter
from queue import Empty, Queue

import customtkinter as ctk

PORTS = range(1, 1025)
NUM_THREADS = 50
TIMEOUT = 1.5
UI_POLL_MS = 100
CSV_FILE = "Network_Audit_Report.csv"
HTTP_PORTS = frozenset({80})
CSV_UNSAFE = ("=", "+", "-", "@")

RISK_MAP = {
    21: "FTP rentan (kredensial plaintext)",
    22: "SSH (pastikan auth kunci & versi terbaru)",
    23: "Telnet BAHAYA (tanpa enkripsi)",
    25: "SMTP (cek risiko open relay)",
    53: "DNS (cek zone transfer)",
    80: "HTTP plaintext",
    110: "POP3 plaintext",
    139: "NetBIOS (rentan enumerasi)",
    143: "IMAP plaintext",
    445: "SMB KRITIS (target ransomware/exploit)",
    3306: "Database MySQL terbuka",
}

results = []
results_lock = threading.Lock()
ui_lock = threading.Lock()
ui_queue = Queue()
DONE = object()


def grab_banner(sock, target, port):
    try:
        if port in HTTP_PORTS:
            sock.sendall(f"HEAD / HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n".encode())
        data = sock.recv(1024)
    except OSError:
        return "No banner"
    line = data.decode(errors="ignore").partition("\n")[0]
    banner = "".join(filter(str.isprintable, line)).strip()[:60]
    return banner or "No banner"


def scan_port(target, ip, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(TIMEOUT)
        if s.connect_ex((ip, port)) != 0:
            return
        banner = grab_banner(s, target, port)
    risk = RISK_MAP.get(port, "Relatif Aman")
    with results_lock:
        results.append((target, ip, port, risk, banner))
    ui_queue.put(f"[+] Port {port} TERBUKA | {risk} | {banner}")


def worker(port_queue, target, ip):
    while True:
        try:
            port = port_queue.get_nowait()
        except Empty:
            return
        try:
            scan_port(target, ip, port)
        except OSError:
            pass


def run_audit(target):
    try:
        try:
            ip = socket.gethostbyname(target)
        except (socket.gaierror, UnicodeError):
            ui_queue.put("[-] Error: Target tidak valid / gagal di-resolve!")
            return

        ui_queue.put(f"[*] Audit dimulai: {target} ({ip}) | port {PORTS.start}-{PORTS.stop - 1}")
        port_queue = Queue()
        for p in PORTS:
            port_queue.put_nowait(p)

        t0 = time.perf_counter()
        threads = [
            threading.Thread(target=worker, args=(port_queue, target, ip), daemon=True)
            for _ in range(NUM_THREADS)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        with results_lock:
            total = len(results)
        ui_queue.put(f"[*] Selesai: {total} port terbuka | {time.perf_counter() - t0:.1f} detik")
    finally:
        ui_queue.put(DONE)


def append_log(text):
    with ui_lock:
        textbox_result.insert("end", text)
        textbox_result.see("end")


def csv_safe(text):
    return "'" + text if text.startswith(CSV_UNSAFE) else text


def start_audit():
    target = entry_target.get().strip()
    with ui_lock:
        textbox_result.delete("1.0", "end")
    if not target:
        append_log("[-] Error: Masukkan target!\n")
        return

    with results_lock:
        results.clear()
    btn_start.configure(state="disabled")
    btn_export.configure(state="disabled")
    append_log(f"[*] Memvalidasi target: {target}\n")
    threading.Thread(target=run_audit, args=(target,), daemon=True).start()


def export_csv():
    with results_lock:
        rows = sorted(results, key=itemgetter(2))
    if not rows:
        append_log("[-] Tidak ada data untuk diexport.\n")
        return

    csv_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), CSV_FILE)

    try:
        with open(csv_path, "w", newline="", encoding="utf-8-sig") as f:
            writer = csv.writer(f)
            writer.writerow(("Target", "IP", "Port", "Penilaian Risiko", "Banner"))
            writer.writerows(row[:4] + (csv_safe(row[4]),) for row in rows)
    except OSError as err:
        append_log(f"[-] Gagal export: {err}\n")
    else:
        append_log(f"[+] {len(rows)} baris berhasil diexport.\n[+] Lokasi file: {csv_path}\n")

def pump_ui():
    lines, finished = [], False
    try:
        while True:
            item = ui_queue.get_nowait()
            if item is DONE:
                finished = True
            else:
                lines.append(item)
    except Empty:
        pass

    if lines:
        append_log("\n".join(lines) + "\n")
    if finished:
        btn_start.configure(state="normal")
        with results_lock:
            has_data = bool(results)
        btn_export.configure(state="normal" if has_data else "disabled")
    app.after(UI_POLL_MS, pump_ui)


ctk.set_appearance_mode("dark")
app = ctk.CTk()
app.title("Advanced Network Recon Tool")
app.geometry("680x540")

entry_target = ctk.CTkEntry(app, width=380, placeholder_text="Target (IP / domain), mis. scanme.nmap.org")
entry_target.pack(pady=(15, 10))

frame_buttons = ctk.CTkFrame(app, fg_color="transparent")
frame_buttons.pack(pady=5)
btn_start = ctk.CTkButton(frame_buttons, text="Mulai Audit", command=start_audit)
btn_start.pack(side="left", padx=5)
btn_export = ctk.CTkButton(frame_buttons, text="Export CSV", command=export_csv, state="disabled")
btn_export.pack(side="left", padx=5)

textbox_result = ctk.CTkTextbox(app, width=640, height=380)
textbox_result.pack(padx=15, pady=10, fill="both", expand=True)

pump_ui()
app.mainloop()