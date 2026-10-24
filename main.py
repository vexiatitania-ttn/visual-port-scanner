import socket
import threading
from queue import Queue, Empty

import customtkinter as ctk

# ====== KONFIGURASI ======
PORT_RANGE = range(1, 101)   # port 1-100
NUM_THREADS = 30             # jumlah worker pemindai
TIMEOUT = 1.5                # detik

# Antrean pesan: thread scanner -> GUI (satu-satunya "jembatan" antar thread)
ui_queue = Queue()
DONE = object()              # penanda "scan selesai"


# ====== BACKEND (jalan di thread terpisah, TIDAK menyentuh widget) ======
def scan_port(target_host, target_ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(TIMEOUT)
            if s.connect_ex((target_ip, port)) == 0:
                try:
                    request = f"HEAD / HTTP/1.1\r\nHost: {target_host}\r\nConnection: close\r\n\r\n"
                    s.send(request.encode())
                    banner = s.recv(1024).decode(errors="ignore").split("\n")[0].strip()
                    if not banner:
                        banner = "No banner"
                except OSError:
                    banner = "No banner"
                ui_queue.put(f"[+] Port {port} Open | {banner[:40]}")
    except OSError:
        pass


def worker(port_queue, target_host, target_ip):
    while True:
        try:
            port = port_queue.get_nowait()
        except Empty:
            return
        try:
            scan_port(target_host, target_ip, port)
        finally:
            port_queue.task_done()


def run_scan(target_host):
    try:
        target_ip = socket.gethostbyname(target_host)
    except socket.gaierror:
        ui_queue.put("[-] Error: Host tidak ditemukan / gagal di-resolve!")
        ui_queue.put(DONE)
        return

    ui_queue.put(f"[*] Target: {target_host} ({target_ip})")

    port_queue = Queue()
    for p in PORT_RANGE:
        port_queue.put(p)

    for _ in range(NUM_THREADS):
        threading.Thread(
            target=worker, args=(port_queue, target_host, target_ip), daemon=True
        ).start()

    port_queue.join()  # tunggu semua port selesai dipindai
    ui_queue.put("[*] Selesai!")
    ui_queue.put(DONE)


# ====== GUI (hanya thread utama yang boleh menyentuh widget) ======
def start_scan():
    target = entry_target.get().strip()
    textbox_result.delete("1.0", "end")
    if not target:
        textbox_result.insert("end", "[-] Error: Masukkan target!\n")
        return

    button_scan.configure(state="disabled")  # cegah scan ganda
    textbox_result.insert("end", f"[*] Scanning: {target}\n")
    threading.Thread(target=run_scan, args=(target,), daemon=True).start()


def process_ui_queue():
    try:
        while True:
            msg = ui_queue.get_nowait()
            if msg is DONE:
                button_scan.configure(state="normal")
            else:
                textbox_result.insert("end", msg + "\n")
                textbox_result.see("end")  # auto-scroll
    except Empty:
        pass
    app.after(100, process_ui_queue)  # jadwalkan ulang pengecekan


ctk.set_appearance_mode("dark")
app = ctk.CTk()
app.title("Port Scanner")
app.geometry("500x450")

entry_target = ctk.CTkEntry(app, width=300)
entry_target.pack(pady=10)

button_scan = ctk.CTkButton(app, text="Start Scan", command=start_scan)
button_scan.pack(pady=10)

textbox_result = ctk.CTkTextbox(app, width=450, height=200)
textbox_result.pack(pady=10)

process_ui_queue()  # mulai "pemantau" antrean
app.mainloop()