import socket
import threading
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
from werkzeug.utils import secure_filename

BUF = 64 * 1024

def recv_line(sock):
    data = bytearray()
    while True:
        ch = sock.recv(1)
        if not ch:
            raise ConnectionError("Closed while reading line")
        if ch == b"\n":
            break
        data.extend(ch)
    return data.decode("utf-8", "replace")

def recv_exact_to_file(sock, size, dest: Path):
    with dest.open("wb") as f:
        remain = size
        while remain > 0:
            chunk = sock.recv(min(BUF, remain))
            if not chunk:
                raise ConnectionError("Closed while reading file data")
            f.write(chunk)
            remain -= len(chunk)

class FileServer:
    def __init__(self, host, port, storage_root, log_cb):
        self.host = host
        self.port = port
        self.storage_root = storage_root
        self.log_cb = log_cb
        self.server_socket = None
        self.running = False

    def log(self, msg):
        self.log_cb(msg)

    def client_folder(self, client_id):
        safe = secure_filename(client_id or "").strip()
        if not safe:
            raise ValueError("client_id is required")
        folder = self.storage_root / safe
        folder.mkdir(parents=True, exist_ok=True)
        return folder

    def start(self):
        if self.running:
            return
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(20)
        self.running = True
        threading.Thread(target=self.accept_loop, daemon=True).start()
        self.log(f"Server listening on {self.host}:{self.port}")

    def stop(self):
        self.running = False
        if self.server_socket:
            try:
                self.server_socket.shutdown(socket.SHUT_RDWR)
            except:
                pass
            self.server_socket.close()
            self.server_socket = None
        self.log("Server stopped.")

    def send_line(self, sock, text):
        sock.sendall((text + "\n").encode("utf-8"))

    def accept_loop(self):
        while self.running:
            try:
                client, addr = self.server_socket.accept()
                threading.Thread(target=self.handle_client, args=(client, addr), daemon=True).start()
            except OSError:
                break

    def handle_client(self, sock, addr):
        with sock:
            try:
                line = recv_line(sock).strip()
                if not line:
                    self.send_line(sock, "ERR empty")
                    return
                parts = line.split()
                cmd = parts[0].upper()

                if cmd == "LIST":
                    cid = parts[1]
                    folder = self.client_folder(cid)
                    files = sorted([p.name for p in folder.iterdir() if p.is_file()])
                    self.send_line(sock, f"OK {len(files)}")
                    for name in files:
                        self.send_line(sock, name)
                    self.log(f"[{addr}] LIST {cid} ({len(files)} files)")

                elif cmd == "UPLOAD":
                    cid = parts[1]
                    size = int(parts[-1])
                    filename = " ".join(parts[2:-1])
                    safe = secure_filename(filename)
                    folder = self.client_folder(cid)
                    dest = folder / safe
                    recv_exact_to_file(sock, size, dest)
                    self.send_line(sock, f"OK {dest.stat().st_size}")
                    self.log(f"[{addr}] UPLOAD {cid}/{safe} ({size} bytes)")

                elif cmd == "DOWNLOAD":
                    cid = parts[1]
                    filename = " ".join(parts[2:])
                    safe = secure_filename(filename)
                    folder = self.client_folder(cid)
                    full = folder / safe
                    if not full.exists():
                        self.send_line(sock, "ERR not found")
                        return
                    size = full.stat().st_size
                    self.send_line(sock, f"OK {size}")
                    with full.open("rb") as f:
                        while True:
                            b = f.read(BUF)
                            if not b:
                                break
                            sock.sendall(b)
                    self.log(f"[{addr}] DOWNLOAD {cid}/{safe} ({size} bytes)")

                else:
                    self.send_line(sock, "ERR unknown")

            except Exception as e:
                self.log(f"Error: {e}")

class ServerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("File Server (Sockets)")
        self.server = None

        self.host = tk.StringVar(value="127.0.0.1")
        self.port = tk.StringVar(value="8001")
        self.storage = tk.StringVar(value=str(Path("storage").resolve()))

        frm = tk.Frame(root, padx=10, pady=10)
        frm.pack(fill="both", expand=True)

        tk.Label(frm, text="Host:").grid(row=0, column=0, sticky="e")
        tk.Entry(frm, textvariable=self.host, width=15).grid(row=0, column=1, sticky="w")
        tk.Label(frm, text="Port:").grid(row=0, column=2, sticky="e")
        tk.Entry(frm, textvariable=self.port, width=8).grid(row=0, column=3, sticky="w")

        tk.Label(frm, text="Storage Folder:").grid(row=1, column=0, sticky="e")
        tk.Entry(frm, textvariable=self.storage, width=50).grid(row=1, column=1, columnspan=3, sticky="we")
        tk.Button(frm, text="בחר תיקייה…", command=self.choose_folder).grid(row=1, column=4, padx=5)

        self.btn_start = tk.Button(frm, text="הפעל שרת", width=15, command=self.start_server)
        self.btn_start.grid(row=2, column=0, pady=10)

        self.btn_stop = tk.Button(frm, text="כבה שרת", width=15, state="disabled", command=self.stop_server)
        self.btn_stop.grid(row=2, column=1, pady=10)

        self.lbl_status = tk.Label(frm, text="שרת כבוי", fg="red")
        self.lbl_status.grid(row=2, column=2, columnspan=3, sticky="w")

        self.log = scrolledtext.ScrolledText(frm, width=80, height=15)
        self.log.grid(row=3, column=0, columnspan=5, pady=10, sticky="nsew")

    def choose_folder(self):
        p = filedialog.askdirectory(initialdir=self.storage.get() or ".")
        if p:
            self.storage.set(p)

    def log_write(self, msg):
        self.log.insert("end", msg + "\n")
        self.log.see("end")

    def start_server(self):
        try:
            host = self.host.get().strip()
            port = int(self.port.get().strip())
            storage_root = Path(self.storage.get().strip())
            storage_root.mkdir(parents=True, exist_ok=True)
            self.server = FileServer(host, port, storage_root, self.log_write)
            self.server.start()
            self.btn_start.config(state="disabled")
            self.btn_stop.config(state="normal")
            self.lbl_status.config(text="שרת פעיל", fg="green")
        except Exception as e:
            messagebox.showerror("שגיאה", str(e))

    def stop_server(self):
        if self.server:
            self.server.stop()
        self.btn_start.config(state="normal")
        self.btn_stop.config(state="disabled")
        self.lbl_status.config(text="שרת כבוי", fg="red")

if __name__ == "__main__":
    root = tk.Tk()
    ServerGUI(root)
    root.mainloop()
