# client_sockets_gui.py — קליינט סוקטים עם "Server URL" + שמירת קובץ עם סיומת/סוג
import socket
import threading
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, Listbox, END

BUF = 64 * 1024

def parse_host_port(url: str):
    url = url.strip()
    if url.startswith("http://"):
        url = url[7:]
    if url.startswith("https://"):
        url = url[8:]
    if "/" in url:
        url = url.split("/", 1)[0]
    if ":" in url:
        host, port = url.rsplit(":", 1)
        return host.strip(), int(port.strip())
    return url.strip(), 8001

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

class SocketClient:
    def __init__(self, host, port, timeout: float = 30.0):
        self.host = host
        self.port = port
        self.timeout = timeout

    def connect(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        s.connect((self.host, self.port))
        return s

    def list_files(self, client_id):
        s = self.connect()
        try:
            s.sendall(f"LIST {client_id}\n".encode("utf-8"))
            first = recv_line(s)
            if not first.startswith("OK "):
                raise RuntimeError(first)
            count = int(first.split()[1])
            return [recv_line(s) for _ in range(count)]
        finally:
            s.close()

    def upload(self, client_id, path: Path):
        size = path.stat().st_size
        s = self.connect()
        try:
            s.sendall(f"UPLOAD {client_id} {path.name} {size}\n".encode("utf-8"))
            with path.open("rb") as f:
                while True:
                    b = f.read(BUF)
                    if not b:
                        break
                    s.sendall(b)
            resp = recv_line(s)
            if not resp.startswith("OK "):
                raise RuntimeError(resp)
            return resp
        finally:
            s.close()

    def download_to(self, client_id, filename, dest: Path):
        s = self.connect()
        try:
            s.sendall(f"DOWNLOAD {client_id} {filename}\n".encode("utf-8"))
            first = recv_line(s)
            if not first.startswith("OK "):
                raise RuntimeError(first)
            size = int(first.split()[1])
            recv_exact_to_file(s, size, dest)
            return size
        finally:
            s.close()

class ClientGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("File Client (Sockets)")

        self.server_url = tk.StringVar(value="127.0.0.1:8001")
        self.client_id = tk.StringVar(value="customer_a")

        frm = tk.Frame(root, padx=10, pady=10)
        frm.pack(fill="both", expand=True)

        tk.Label(frm, text="Server URL:").grid(row=0, column=0, sticky="e")
        tk.Entry(frm, textvariable=self.server_url, width=40).grid(row=0, column=1, columnspan=2, sticky="we")

        tk.Label(frm, text="Client ID:").grid(row=1, column=0, sticky="e")
        tk.Entry(frm, textvariable=self.client_id, width=20).grid(row=1, column=1, sticky="w")

        tk.Button(frm, text="העלה קובץ…", width=15, command=self.upload_dialog).grid(row=1, column=2, padx=5)
        tk.Button(frm, text="רענן רשימה", width=15, command=self.refresh_list).grid(row=2, column=2, padx=5)

        tk.Label(frm, text="קבצים בשרת:").grid(row=2, column=0, sticky="w")
        self.listbox = Listbox(frm, width=50, height=12)
        self.listbox.grid(row=3, column=0, columnspan=2, sticky="nsew")
        tk.Button(frm, text="הורד נבחר…", width=15, command=self.download_selected).grid(row=3, column=2, padx=5, sticky="n")

        self.log = scrolledtext.ScrolledText(frm, width=70, height=10)
        self.log.grid(row=4, column=0, columnspan=3, pady=10, sticky="nsew")

        frm.grid_columnconfigure(1, weight=1)
        frm.grid_rowconfigure(3, weight=1)

        self.refresh_list()

    def log_write(self, msg):
        self.log.insert("end", msg + "\n")
        self.log.see("end")

    def client(self):
        host, port = parse_host_port(self.server_url.get())
        return SocketClient(host, port, timeout=30.0)

    def run_bg(self, target, *args):
        threading.Thread(target=target, args=args, daemon=True).start()

    # === פעולות ===
    def upload_dialog(self):
        p = filedialog.askopenfilename()
        if p:
            self.run_bg(self.upload_file, Path(p))

    def upload_file(self, path: Path):
        try:
            self.log_write(f"Uploading: {path}")
            resp = self.client().upload(self.client_id.get().strip(), path)
            self.log_write(f"Uploaded: {resp}")
            self.refresh_list()
        except Exception as e:
            self.log_write(f"Error: {e}")

    def refresh_list(self):
        self.run_bg(self._refresh_list)

    def _refresh_list(self):
        try:
            files = self.client().list_files(self.client_id.get().strip())
            self.listbox.delete(0, END)
            for name in files:
                self.listbox.insert(END, name)
            self.log_write(f"Found {len(files)} files for '{self.client_id.get().strip()}'")
        except Exception as e:
            self.log_write(f"Error: {e}")

    def download_selected(self):
        sel = self.listbox.curselection()
        if not sel:
            messagebox.showinfo("הורדה", "לא נבחר קובץ")
            return

        filename = self.listbox.get(sel[0])
        ext = Path(filename).suffix.lower()

        # אם אין סיומת—נציע אחת דיפולטית ונציג סוגים נפוצים כדי שהרשימה לא תישאר ריקה
        common_types = [
            ("PNG (*.png)", "*.png"),
            ("JPEG (*.jpg;*.jpeg)", "*.jpg;*.jpeg"),
            ("GIF (*.gif)", "*.gif"),
            ("WEBP (*.webp)", "*.webp"),
            ("BMP (*.bmp)", "*.bmp"),
            ("MP4 (*.mp4)", "*.mp4"),
            ("MKV (*.mkv)", "*.mkv"),
            ("MP3 (*.mp3)", "*.mp3"),
            ("PDF (*.pdf)", "*.pdf"),
            ("ZIP (*.zip)", "*.zip"),
            ("All files (*.*)", "*.*"),
        ]

        filetypes = []
        if ext:
            filetypes.append((f"{ext[1:].upper()} (*{ext})", f"*{ext}"))
        filetypes.extend(common_types)

        save_to = filedialog.asksaveasfilename(
            initialfile=filename,
            defaultextension=ext if ext else ".bin",
            filetypes=filetypes
        )
        if save_to:
            self.run_bg(self._download_to, filename, Path(save_to))

    def _download_to(self, filename: str, save_to: Path):
        try:
            self.log_write(f"Downloading: {filename}")
            size = self.client().download_to(self.client_id.get().strip(), filename, save_to)
            self.log_write(f"Saved {size} bytes to: {save_to}")
        except Exception as e:
            self.log_write(f"Error: {e}")

if __name__ == "__main__":
    root = tk.Tk()
    ClientGUI(root)
    root.mainloop()
