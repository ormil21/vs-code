# --- proto helpers (no shared.py) ---
import socket, struct, json
def create_connection(host, port, server=False):
    if server:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, port)); s.listen(1)
        conn, addr = s.accept(); s.close()
        return conn, addr
    else:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((host, port))
        return s, (host, port)
def send_packet(sock, header: dict, payload: bytes = b""):
    h = json.dumps(header).encode("utf-8")
    sock.sendall(struct.pack("!I", len(h)) + h + struct.pack("!I", len(payload)) + payload)
def _recvn(sock, n):
    b = b""
    while len(b) < n:
        ch = sock.recv(n - len(b))
        if not ch: raise ConnectionError("socket closed")
        b += ch
    return b
def recv_packet(sock):
    hlen = struct.unpack("!I", _recvn(sock, 4))[0]
    header = json.loads(_recvn(sock, hlen).decode("utf-8"))
    plen = struct.unpack("!I", _recvn(sock, 4))[0]
    payload = _recvn(sock, plen) if plen else b""
    return header, payload

# --- app ---
import io, zlib, threading
import tkinter as tk
from tkinter import simpledialog, messagebox
from PIL import Image, ImageTk

PORT = 5000

class RemoteGUI:
    def __init__(self, root, sock):
        self.root = root; self.sock = sock
        self.root.title("Remote Control - LAN")
        self.img_label = tk.Label(root, bd=0); self.img_label.pack()
        self.frame_w = 1; self.frame_h = 1; self._imgtk = None

        # mouse
        self.img_label.bind("<Motion>", self.on_mouse_move)
        self.img_label.bind("<ButtonPress-1>", lambda e: self.mouse("down","left"))
        self.img_label.bind("<ButtonRelease-1>", lambda e: self.mouse("up","left"))
        self.img_label.bind("<Double-Button-1>", lambda e: self.mouse("click","left"))
        self.img_label.bind("<ButtonPress-3>", lambda e: self.mouse("down","right"))
        self.img_label.bind("<ButtonRelease-3>", lambda e: self.mouse("up","right"))
        self.img_label.bind("<Double-Button-3>", lambda e: self.mouse("click","right"))
        self.img_label.bind("<ButtonPress-2>", lambda e: self.mouse("down","middle"))
        self.img_label.bind("<ButtonRelease-2>", lambda e: self.mouse("up","middle"))
        self.img_label.bind("<MouseWheel>", self.on_wheel)      # Win/mac
        self.img_label.bind("<Button-4>", lambda e: self.scroll(+120))  # Linux
        self.img_label.bind("<Button-5>", lambda e: self.scroll(-120))

        # keyboard
        root.bind("<KeyPress>", self.on_key_down)
        root.bind("<KeyRelease>", self.on_key_up)

        threading.Thread(target=self.rx_frames, daemon=True).start()

    def rx_frames(self):
        while True:
            try:
                header, payload = recv_packet(self.sock)
                if header.get("type") != "frame": continue
                data = zlib.decompress(payload)
                img = Image.open(io.BytesIO(data))
                self.frame_w, self.frame_h = header["w"], header["h"]
                self._imgtk = ImageTk.PhotoImage(img)
                self.root.after(0, lambda im=self._imgtk: self.update_image(im))
                send_packet(self.sock, {"type":"sync_frame_size","w":self.frame_w,"h":self.frame_h})
            except Exception as e:
                print("Receive:", e)
                messagebox.showerror("Connection","Disconnected."); break

    def update_image(self, imtk):
        self.img_label.configure(image=imtk); self.img_label.image = imtk

    # mouse
    def on_mouse_move(self, ev):
        send_packet(self.sock, {"type":"mouse","action":"move","x":int(ev.x),"y":int(ev.y)})
    def mouse(self, action, button):
        send_packet(self.sock, {"type":"mouse","action":action,"button":button})
    def on_wheel(self, ev): self.scroll(ev.delta)
    def scroll(self, delta):
        send_packet(self.sock, {"type":"mouse","action":"scroll","delta":int(delta)})

    # keyboard
    def on_key_down(self, ev):
        send_packet(self.sock, {"type":"key","action":"down","key":self.norm(ev.keysym)})
    def on_key_up(self, ev):
        send_packet(self.sock, {"type":"key","action":"up","key":self.norm(ev.keysym)})

    @staticmethod
    def norm(keysym:str)->str:
        k = keysym.lower()
        m = {"return":"enter","backspace":"backspace","escape":"esc","space":"space","tab":"tab",
             "shift_l":"shift","shift_r":"shift","control_l":"ctrl","control_r":"ctrl",
             "alt_l":"alt","alt_r":"alt","super_l":"windows","super_r":"windows",
             "left":"left","right":"right","up":"up","down":"down","prior":"pageup","next":"pagedown",
             "home":"home","end":"end","insert":"insert","delete":"delete",
             "minus":"-","equal":"=","comma":",","period":".","slash":"/",
             "semicolon":";","apostrophe":"'","bracketleft":"[","bracketright":"]","backslash":"\\"}
        return m.get(k, k)

def connect_dialog(root):
    ip = simpledialog.askstring("Connect","Server IP (LAN):", parent=root)
    if not ip: raise SystemExit
    try:
        sock, _ = create_connection(ip.strip(), PORT, server=False); return sock
    except Exception as e:
        messagebox.showerror("Error", f"Failed to connect: {e}"); raise SystemExit

if __name__ == "__main__":
    root = tk.Tk()
    sock = connect_dialog(root)
    RemoteGUI(root, sock)
    root.mainloop()
