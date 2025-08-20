# --- proto helpers (no shared.py) ---
import socket, struct, json
def create_connection(host, port, server=False, backlog=1):
    if server:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, port)); s.listen(backlog)
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
import io, zlib, threading, time, mss
from PIL import Image
import win32api, win32con
import keyboard



import socket
HOST = socket.gethostbyname(socket.gethostname())
PORT = 5000
FPS = 12
SCALE = 0.6
QUALITY = 90

def grab_frame(scale=SCALE, quality=QUALITY):
    with mss.mss() as sct:
        shot = sct.grab(sct.monitors[1])   # primary
        img = Image.frombytes("RGB", shot.size, shot.rgb)
        if scale != 1.0:
            img = img.resize((int(img.width*scale), int(img.height*scale),), Image.LANCZOS)
        buf = io.BytesIO(); img.save(buf, "JPEG", quality=quality, optimize=True)
        return img.width, img.height, zlib.compress(buf.getvalue(), 6)

def screen_size():
    return win32api.GetSystemMetrics(0), win32api.GetSystemMetrics(1)

def map_to_screen(x, y, fw, fh):
    sw, sh = screen_size()
    return max(0, min(int(x * (sw/max(fw,1))), sw-1)), max(0, min(int(y * (sh/max(fh,1))), sh-1))

def mouse_move(x, y): win32api.SetCursorPos((x, y))
def mouse_down(btn):
    d = {"left": win32con.MOUSEEVENTF_LEFTDOWN, "right": win32con.MOUSEEVENTF_RIGHTDOWN, "middle": win32con.MOUSEEVENTF_MIDDLEDOWN}[btn]
    win32api.mouse_event(d,0,0,0,0)
def mouse_up(btn):
    u = {"left": win32con.MOUSEEVENTF_LEFTUP, "right": win32con.MOUSEEVENTF_RIGHTUP, "middle": win32con.MOUSEEVENTF_MIDDLEUP}[btn]
    win32api.mouse_event(u,0,0,0,0)
def mouse_click(btn): mouse_down(btn); mouse_up(btn)
def mouse_scroll(delta): win32api.mouse_event(win32con.MOUSEEVENTF_WHEEL,0,0,int(delta),0)

def key_down(k): keyboard.press(k)
def key_up(k):   keyboard.release(k)
def key_press(k): keyboard.send(k)

def tx_loop(sock, running):
    interval = 1.0/max(FPS,1)
    while running[0]:
        try:
            w, h, comp = grab_frame()
            send_packet(sock, {"type":"frame","w":w,"h":h,"codec":"jpeg+zlib"}, comp)
            time.sleep(interval)
        except Exception as e:
            print("TX:", e); running[0] = False; break

def rx_loop(sock, running):
    fw, fh = 1, 1
    while running[0]:
        try:
            header, payload = recv_packet(sock)
            t = header.get("type")
            if t == "sync_frame_size":
                fw, fh = header["w"], header["h"]
            elif t == "mouse":
                act = header["action"]
                if act == "move":
                    x,y = map_to_screen(header["x"], header["y"], fw, fh); mouse_move(x,y)
                elif act == "click":  mouse_click(header.get("button","left"))
                elif act == "down":   mouse_down(header.get("button","left"))
                elif act == "up":     mouse_up(header.get("button","left"))
                elif act == "scroll": mouse_scroll(int(header.get("delta",0)))
            elif t == "key":
                act,key = header["action"], header["key"]
                if   act=="press": key_press(key)
                elif act=="down":  key_down(key)
                elif act=="up":    key_up(key)
        except Exception as e:
            print("RX:", e); running[0] = False; break

if __name__ == "__main__":
    print(f"Waiting on {HOST}:{PORT}...")
    sock, addr = create_connection(HOST, PORT, server=True)
    print("Client connected:", addr)
    running = [True]
    threading.Thread(target=tx_loop, args=(sock,running), daemon=True).start()
    threading.Thread(target=rx_loop, args=(sock,running), daemon=True).start()
    try:
        while running[0]: time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    running[0] = False
    try: sock.close()
    except: pass
