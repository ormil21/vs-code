import os
import time
import requests
import threading
import tkinter as tk
from tkinter import filedialog, ttk
from PIL import Image, ImageTk
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import tempfile  
import shutil    

API_KEY = '0e5f0c7f851381c8dbce5aad267fdec7d90f9aae38c14e21af93b353406a8a89'
SCAN_URL = 'https://www.virustotal.com/vtapi/v2/file/scan'
REPORT_URL = 'https://www.virustotal.com/vtapi/v2/file/report'
MAX_SIZE_MB = 31
MAX_SIZE_BYTES = MAX_SIZE_MB * 1024 * 1024


# מחלקת מעקב קבצים
class FileCreatedHandler(FileSystemEventHandler):
    def __init__(self, callback):
        super().__init__()
        self.callback = callback

    def on_created(self, event):
        if not event.is_directory:
            self.callback(event.src_path)


# ממשק גרפי
class VirusScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("VirusTotal Scanner")
        self.folder_path = tk.StringVar()
        self.files = []
        self.observer = None

        img = Image.open("logo.png")
        img = img.resize((80, 80))
        self.logo_img = ImageTk.PhotoImage(img)
        tk.Label(root, image=self.logo_img, bg="#d0e0ea").pack(pady=(10, 0))
        root.iconphoto(False, self.logo_img)

        frame_top = tk.Frame(root, bg="#d0e0ea")
        frame_top.pack(pady=10)

        tk.Label(frame_top, text="בחר תיקייה לסריקה:", font=("Segoe UI", 12, "bold"), bg="#d0e0ea").pack()

        btn_frame = tk.Frame(root, bg="#d0e0ea")
        btn_frame.pack(pady=5)

        browse_btn = tk.Button(btn_frame, text="📁 Browse Folder", font=("Segoe UI", 10), command=self.browse_folder, relief="raised", bd=2)
        browse_btn.pack(side=tk.LEFT, padx=5)

        self.scan_button = tk.Button(btn_frame, text="🛡️ Start Scan", font=("Segoe UI", 10, "bold"), bg="#2dce45", fg="white", relief="raised", bd=2, command=self.start_scan_thread)
        self.scan_button.pack(side=tk.LEFT, padx=5)

        self.path_label = tk.Label(root, textvariable=self.folder_path, font=("Segoe UI", 9), fg="#003366", bg="#d0e0ea")
        self.path_label.pack(pady=(0, 10))

        self.current_file_label = tk.Label(root, text="", font=("Segoe UI", 10, "bold"), bg="#d0e0ea")
        self.current_file_label.pack(pady=(0, 5))

        self.timer_label = tk.Label(root, text="", fg="gray", bg="#d0e0ea")
        self.timer_label.pack(pady=(0, 10))

        style = ttk.Style()
        style.configure("TProgressbar", troughcolor='#e0e0e0', background='#4a90e2', thickness=20)
        self.progress = ttk.Progressbar(root, length=500, mode="determinate", style="TProgressbar")
        self.progress.pack(pady=5)

        self.output_text = tk.Text(root, height=14, width=85, font=("Consolas", 10), wrap=tk.WORD, borderwidth=2, relief="solid")
        self.output_text.pack(pady=10, padx=10)

    def browse_folder(self):
        folder = filedialog.askdirectory()
        if folder:
            self.folder_path.set(folder)
            self.output_text.delete(1.0, tk.END)
            self.output_text.insert(tk.END, f"Selected folder:\n{folder}\n\n")

            if self.observer:
                self.observer.stop()

            event_handler = FileCreatedHandler(self.auto_scan_file)
            self.observer = Observer()
            self.observer.schedule(event_handler, path=folder, recursive=False)
            self.observer.start()

    def start_scan_thread(self):
        self.scan_button.config(state="disabled")
        thread = threading.Thread(target=self.scan_files)
        thread.start()

    def scan_files(self):
        folder = self.folder_path.get()
        if not folder or not os.path.exists(folder):
            self.output_text.insert(tk.END, "❌ Folder not selected or doesn't exist.\n")
            self.scan_button.config(state="normal")
            return

        scan_links_file = open("scan_links.txt", "w", encoding="utf-8")
        self.files = [f for f in os.listdir(folder) if os.path.isfile(os.path.join(folder, f))]
        self.progress["maximum"] = len(self.files)
        self.progress["value"] = 0

        for filename in self.files:
            full_path = os.path.join(folder, filename)

            self.current_file_label.config(text=f"🔍 Scanning: {filename}")
            self.root.update()

            if os.path.getsize(full_path) > MAX_SIZE_BYTES:
                self.output_text.insert(tk.END, f"⏭️ Skipping {filename} (over {MAX_SIZE_MB}MB)\n")
                self.progress["value"] += 1
                self.root.update()
                continue

            self.output_text.insert(tk.END, f"📤 Sending {filename}...\n")
            self.root.update()

            try:
                with open(full_path, 'rb') as f:
                    files = {'file': (filename, f)}
                    params = {'apikey': API_KEY}
                    response = requests.post(SCAN_URL, files=files, params=params)

                    if response.status_code == 200:
                        result = response.json()
                        permalink = result.get("permalink", "N/A")
                        resource = result.get("resource", "")
                        scan_links_file.write(f"{filename}: {permalink}\n")
                        self.output_text.insert(tk.END, f"✅ Sent! Link: {permalink}\n")

                        for t in range(20, 0, -1):
                            self.timer_label.config(text=f"⏳ Waiting {t} seconds for report...")
                            self.root.update()
                            time.sleep(1)
                        self.timer_label.config(text="")

                        report_params = {'apikey': API_KEY, 'resource': resource}
                        report_response = requests.get(REPORT_URL, params=report_params)

                        if report_response.status_code == 200:
                            report_data = report_response.json()
                            positives = report_data.get('positives', 'N/A')
                            total = report_data.get('total', 'N/A')
                            self.output_text.insert(tk.END, f"🧪 Report: {positives}/{total} engines detected malware.\n\n")
                        else:
                            self.output_text.insert(tk.END, "❌ Failed to get report.\n\n")
                    else:
                        self.output_text.insert(tk.END, f"❌ Error during scan: {response.status_code}\n\n")

            except Exception as e:
                self.output_text.insert(tk.END, f"❌ Error processing {filename}: {e}\n\n")

            self.progress["value"] += 1
            self.root.update()

        scan_links_file.close()
        self.output_text.insert(tk.END, "\n✅ Done! Links saved to 'scan_links.txt'\n")
        self.current_file_label.config(text="")
        self.scan_button.config(state="normal")

    def auto_scan_file(self, file_path):
        file_path = os.path.normpath(file_path)
        filename = os.path.basename(file_path)

        if not os.path.exists(file_path) or not os.access(file_path, os.R_OK):
            self.output_text.insert(tk.END, f"❌ File inaccessible: {file_path}\n")
            return

        self.output_text.insert(tk.END, f"\n📥 New file detected: {filename}\n")
        self.root.update()

        if os.path.getsize(file_path) > MAX_SIZE_BYTES:
            self.output_text.insert(tk.END, f"⏭️ Skipping {filename} (over {MAX_SIZE_MB}MB)\n")
            return

        try:
            temp_path = os.path.join(tempfile.gettempdir(), filename)
            shutil.copy2(file_path, temp_path)
        except Exception as e:
            self.output_text.insert(tk.END, f"❌ Cannot copy file to temp: {e}\n")
            return

        try:
            with open(temp_path, 'rb') as f:
                files = {'file': (filename, f)}
                params = {'apikey': API_KEY}
                response = requests.post(SCAN_URL, files=files, params=params)
        except Exception as e:
            self.output_text.insert(tk.END, f"❌ Failed to send file: {e}\n")
            return

        if response.status_code == 200:
            result = response.json()
            permalink = result.get("permalink", "N/A")
            resource = result.get("resource", "")
            self.output_text.insert(tk.END, f"✅ Sent! Link: {permalink}\n")

            for t in range(20, 0, -1):
                self.timer_label.config(text=f"⏳ Waiting {t} seconds for report...")
                self.root.update()
                time.sleep(1)
            self.timer_label.config(text="")

            report_params = {'apikey': API_KEY, 'resource': resource}
            report_response = requests.get(REPORT_URL, params=report_params)

            if report_response.status_code == 200:
                report_data = report_response.json()
                positives = report_data.get('positives', 'N/A')
                total = report_data.get('total', 'N/A')
                self.output_text.insert(tk.END, f"🧪 Report: {positives}/{total} engines detected malware.\n\n")
            else:
                self.output_text.insert(tk.END, "❌ Failed to get report.\n\n")
        else:
            self.output_text.insert(tk.END, f"❌ Error during scan: {response.status_code}\n\n")


# מסך פתיחה
def launch_main_app(splash):
    splash.destroy()
    main_window = tk.Tk()
    main_window.geometry("800x600")
    bg_image = Image.open("background.png").resize((800, 600))
    bg_photo = ImageTk.PhotoImage(bg_image)
    tk.Label(main_window, image=bg_photo).place(x=0, y=0, relwidth=1, relheight=1)
    app = VirusScannerGUI(main_window)
    main_window.mainloop()

if __name__ == "__main__":
    splash = tk.Tk()
    splash.geometry("400x700")
    splash.title("Welcome to Antivirus")
    splash_bg = Image.open("sp2.png").resize((400, 900))
    splash_img = ImageTk.PhotoImage(splash_bg)
    tk.Label(splash, image=splash_img).place(x=0, y=0, relwidth=1, relheight=1)
    tk.Label(splash, text="Welcome to Antivirus", font=("Arial", 20, "bold"), bg="#007a5e", fg="white", padx=10, pady=5).place(relx=0.5, rely=0.06, anchor=tk.CENTER)
    tk.Button(splash, text="Scan Now", font=("Arial", 16, "bold"), bg="#004d33", fg="white", padx=20, pady=10, relief="raised", command=lambda: launch_main_app(splash)).place(relx=0.5, rely=0.85, anchor=tk.CENTER)
    splash.mainloop()
