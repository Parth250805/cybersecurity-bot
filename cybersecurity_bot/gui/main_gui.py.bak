from pathlib import Path

CONFIG_PATH = Path(__file__).resolve().parents[1] / "config" / "config.yaml"
CONFIG_PATH = Path(__file__).resolve().parents[1] / "config" / "config.yaml"
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import os
import re
import threading
import time
import queue
import math
from datetime import datetime
import psutil
import yaml
from collections import deque

from cybersecurity_bot.core.predictor import predict_process_risk
from cybersecurity_bot.utils.killer import kill_process
from cybersecurity_bot.core.vt_scanner import get_file_hash, check_virustotal


class ProSecurityGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("🛡️ Cybersecurity Bot - Professional Control Panel")
        self.root.geometry("1200x780")
        self.root.configure(bg="#0a0a0a")

        # Colors
        self.c = {
            "bg": "#0a0a0a",
            "card": "#151515",
            "panel": "#1f1f1f",
            "muted": "#9aa0a6",
            "text": "#ffffff",
            "blue": "#00d4ff",
            "green": "#22c55e",
            "orange": "#ffa502",
            "red": "#ef4444",
        }

        # State
        self.is_monitoring = False
        self.q = queue.Queue()
        self.pulse = 0.0
        # Defaults (can be overridden by config.yaml)
        self.monitor_interval = 5
        self.risk_threshold = 0.7
        self.confirm_kill = True
        self.safe_mode = True
        self.allowlist = set()
        self.denylist = set()
        self.vt_cache = {}
        self.vt_times = deque(maxlen=120)  # timestamps for VT rate limiting
        self.vt_rate_limit_per_min = 10
        self.show_system_tray = False
        self._tray_icon = None
        self._tray_thread = None

        self._load_config()

        # Secret redaction
        self._secrets_to_redact = []
        try:
            from dotenv import load_dotenv
            load_dotenv()
        except Exception:
            pass
        vt_key = os.getenv("VT_API_KEY")
        if vt_key:
            self._secrets_to_redact.append(vt_key)

        self._build_ui()
        self._style_ttk()
        self._tick()
        self._drain_queue()

    def _style_ttk(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure(
            "Treeview",
            background=self.c["panel"],
            fieldbackground=self.c["panel"],
            foreground=self.c["text"],
            borderwidth=0,
            rowheight=26,
            font=("Segoe UI", 10),
        )
        style.configure(
            "Treeview.Heading",
            background=self.c["card"],
            foreground=self.c["text"],
            font=("Segoe UI", 10, "bold"),
            borderwidth=0,
        )

    def _build_ui(self):
        # Header
        header = tk.Frame(self.root, bg=self.c["bg"]) 
        header.pack(fill="x", padx=20, pady=(16, 8))

        self.pulse_dot = tk.Label(header, text="●", fg=self.c["blue"], bg=self.c["bg"], font=("Segoe UI", 18, "bold"))
        self.pulse_dot.pack(side="left", padx=(0, 10))

        title = tk.Label(header, text="Cybersecurity Bot", fg=self.c["text"], bg=self.c["bg"], font=("Segoe UI", 26, "bold"))
        title.pack(side="left")
        subtitle = tk.Label(header, text="Professional Threat Detection System", fg=self.c["muted"], bg=self.c["bg"], font=("Segoe UI", 11))
        subtitle.pack(side="left", padx=16)

        self.header_status = tk.Label(header, text="● SYSTEM READY", fg=self.c["green"], bg=self.c["bg"], font=("Segoe UI", 11, "bold"))
        self.header_status.pack(side="right")

        # Body grid
        body = tk.Frame(self.root, bg=self.c["bg"]) 
        body.pack(fill="both", expand=True, padx=20, pady=8)

        left = tk.Frame(body, bg=self.c["bg"]) 
        left.pack(side="left", fill="y")
        right = tk.Frame(body, bg=self.c["bg"]) 
        right.pack(side="right", fill="both", expand=True)

        # Controls card
        ctrl = self._card(left, "Controls")
        ctrl.pack(fill="x", pady=(0, 12))
        row = tk.Frame(ctrl, bg=self.c["card"]) ; row.pack(padx=12, pady=12)
        self.btn_start = self._button(row, "🚀 Start", self.start)
        self.btn_start.pack(side="left", padx=6)
        self.btn_stop = self._button(row, "⏹ Stop", self.stop, kind="danger")
        self.btn_stop.config(state="disabled")
        self.btn_stop.pack(side="left", padx=6)
        self.btn_quick = self._button(row, "🔍 Quick Scan", self.quick_scan, kind="accent")
        self.btn_quick.pack(side="left", padx=6)
        self.btn_pause = self._button(row, "⏸ Pause", self.pause, kind="accent")
        self.btn_pause.pack(side="left", padx=6)
        self.btn_export = self._button(row, "💾 Export CSV", self.export_csv, kind="accent")
        self.btn_export.pack(side="left", padx=6)

        # Tray integration
        if self.show_system_tray:
            try:
                self._setup_tray()
                self.root.protocol("WM_DELETE_WINDOW", self._on_close_to_tray)
                self.root.bind("<Unmap>", self._maybe_minimize_to_tray)
            except Exception:
                pass

        # Status card
        stat = self._card(left, "System Status")
        stat.pack(fill="x", pady=12)
        self.lbl_cpu = self._stat_line(stat, "CPU", self.c["blue"]) 
        self.lbl_ram = self._stat_line(stat, "RAM", self.c["green"]) 
        self.lbl_proc = self._stat_line(stat, "Processes", self.c["orange"]) 

        # Scanned feed
        feed = self._card(right, "Scanning Feed (live)")
        feed.pack(fill="x")
        self.scanned_list = tk.Listbox(feed, bg=self.c["panel"], fg=self.c["text"], height=8, borderwidth=0, highlightthickness=0, font=("Consolas", 10))
        self.scanned_list.pack(fill="x", padx=12, pady=(4, 12))

        # Threats table
        thcard = self._card(right, "Detected Threats")
        thcard.pack(fill="both", expand=True, pady=(12, 12))
        cols = ("PID", "Name", "CPU%", "RAM%", "Risk", "VT", "Verdict")
        self.threats = ttk.Treeview(thcard, columns=cols, show="headings")
        for c in cols:
            self.threats.heading(c, text=c)
            self.threats.column(c, width=140 if c == "Name" else 90, anchor="center")
        self.threats.pack(fill="both", expand=True, padx=12, pady=(4, 12))

        # Log
        logc = self._card(right, "Activity Log")
        logc.pack(fill="x")
        self.log = scrolledtext.ScrolledText(logc, height=6, bg=self.c["panel"], fg=self.c["text"], insertbackground=self.c["text"], font=("Consolas", 9), borderwidth=0, highlightthickness=0)
        self.log.pack(fill="x", padx=12, pady=(4, 12))

    def _card(self, parent, title):
        card = tk.Frame(parent, bg=self.c["card"], bd=0, highlightthickness=1, highlightbackground="#2b2b2b")
        tk.Label(card, text=title, fg=self.c["text"], bg=self.c["card"], font=("Segoe UI", 12, "bold")).pack(anchor="w", padx=12, pady=(10, 0))
        tk.Frame(card, bg="#2b2b2b", height=1).pack(fill="x", padx=12, pady=(6, 0))
        return card

    def _button(self, parent, text, cmd, kind="primary"):
        bg = self.c["green"] if kind == "primary" else self.c["red"] if kind == "danger" else self.c["blue"]
        return tk.Button(parent, text=text, command=cmd, font=("Segoe UI", 10, "bold"), bg=bg, fg="#0b0f10", activebackground=bg, activeforeground="#0b0f10", relief="flat", padx=16, pady=10, cursor="hand2")

    def _stat_line(self, parent, label, color):
        row = tk.Frame(parent, bg=self.c["card"]) ; row.pack(fill="x", padx=12, pady=6)
        tk.Label(row, text=f"{label}:", fg=self.c["muted"], bg=self.c["card"], font=("Segoe UI", 10)).pack(side="left")
        v = tk.Label(row, text="-", fg=color, bg=self.c["card"], font=("Segoe UI", 11, "bold"))
        v.pack(side="right")
        return v

    def _tick(self):
        # Pulse animation + system stats
        self.pulse += 0.14
        bright = 0.5 + 0.5 * (math.sin(self.pulse))
        self.pulse_dot.config(fg=self._mix(self.c["blue"], self.c["green"], bright))

        cpu = psutil.cpu_percent(interval=0.1)
        ram = psutil.virtual_memory().percent
        self.lbl_cpu.config(text=f"{cpu:.1f}%")
        self.lbl_ram.config(text=f"{ram:.1f}%")
        try:
            self.lbl_proc.config(text=str(len(psutil.pids())))
        except Exception:
            pass

        self.root.after(500, self._tick)

    def _drain_queue(self):
        try:
            while True:
                kind, payload = self.q.get_nowait()
                if kind == "scanned":
                    pid, name = payload
                    self._append_feed(f"Scanning: {name} ({pid})")
                elif kind == "threat":
                    self._add_threat_row(*payload)
                elif kind == "log":
                    self._log(payload)
        except queue.Empty:
            pass
        self.root.after(100, self._drain_queue)

    # Actions
    def start(self):
        if self.is_monitoring:
            return
        self.is_monitoring = True
        self.header_status.config(text="● MONITORING", fg=self.c["green"])
        self.btn_start.config(state="disabled")
        self.btn_stop.config(state="normal")
        threading.Thread(target=self._monitor_loop, daemon=True).start()
        self._log("Monitoring started")

    def stop(self):
        self.is_monitoring = False
        self.header_status.config(text="● SYSTEM READY", fg=self.c["green"])
        self.btn_start.config(state="normal")
        self.btn_stop.config(state="disabled")
        self._log("Monitoring stopped")

    def pause(self):
        if not self.is_monitoring:
            return
        self.is_paused = not getattr(self, 'is_paused', False)
        if self.is_paused:
            self.header_status.config(text="● PAUSED", fg=self.c["orange"]) 
            self.btn_pause.config(text="▶ Resume")
            self._log("Monitoring paused")
        else:
            self.header_status.config(text="● MONITORING", fg=self.c["green"]) 
            self.btn_pause.config(text="⏸ Pause")
            self._log("Monitoring resumed")

    def quick_scan(self):
        self._log("Quick scan initiated")
        threading.Thread(target=self._scan_once, daemon=True).start()

    # Scanning
    def _monitor_loop(self):
        while self.is_monitoring:
            if not getattr(self, 'is_paused', False):
                self._scan_once()
            time.sleep(self.monitor_interval)

    def _scan_once(self):
        try:
            # Sample processes to reduce overhead
            procs = list(psutil.process_iter(["pid", "name"]))
            snap = []
            for pr in procs:
                try:
                    snap.append((pr, pr.cpu_percent(interval=0.0)))
                except Exception:
                    continue
            snap.sort(key=lambda x: x[1], reverse=True)
            candidates = [p for p,_ in snap[:50]] + [p for p,_ in snap[50:100:2]]
            for proc in candidates:
                try:
                    pid = proc.info["pid"]
                    name = (proc.info["name"] or "<unknown>")
                    name_lower = name.lower()
                    if name_lower in self.allowlist:
                        continue
                    self.q.put(("scanned", (pid, name)))

                    p = psutil.Process(pid)
                    cpu = p.cpu_percent(interval=0.05)
                    mem = p.memory_percent()
                    threads = p.num_threads()
                    # psutil.connections() is deprecated; use net_connections()
                    conns = len(p.net_connections())
                    risk = float(predict_process_risk([[cpu, mem, threads, conns]]))
                    if name_lower in self.denylist:
                        risk = max(risk, 0.99)

                    vt_verdict = "-"
                    if risk >= self.risk_threshold:
                        # Optional VirusTotal check using file hash
                        try:
                            exe_path = p.exe()
                        except Exception:
                            exe_path = None
                        h = get_file_hash(exe_path) if exe_path else None
                        if h:
                            # simple per-minute rate limiting
                            now = time.time()
                            while self.vt_times and now - self.vt_times[0] > 60:
                                self.vt_times.popleft()
                            if len(self.vt_times) < self.vt_rate_limit_per_min:
                                self.vt_times.append(now)
                                vt_bool, _stats = check_virustotal(h)
                            else:
                                vt_bool = None
                            if vt_bool is True:
                                vt_verdict = "Malicious"
                            elif vt_bool is False:
                                vt_verdict = "Clean"
                            else:
                                vt_verdict = "Unknown"
                        self.q.put(("threat", (pid, name, cpu, mem, risk, vt_verdict)))
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            self.q.put(("log", "Scan completed"))
        except Exception as e:
            self.q.put(("log", f"Scan error: {e}"))

    # UI helpers
    def _add_threat_row(self, pid, name, cpu, mem, risk, vt_verdict="-"):
        verdict = "CRITICAL" if risk > 0.85 else "HIGH" if risk > 0.7 else "SUSPICIOUS"
        self.threats.insert("", "end", values=(pid, name, f"{cpu:.1f}", f"{mem:.1f}", f"{risk:.2f}", vt_verdict, verdict))
        if risk >= self.risk_threshold:
            self._log(f"Threat: {name} ({pid}) risk {risk:.2f}")

    def _append_feed(self, line):
        self.scanned_list.insert("end", f"[{datetime.now().strftime('%H:%M:%S')}] {line}")
        if self.scanned_list.size() > 200:
            self.scanned_list.delete(0)
        self.scanned_list.see("end")

    def _log(self, line):
        safe = self._redact_text(line)
        self.log.insert("end", f"[{datetime.now().strftime('%H:%M:%S')}] {safe}\n")
        self.log.see("end")

    def _log_json(self, obj):
        try:
            import json
            def _redact_any(x):
                if isinstance(x, str):
                    return self._redact_text(x)
                if isinstance(x, dict):
                    return {k: _redact_any(v) for k, v in x.items()}
                if isinstance(x, (list, tuple)):
                    t = type(x)
                    return t(_redact_any(v) for v in x)
                return x
            safe_obj = _redact_any(obj)
            with open("detection.log.jsonl", "a", encoding="utf-8") as f:
                f.write(json.dumps(safe_obj, ensure_ascii=False) + "\n")
        except Exception:
            pass

    def _redact_text(self, text):
        try:
            safe = str(text)
            for secret in self._secrets_to_redact:
                if secret:
                    safe = safe.replace(secret, "[REDACTED]")
            # Also redact common API key patterns (basic heuristic)
            safe = re.sub(r"(?i)(api[_-]?key\s*[:=]\s*)([A-Za-z0-9_\-]{16,})", r"\1[REDACTED]", safe)
            return safe
        except Exception:
            return text

    # ---- System tray integration ----
    def _setup_tray(self):
        try:
            import pystray
            from PIL import Image
        except Exception as e:
            self._log(f"Tray not available: {e}")
            return
        icon_path = os.path.abspath("icon.ico")
        image = None
        try:
            if os.path.exists(icon_path):
                from PIL import Image
                image = Image.open(icon_path)
        except Exception:
            image = None
        if image is None:
            try:
                from PIL import Image
                image = Image.new("RGB", (64, 64), color=(15, 120, 200))
            except Exception:
                pass
        import pystray
        menu = pystray.Menu(
            pystray.MenuItem("Show", lambda: self._restore_from_tray()),
            pystray.MenuItem("Quit", lambda: self._quit_from_tray()),
        )
        self._tray_icon = pystray.Icon("Cybersecurity Bot", image, "Cybersecurity Bot", menu)

        def run_icon():
            try:
                self._tray_icon.run()
            except Exception:
                pass
        import threading as _th
        self._tray_thread = _th.Thread(target=run_icon, daemon=True)
        self._tray_thread.start()

    def _maybe_minimize_to_tray(self, event=None):
        try:
            if self.root.state() == 'iconic' and self._tray_icon is not None:
                self.root.withdraw()
                self._log("Minimized to tray")
        except Exception:
            pass

    def _on_close_to_tray(self):
        if self._tray_icon is not None:
            try:
                self.root.withdraw()
                self._log("Running in tray. Use tray menu to Quit or Show.")
                return
            except Exception:
                pass
        # fallback: normal close
        self.root.destroy()

    def _restore_from_tray(self):
        try:
            self.root.deiconify()
            self.root.state('normal')
            self.root.after(0, self.root.lift)
        except Exception:
            pass

    def _quit_from_tray(self):
        try:
            self.is_monitoring = False
            if self._tray_icon is not None:
                try:
                    self._tray_icon.stop()
                except Exception:
                    pass
            self.root.after(0, self.root.destroy)
        except Exception:
            os._exit(0)

    def export_csv(self):
        try:
            path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV", "*.csv")], initialfile="threats_export.csv")
            if not path:
                return
            import csv
            cols = ("PID","Name","CPU%","RAM%","Risk","VT","Verdict")
            with open(path, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(cols)
                for iid in self.threats.get_children():
                    w.writerow(self.threats.item(iid, "values"))
            messagebox.showinfo("Export", f"Exported to {path}")
        except Exception as e:
            messagebox.showerror("Export", f"Failed to export: {e}")

    def _load_config(self):
        try:
            with open(CONFIG_PATH, "r"), "r", encoding="utf-8") as f:
                cfg = yaml.safe_load(f) or {}
            self.monitor_interval = int(cfg.get("monitor_interval_seconds", self.monitor_interval))
            self.risk_threshold = float(cfg.get("risk_score_kill_threshold", self.risk_threshold))
            self.confirm_kill = bool(cfg.get("confirm_kill", self.confirm_kill))
            self.safe_mode = bool(cfg.get("safe_mode", self.safe_mode))
            self.vt_rate_limit_per_min = int(cfg.get("vt_rate_limit_per_min", self.vt_rate_limit_per_min))
            self.allowlist = set([s.lower() for s in cfg.get("whitelist", [])])
            self.denylist = set([s.lower() for s in cfg.get("blacklist", [])])
            self.show_system_tray = bool(cfg.get("show_system_tray", self.show_system_tray))
            self.minimize_to_tray = bool(cfg.get("minimize_to_tray", True))
        except Exception:
            pass

    @staticmethod
    def _mix(hex1, hex2, t):
        def to_rgb(h):
            h = h.lstrip('#'); return tuple(int(h[i:i+2], 16) for i in (0,2,4))
        def to_hex(rgb):
            return '#%02x%02x%02x' % rgb
        a = to_rgb(hex1); b = to_rgb(hex2)
        m = (int(a[0]*(1-t)+b[0]*t), int(a[1]*(1-t)+b[1]*t), int(a[2]*(1-t)+b[2]*t))
        return to_hex(m)


def main():
    root = tk.Tk()
    try:
        root.iconbitmap('icon.ico')
    except Exception:
        pass
    app = ProSecurityGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import time
import queue
import os
import math
from datetime import datetime
import psutil

# Import your existing modules
from cybersecurity_bot.core.detector import scan_for_malware
from cybersecurity_bot.utils.notifier import send_alert
from cybersecurity_bot.utils.logger import log_detection
from cybersecurity_bot.utils.killer import kill_process
from cybersecurity_bot.utils.emailer import send_email_alert
from cybersecurity_bot.core.vt_scanner import get_file_hash, check_virustotal
from cybersecurity_bot.core.predictor import predict_process_risk

class CybersecurityBotGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("🛡️ Cybersecurity Bot - Professional Control Panel")
        self.root.geometry("1200x800")
        self.root.configure(bg='#0a0a0a')
        self.root.minsize(1000, 700)
        
        # Modern color scheme
        self.colors = {
            'bg_primary': '#0a0a0a',
            'bg_secondary': '#1a1a1a',
            'bg_tertiary': '#2a2a2a',
            'accent_blue': '#00d4ff',
            'accent_green': '#00ff88',
            'accent_red': '#ff4757',
            'accent_orange': '#ffa502',
            'text_primary': '#ffffff',
            'text_secondary': '#b0b0b0',
            'text_muted': '#666666',
            'border': '#333333',
            'success': '#2ed573',
            'warning': '#ffa502',
            'danger': '#ff4757'
        }
        
        # Bot state
        self.is_monitoring = False
        self.monitor_thread = None
        self.message_queue = queue.Queue()
        self.animation_running = False
        
        # Configuration
        self.config = {
            'monitor_interval': 5,
            'risk_threshold': 0.7,
            'email_alerts': True,
            'popup_alerts': True
        }
        
        # Animation variables
        self.pulse_phase = 0
        self.scan_animation = False
        
        # Initialize variables
        self.interval_var = tk.StringVar()
        self.threshold_var = tk.StringVar()
        self.email_var = tk.BooleanVar()
        self.popup_var = tk.BooleanVar()
        
        self.setup_ui()
        self.check_queue()
        self.start_animations()
        self.update_system_info()
        
    def setup_ui(self):
        # Create main container with padding
        main_container = tk.Frame(self.root, bg=self.colors['bg_primary'])
        main_container.pack(fill='both', expand=True, padx=20, pady=20)
        
        # Header section
        self.setup_header(main_container)
        
        # Dashboard grid
        dashboard_frame = tk.Frame(main_container, bg=self.colors['bg_primary'])
        dashboard_frame.pack(fill='both', expand=True, pady=(20, 0))
        
        # Left column
        left_column = tk.Frame(dashboard_frame, bg=self.colors['bg_primary'])
        left_column.pack(side='left', fill='both', expand=True, padx=(0, 10))
        
        # Right column
        right_column = tk.Frame(dashboard_frame, bg=self.colors['bg_primary'])
        right_column.pack(side='right', fill='both', expand=True, padx=(10, 0))
        
        # Left column components
        self.setup_status_cards(left_column)
        self.setup_control_panel(left_column)
        self.setup_config_panel(left_column)
        
        # Right column components
        self.setup_monitoring_dashboard(right_column)
        self.setup_activity_log(right_column)
        
    def setup_header(self, parent):
        """Create modern header with logo and title"""
        header_frame = tk.Frame(parent, bg=self.colors['bg_primary'])
        header_frame.pack(fill='x', pady=(0, 20))
        
        # Logo and title container
        title_container = tk.Frame(header_frame, bg=self.colors['bg_primary'])
        title_container.pack(side='left')
        
        # Shield icon with animation
        self.shield_label = tk.Label(
            title_container,
            text="🛡️",
            font=('Arial', 32),
            bg=self.colors['bg_primary'],
            fg=self.colors['accent_blue']
        )
        self.shield_label.pack(side='left', padx=(0, 15))
        
        # Title and subtitle
        title_text = tk.Label(
            title_container,
            text="Cybersecurity Bot",
            font=('Segoe UI', 28, 'bold'),
            fg=self.colors['text_primary'],
            bg=self.colors['bg_primary']
        )
        title_text.pack(side='left', anchor='n')
        
        subtitle_text = tk.Label(
            title_container,
            text="Professional Threat Detection System",
            font=('Segoe UI', 12),
            fg=self.colors['text_secondary'],
            bg=self.colors['bg_primary']
        )
        subtitle_text.pack(side='left', anchor='n', padx=(10, 0))
        
        # Status indicator on the right
        self.header_status_frame = tk.Frame(header_frame, bg=self.colors['bg_primary'])
        self.header_status_frame.pack(side='right', anchor='e')
        
        self.header_status_label = tk.Label(
            self.header_status_frame,
            text="● SYSTEM READY",
            font=('Segoe UI', 12, 'bold'),
            fg=self.colors['success'],
            bg=self.colors['bg_primary']
        )
        self.header_status_label.pack()
        
    def setup_status_cards(self, parent):
        """Create modern status cards"""
        cards_frame = tk.Frame(parent, bg=self.colors['bg_primary'])
        cards_frame.pack(fill='x', pady=(0, 20))
        
        # System Status Card
        self.status_card = self.create_card(cards_frame, "System Status", self.colors['accent_blue'])
        self.status_card.pack(side='left', fill='x', expand=True, padx=(0, 10))
        
        # Add initial system info to status card
        self.add_system_info_to_card()
        
        # Bot Status Card
        self.bot_status_card = self.create_card(cards_frame, "Bot Status", self.colors['accent_green'])
        self.bot_status_card.pack(side='left', fill='x', expand=True, padx=(10, 0))
        
        # Add initial bot status to card
        self.add_bot_status_to_card()
        
    def create_card(self, parent, title, accent_color):
        """Create a modern card component"""
        card_frame = tk.Frame(
            parent,
            bg=self.colors['bg_secondary'],
            relief='flat',
            bd=0
        )
        
        # Card header
        header_frame = tk.Frame(card_frame, bg=self.colors['bg_secondary'])
        header_frame.pack(fill='x', padx=20, pady=(20, 10))
        
        # Accent line
        accent_line = tk.Frame(header_frame, bg=accent_color, height=3)
        accent_line.pack(fill='x', pady=(0, 10))
        
        # Title
        title_label = tk.Label(
            header_frame,
            text=title,
            font=('Segoe UI', 14, 'bold'),
            fg=self.colors['text_primary'],
            bg=self.colors['bg_secondary']
        )
        title_label.pack(anchor='w')
        
        # Content area
        content_frame = tk.Frame(card_frame, bg=self.colors['bg_secondary'])
        content_frame.pack(fill='both', expand=True, padx=20, pady=(0, 20))
        
        return content_frame
        
    def add_system_info_to_card(self):
        """Add system information to the status card"""
        try:
            cpu_percent = psutil.cpu_percent(interval=0.1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            # Add system info
            cpu_label = tk.Label(
                self.status_card,
                text=f"CPU: {cpu_percent:.1f}%",
                font=('Segoe UI', 12, 'bold'),
                fg=self.colors['accent_blue'],
                bg=self.colors['bg_secondary']
            )
            cpu_label.pack(anchor='w', pady=2)
            
            memory_label = tk.Label(
                self.status_card,
                text=f"RAM: {memory.percent:.1f}%",
                font=('Segoe UI', 12, 'bold'),
                fg=self.colors['accent_green'],
                bg=self.colors['bg_secondary']
            )
            memory_label.pack(anchor='w', pady=2)
            
            disk_label = tk.Label(
                self.status_card,
                text=f"Disk: {disk.percent:.1f}%",
                font=('Segoe UI', 12, 'bold'),
                fg=self.colors['accent_orange'],
                bg=self.colors['bg_secondary']
            )
            disk_label.pack(anchor='w', pady=2)
        except Exception as e:
            error_label = tk.Label(
                self.status_card,
                text=f"Error: {e}",
                font=('Segoe UI', 10),
                fg=self.colors['danger'],
                bg=self.colors['bg_secondary']
            )
            error_label.pack(anchor='w', pady=2)
            
    def add_bot_status_to_card(self):
        """Add bot status to the status card"""
        status_label = tk.Label(
            self.bot_status_card,
            text="🔴 STOPPED",
            font=('Segoe UI', 16, 'bold'),
            fg=self.colors['danger'],
            bg=self.colors['bg_secondary']
        )
        status_label.pack(anchor='w', pady=5)
        
        mode_label = tk.Label(
            self.bot_status_card,
            text="Standby Mode",
            font=('Segoe UI', 10),
            fg=self.colors['text_secondary'],
            bg=self.colors['bg_secondary']
        )
        mode_label.pack(anchor='w')
        
    def setup_control_panel(self, parent):
        """Create modern control panel"""
        control_frame = tk.Frame(parent, bg=self.colors['bg_primary'])
        control_frame.pack(fill='x', pady=(0, 20))
        
        # Control panel card
        control_card = self.create_card(control_frame, "Control Panel", self.colors['accent_orange'])
        
        # Control buttons with modern styling
        button_frame = tk.Frame(control_card, bg=self.colors['bg_secondary'])
        button_frame.pack(fill='x', pady=10)
        
        # Start button
        self.start_button = self.create_modern_button(
            button_frame,
            "🚀 START MONITORING",
            self.start_monitoring,
            self.colors['success'],
            'left'
        )
        
        # Stop button
        self.stop_button = self.create_modern_button(
            button_frame,
            "⏹️ STOP MONITORING",
            self.stop_monitoring,
            self.colors['danger'],
            'left'
        )
        self.stop_button.config(state='disabled')
        
        # Quick scan button
        self.scan_button = self.create_modern_button(
            button_frame,
            "🔍 QUICK SCAN",
            self.quick_scan,
            self.colors['accent_blue'],
            'left'
        )
        
    def create_modern_button(self, parent, text, command, color, side='left'):
        """Create a modern styled button"""
        button = tk.Button(
            parent,
            text=text,
            command=command,
            font=('Segoe UI', 11, 'bold'),
            bg=color,
            fg='white',
            relief='flat',
            bd=0,
            padx=20,
            pady=12,
            cursor='hand2',
            activebackground=self.darken_color(color),
            activeforeground='white'
        )
        button.pack(side=side, padx=(0, 10), pady=5)
        return button
        
    def darken_color(self, color):
        """Darken a hex color for hover effects"""
        # Simple color darkening - you could make this more sophisticated
        color_map = {
            self.colors['success']: '#1e7e34',
            self.colors['danger']: '#c82333',
            self.colors['accent_blue']: '#0056b3',
            self.colors['accent_orange']: '#e67e22'
        }
        return color_map.get(color, color)
        
    def setup_config_panel(self, parent):
        """Create modern configuration panel"""
        config_frame = tk.Frame(parent, bg=self.colors['bg_primary'])
        config_frame.pack(fill='x')
        
        # Config panel card
        config_card = self.create_card(config_frame, "Configuration", self.colors['accent_blue'])
        
        # Configuration grid
        config_grid = tk.Frame(config_card, bg=self.colors['bg_secondary'])
        config_grid.pack(fill='x', pady=10)
        
        # Monitor interval
        self.create_config_row(config_grid, "Monitor Interval (seconds):", 
                              self.interval_var, str(self.config['monitor_interval']), 0)
        
        # Risk threshold
        self.create_config_row(config_grid, "Risk Threshold:", 
                              self.threshold_var, str(self.config['risk_threshold']), 1)
        
        # Checkboxes
        checkbox_frame = tk.Frame(config_grid, bg=self.colors['bg_secondary'])
        checkbox_frame.grid(row=2, column=0, columnspan=2, sticky='ew', pady=10)
        
        self.email_var = tk.BooleanVar(value=self.config['email_alerts'])
        email_check = self.create_modern_checkbox(checkbox_frame, "Email Alerts", self.email_var, 'left')
        
        self.popup_var = tk.BooleanVar(value=self.config['popup_alerts'])
        popup_check = self.create_modern_checkbox(checkbox_frame, "Popup Alerts", self.popup_var, 'left')
        
        # Save button
        save_button = tk.Button(
            config_grid,
            text="💾 SAVE CONFIG",
            command=self.save_config,
            font=('Segoe UI', 11, 'bold'),
            bg=self.colors['accent_blue'],
            fg='white',
            relief='flat',
            bd=0,
            padx=20,
            pady=12,
            cursor='hand2',
            activebackground=self.darken_color(self.colors['accent_blue']),
            activeforeground='white'
        )
        save_button.grid(row=3, column=0, columnspan=2, pady=10)
        
    def create_config_row(self, parent, label_text, var, default_value, row):
        """Create a configuration row"""
        # Label
        label = tk.Label(
            parent,
            text=label_text,
            font=('Segoe UI', 10),
            fg=self.colors['text_secondary'],
            bg=self.colors['bg_secondary']
        )
        label.grid(row=row, column=0, sticky='w', padx=(0, 10), pady=5)
        
        # Entry
        var.set(default_value)
        entry = tk.Entry(
            parent,
            textvariable=var,
            font=('Segoe UI', 10),
            bg=self.colors['bg_tertiary'],
            fg=self.colors['text_primary'],
            relief='flat',
            bd=0,
            insertbackground=self.colors['text_primary']
        )
        entry.grid(row=row, column=1, sticky='w', pady=5)
        
    def create_modern_checkbox(self, parent, text, var, side):
        """Create a modern styled checkbox"""
        checkbox = tk.Checkbutton(
            parent,
            text=text,
            variable=var,
            font=('Segoe UI', 10),
            fg=self.colors['text_secondary'],
            bg=self.colors['bg_secondary'],
            selectcolor=self.colors['bg_tertiary'],
            activebackground=self.colors['bg_secondary'],
            activeforeground=self.colors['text_primary'],
            relief='flat',
            bd=0
        )
        checkbox.pack(side=side, padx=(0, 20), pady=5)
        return checkbox
        
    def setup_monitoring_dashboard(self, parent):
        """Create modern monitoring dashboard"""
        monitor_frame = tk.Frame(parent, bg=self.colors['bg_primary'])
        monitor_frame.pack(fill='both', expand=True, pady=(0, 20))
        
        # Monitoring card
        monitor_card = self.create_card(monitor_frame, "Real-time Monitoring", self.colors['accent_green'])
        
        # Stats header
        stats_frame = tk.Frame(monitor_card, bg=self.colors['bg_secondary'])
        stats_frame.pack(fill='x', pady=(0, 15))
        
        # Threat counter
        self.threat_count_label = tk.Label(
            stats_frame,
            text="Threats Detected: 0",
            font=('Segoe UI', 14, 'bold'),
            fg=self.colors['danger'],
            bg=self.colors['bg_secondary']
        )
        self.threat_count_label.pack(side='left')
        
        # Last scan
        self.last_scan_label = tk.Label(
            stats_frame,
            text="Last Scan: Never",
            font=('Segoe UI', 10),
            fg=self.colors['text_muted'],
            bg=self.colors['bg_secondary']
        )
        self.last_scan_label.pack(side='right')
        
        # Process tree with modern styling
        tree_frame = tk.Frame(monitor_card, bg=self.colors['bg_secondary'])
        tree_frame.pack(fill='both', expand=True)
        
        # Configure ttk style
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("Treeview",
                       background=self.colors['bg_tertiary'],
                       foreground=self.colors['text_primary'],
                       fieldbackground=self.colors['bg_tertiary'],
                       borderwidth=0,
                       font=('Segoe UI', 9))
        style.configure("Treeview.Heading",
                       background=self.colors['bg_secondary'],
                       foreground=self.colors['text_primary'],
                       font=('Segoe UI', 10, 'bold'),
                       borderwidth=0)
        
        self.process_tree = ttk.Treeview(
            tree_frame,
            columns=('PID', 'Name', 'CPU', 'Memory', 'Risk', 'Status'),
            show='headings',
            height=12
        )
        
        # Configure columns
        columns_config = [
            ('PID', 60), ('Name', 200), ('CPU', 80), 
            ('Memory', 80), ('Risk', 80), ('Status', 120)
        ]
        
        for col, width in columns_config:
            self.process_tree.heading(col, text=col)
            self.process_tree.column(col, width=width, anchor='center')
        
        # Scrollbar
        tree_scroll = ttk.Scrollbar(tree_frame, orient='vertical', command=self.process_tree.yview)
        self.process_tree.configure(yscrollcommand=tree_scroll.set)
        
        self.process_tree.pack(side='left', fill='both', expand=True)
        tree_scroll.pack(side='right', fill='y')
        
        # Threat counter
        self.threat_count = 0
        
    def setup_activity_log(self, parent):
        """Create modern activity log"""
        log_frame = tk.Frame(parent, bg=self.colors['bg_primary'])
        log_frame.pack(fill='x')
        
        # Log card
        log_card = self.create_card(log_frame, "Activity Log", self.colors['accent_orange'])
        
        # Log text area
        self.log_text = scrolledtext.ScrolledText(
            log_card,
            height=8,
            font=('Consolas', 9),
            bg=self.colors['bg_tertiary'],
            fg=self.colors['accent_green'],
            insertbackground=self.colors['text_primary'],
            relief='flat',
            bd=0,
            wrap='word'
        )
        self.log_text.pack(fill='x', pady=(0, 10))
        
        # Clear button
        clear_button = tk.Button(
            log_card,
            text="🗑️ CLEAR LOG",
            command=self.clear_log,
            font=('Segoe UI', 11, 'bold'),
            bg=self.colors['text_muted'],
            fg='white',
            relief='flat',
            bd=0,
            padx=20,
            pady=12,
            cursor='hand2',
            activebackground=self.darken_color(self.colors['text_muted']),
            activeforeground='white'
        )
        clear_button.pack(pady=5)
        
    def start_animations(self):
        """Start UI animations"""
        self.animation_running = True
        self.animate_shield()
        
    def animate_shield(self):
        """Animate the shield icon"""
        if not self.animation_running:
            return
            
        self.pulse_phase += 0.1
        intensity = (math.sin(self.pulse_phase) + 1) / 2
        alpha = int(255 * (0.5 + 0.5 * intensity))
        
        # Create pulsing effect
        if hasattr(self, 'shield_label'):
            if self.is_monitoring:
                self.shield_label.config(fg=self.colors['accent_green'])
            else:
                self.shield_label.config(fg=self.colors['accent_blue'])
        
        self.root.after(100, self.animate_shield)
        
    def setup_status_frame(self):
        status_frame = tk.LabelFrame(
            self.root, 
            text="System Status", 
            font=('Arial', 12, 'bold'),
            fg='white',
            bg='#2b2b2b',
            relief='raised',
            bd=2
        )
        status_frame.pack(fill='x', padx=10, pady=5)
        
        # Status indicators
        self.status_label = tk.Label(
            status_frame,
            text="🔴 STOPPED",
            font=('Arial', 14, 'bold'),
            fg='red',
            bg='#2b2b2b'
        )
        self.status_label.pack(side='left', padx=10, pady=5)
        
        # System info
        self.system_info_label = tk.Label(
            status_frame,
            text="",
            font=('Arial', 10),
            fg='white',
            bg='#2b2b2b'
        )
        self.system_info_label.pack(side='right', padx=10, pady=5)
        
        self.update_system_info()
        
    def setup_control_frame(self):
        control_frame = tk.LabelFrame(
            self.root,
            text="Bot Controls",
            font=('Arial', 12, 'bold'),
            fg='white',
            bg='#2b2b2b',
            relief='raised',
            bd=2
        )
        control_frame.pack(fill='x', padx=10, pady=5)
        
        # Control buttons
        button_frame = tk.Frame(control_frame, bg='#2b2b2b')
        button_frame.pack(pady=10)
        
        self.start_button = tk.Button(
            button_frame,
            text="🚀 Start Monitoring",
            command=self.start_monitoring,
            font=('Arial', 12, 'bold'),
            bg='#00aa00',
            fg='white',
            relief='raised',
            bd=3,
            padx=20,
            pady=5
        )
        self.start_button.pack(side='left', padx=5)
        
        self.stop_button = tk.Button(
            button_frame,
            text="⏹️ Stop Monitoring",
            command=self.stop_monitoring,
            font=('Arial', 12, 'bold'),
            bg='#aa0000',
            fg='white',
            relief='raised',
            bd=3,
            padx=20,
            pady=5,
            state='disabled'
        )
        self.stop_button.pack(side='left', padx=5)
        
        self.scan_button = tk.Button(
            button_frame,
            text="🔍 Quick Scan",
            command=self.quick_scan,
            font=('Arial', 12, 'bold'),
            bg='#0066cc',
            fg='white',
            relief='raised',
            bd=3,
            padx=20,
            pady=5
        )
        self.scan_button.pack(side='left', padx=5)
        
    def setup_config_frame(self):
        config_frame = tk.LabelFrame(
            self.root,
            text="Configuration",
            font=('Arial', 12, 'bold'),
            fg='white',
            bg='#2b2b2b',
            relief='raised',
            bd=2
        )
        config_frame.pack(fill='x', padx=10, pady=5)
        
        # Configuration options
        config_grid = tk.Frame(config_frame, bg='#2b2b2b')
        config_grid.pack(pady=10)
        
        # Monitor interval
        tk.Label(config_grid, text="Monitor Interval (seconds):", 
                fg='white', bg='#2b2b2b', font=('Arial', 10)).grid(row=0, column=0, sticky='w', padx=5)
        self.interval_var = tk.StringVar(value=str(self.config['monitor_interval']))
        interval_entry = tk.Entry(config_grid, textvariable=self.interval_var, width=10)
        interval_entry.grid(row=0, column=1, padx=5)
        
        # Risk threshold
        tk.Label(config_grid, text="Risk Threshold:", 
                fg='white', bg='#2b2b2b', font=('Arial', 10)).grid(row=0, column=2, sticky='w', padx=5)
        self.threshold_var = tk.StringVar(value=str(self.config['risk_threshold']))
        threshold_entry = tk.Entry(config_grid, textvariable=self.threshold_var, width=10)
        threshold_entry.grid(row=0, column=3, padx=5)
        
        # Email alerts
        self.email_var = tk.BooleanVar(value=self.config['email_alerts'])
        email_check = tk.Checkbutton(config_grid, text="Email Alerts", 
                                   variable=self.email_var, fg='white', bg='#2b2b2b')
        email_check.grid(row=1, column=0, sticky='w', padx=5)
        
        # Popup alerts
        self.popup_var = tk.BooleanVar(value=self.config['popup_alerts'])
        popup_check = tk.Checkbutton(config_grid, text="Popup Alerts", 
                                   variable=self.popup_var, fg='white', bg='#2b2b2b')
        popup_check.grid(row=1, column=1, sticky='w', padx=5)
        
        # Save config button
        save_button = tk.Button(config_grid, text="💾 Save Config", 
                              command=self.save_config, bg='#666666', fg='white')
        save_button.grid(row=1, column=2, padx=5)
        
    def setup_monitoring_frame(self):
        monitor_frame = tk.LabelFrame(
            self.root,
            text="Real-time Monitoring",
            font=('Arial', 12, 'bold'),
            fg='white',
            bg='#2b2b2b',
            relief='raised',
            bd=2
        )
        monitor_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        # Threat counter
        threat_frame = tk.Frame(monitor_frame, bg='#2b2b2b')
        threat_frame.pack(fill='x', padx=10, pady=5)
        
        self.threat_count_label = tk.Label(
            threat_frame,
            text="Threats Detected: 0",
            font=('Arial', 12, 'bold'),
            fg='#ff6600',
            bg='#2b2b2b'
        )
        self.threat_count_label.pack(side='left')
        
        self.last_scan_label = tk.Label(
            threat_frame,
            text="Last Scan: Never",
            font=('Arial', 10),
            fg='white',
            bg='#2b2b2b'
        )
        self.last_scan_label.pack(side='right')
        
        # Process list
        self.process_tree = ttk.Treeview(
            monitor_frame,
            columns=('PID', 'Name', 'CPU', 'Memory', 'Risk', 'Status'),
            show='headings',
            height=8
        )
        
        # Configure columns
        self.process_tree.heading('PID', text='PID')
        self.process_tree.heading('Name', text='Process Name')
        self.process_tree.heading('CPU', text='CPU %')
        self.process_tree.heading('Memory', text='Memory %')
        self.process_tree.heading('Risk', text='Risk Score')
        self.process_tree.heading('Status', text='Status')
        
        self.process_tree.column('PID', width=60)
        self.process_tree.column('Name', width=200)
        self.process_tree.column('CPU', width=80)
        self.process_tree.column('Memory', width=80)
        self.process_tree.column('Risk', width=80)
        self.process_tree.column('Status', width=100)
        
        # Scrollbar for process tree
        process_scroll = ttk.Scrollbar(monitor_frame, orient='vertical', command=self.process_tree.yview)
        self.process_tree.configure(yscrollcommand=process_scroll.set)
        
        self.process_tree.pack(side='left', fill='both', expand=True, padx=(10, 0), pady=5)
        process_scroll.pack(side='right', fill='y', pady=5)
        
        # Threat counter
        self.threat_count = 0
        
    def setup_log_frame(self):
        log_frame = tk.LabelFrame(
            self.root,
            text="Activity Log",
            font=('Arial', 12, 'bold'),
            fg='white',
            bg='#2b2b2b',
            relief='raised',
            bd=2
        )
        log_frame.pack(fill='x', padx=10, pady=5)
        
        self.log_text = scrolledtext.ScrolledText(
            log_frame,
            height=6,
            font=('Consolas', 9),
            bg='#1a1a1a',
            fg='#00ff00',
            insertbackground='white'
        )
        self.log_text.pack(fill='x', padx=10, pady=5)
        
        # Clear log button
        clear_button = tk.Button(
            log_frame,
            text="🗑️ Clear Log",
            command=self.clear_log,
            bg='#666666',
            fg='white'
        )
        clear_button.pack(pady=5)
        
    def update_system_info(self):
        """Update system information display"""
        try:
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            # Update system status card
            if hasattr(self, 'status_card'):
                # Clear existing content
                for widget in self.status_card.winfo_children():
                    widget.destroy()
                
                # Add system info
                cpu_label = tk.Label(
                    self.status_card,
                    text=f"CPU: {cpu_percent:.1f}%",
                    font=('Segoe UI', 12, 'bold'),
                    fg=self.colors['accent_blue'],
                    bg=self.colors['bg_secondary']
                )
                cpu_label.pack(anchor='w', pady=2)
                
                memory_label = tk.Label(
                    self.status_card,
                    text=f"RAM: {memory.percent:.1f}%",
                    font=('Segoe UI', 12, 'bold'),
                    fg=self.colors['accent_green'],
                    bg=self.colors['bg_secondary']
                )
                memory_label.pack(anchor='w', pady=2)
                
                disk_label = tk.Label(
                    self.status_card,
                    text=f"Disk: {disk.percent:.1f}%",
                    font=('Segoe UI', 12, 'bold'),
                    fg=self.colors['accent_orange'],
                    bg=self.colors['bg_secondary']
                )
                disk_label.pack(anchor='w', pady=2)
            
            # Update every 5 seconds
            self.root.after(5000, self.update_system_info)
        except Exception as e:
            if hasattr(self, 'log_message'):
                self.log_message(f"Error updating system info: {e}")
            
    def log_message(self, message):
        """Add message to log display"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_entry = f"[{timestamp}] {message}\n"
        
        self.log_text.insert(tk.END, log_entry)
        self.log_text.see(tk.END)
        
        # Keep only last 1000 lines
        lines = self.log_text.get("1.0", tk.END).split('\n')
        if len(lines) > 1000:
            self.log_text.delete("1.0", f"{len(lines)-1000}.0")
            
    def clear_log(self):
        """Clear the log display"""
        self.log_text.delete("1.0", tk.END)
        
    def start_monitoring(self):
        """Start the monitoring thread"""
        if not self.is_monitoring:
            self.is_monitoring = True
            self.monitor_thread = threading.Thread(target=self.monitor_loop, daemon=True)
            self.monitor_thread.start()
            
            # Update header status
            self.header_status_label.config(text="● MONITORING ACTIVE", fg=self.colors['success'])
            
            # Update bot status card
            if hasattr(self, 'bot_status_card'):
                for widget in self.bot_status_card.winfo_children():
                    widget.destroy()
                
                status_label = tk.Label(
                    self.bot_status_card,
                    text="🟢 ACTIVE",
                    font=('Segoe UI', 16, 'bold'),
                    fg=self.colors['success'],
                    bg=self.colors['bg_secondary']
                )
                status_label.pack(anchor='w', pady=5)
                
                mode_label = tk.Label(
                    self.bot_status_card,
                    text="Real-time Protection",
                    font=('Segoe UI', 10),
                    fg=self.colors['text_secondary'],
                    bg=self.colors['bg_secondary']
                )
                mode_label.pack(anchor='w')
            
            self.start_button.config(state='disabled')
            self.stop_button.config(state='normal')
            
            self.log_message("🛡️ Cybersecurity Bot monitoring started")
            
    def stop_monitoring(self):
        """Stop the monitoring thread"""
        if self.is_monitoring:
            self.is_monitoring = False
            
            # Update header status
            self.header_status_label.config(text="● SYSTEM READY", fg=self.colors['text_muted'])
            
            # Update bot status card
            if hasattr(self, 'bot_status_card'):
                for widget in self.bot_status_card.winfo_children():
                    widget.destroy()
                
                status_label = tk.Label(
                    self.bot_status_card,
                    text="🔴 STOPPED",
                    font=('Segoe UI', 16, 'bold'),
                    fg=self.colors['danger'],
                    bg=self.colors['bg_secondary']
                )
                status_label.pack(anchor='w', pady=5)
                
                mode_label = tk.Label(
                    self.bot_status_card,
                    text="Standby Mode",
                    font=('Segoe UI', 10),
                    fg=self.colors['text_secondary'],
                    bg=self.colors['bg_secondary']
                )
                mode_label.pack(anchor='w')
            
            self.start_button.config(state='normal')
            self.stop_button.config(state='disabled')
            
            self.log_message("⏹️ Cybersecurity Bot monitoring stopped")
            
    def quick_scan(self):
        """Perform a quick scan without starting continuous monitoring"""
        self.log_message("🔍 Performing quick scan...")
        
        def scan():
            try:
                suspicious_processes = scan_for_malware()
                self.message_queue.put(('scan_result', len(suspicious_processes)))
                
                for process in suspicious_processes:
                    self.message_queue.put(('threat_detected', process))
                    
            except Exception as e:
                self.message_queue.put(('error', f"Scan error: {e}"))
                
        threading.Thread(target=scan, daemon=True).start()
        
    def monitor_loop(self):
        """Main monitoring loop (runs in separate thread)"""
        while self.is_monitoring:
            try:
                # Update configuration
                self.config['monitor_interval'] = int(self.interval_var.get())
                self.config['risk_threshold'] = float(self.threshold_var.get())
                self.config['email_alerts'] = self.email_var.get()
                self.config['popup_alerts'] = self.popup_var.get()
                
                # Perform scan
                suspicious_processes = scan_for_malware()
                self.message_queue.put(('scan_complete', len(suspicious_processes)))
                
                # Process each suspicious process
                for process in suspicious_processes:
                    self.message_queue.put(('threat_detected', process))
                    
                # Wait for next scan
                time.sleep(self.config['monitor_interval'])
                
            except Exception as e:
                self.message_queue.put(('error', f"Monitoring error: {e}"))
                time.sleep(5)  # Wait before retrying
                
    def check_queue(self):
        """Check for messages from monitoring thread"""
        try:
            while True:
                message_type, data = self.message_queue.get_nowait()
                
                if message_type == 'scan_complete':
                    self.last_scan_label.config(text=f"Last Scan: {datetime.now().strftime('%H:%M:%S')}")
                    
                elif message_type == 'threat_detected':
                    self.handle_threat_detected(data)
                    
                elif message_type == 'error':
                    self.log_message(f"❌ {data}")
                    
        except queue.Empty:
            pass
            
        # Check again in 100ms
        self.root.after(100, self.check_queue)
        
    def handle_threat_detected(self, process):
        """Handle a detected threat"""
        try:
            pid = process.pid
            process_name = process.name()
            
            # Get process info
            cpu = process.cpu_percent(interval=0.1)
            memory = process.memory_percent()
            
            # Calculate risk score
            try:
                num_threads = process.num_threads()
                num_connections = len(process.connections())
                features = [[cpu, memory, num_threads, num_connections]]
                risk_score = predict_process_risk(features)
            except:
                risk_score = 0.5  # Default risk score
                
            # Add to process tree with color coding
            status = "⚠️ Suspicious"
            status_color = self.colors['warning']
            if risk_score > self.config['risk_threshold']:
                status = "🚨 High Risk"
                status_color = self.colors['danger']
                
            item = self.process_tree.insert('', 'end', values=(
                pid, process_name, f"{cpu:.1f}%", f"{memory:.1f}%", 
                f"{risk_score:.2f}", status
            ))
            
            # Color code based on risk level
            if risk_score > 0.8:
                self.process_tree.set(item, 'Status', f"🚨 CRITICAL")
            elif risk_score > 0.6:
                self.process_tree.set(item, 'Status', f"⚠️ HIGH")
            else:
                self.process_tree.set(item, 'Status', f"🔍 LOW")
            
            # Update threat count
            self.threat_count += 1
            self.threat_count_label.config(text=f"Threats Detected: {self.threat_count}")
            
            # Log the detection
            self.log_message(f"🚨 Threat detected: {process_name} (PID: {pid}) - Risk: {risk_score:.2f}")
            
            # Send alerts if enabled
            if self.config['popup_alerts']:
                send_alert(process_name, pid)
                
            if self.config['email_alerts']:
                email_body = f"Threat detected: {process_name} (PID: {pid})\nRisk Score: {risk_score:.2f}"
                send_email_alert("⚠️ Threat Detected", email_body)
                
            # Auto-kill if high risk
            if risk_score > self.config['risk_threshold']:
                self.log_message(f"🔪 Auto-killing high-risk process: {process_name}")
                kill_process(pid)
                
        except Exception as e:
            self.log_message(f"❌ Error handling threat: {e}")
            
    def save_config(self):
        """Save configuration to file"""
        try:
            config_data = {
                'monitor_interval_seconds': int(self.interval_var.get()),
                'risk_score_kill_threshold': float(self.threshold_var.get()),
                'email_alerts': self.email_var.get(),
                'popups': self.popup_var.get()
            }
            
            import yaml
            with open(CONFIG_PATH, "r"), "w") as f:
                yaml.dump(config_data, f)
                
            self.log_message("💾 Configuration saved successfully")
            messagebox.showinfo("Success", "Configuration saved to config.yaml")
            
        except Exception as e:
            self.log_message(f"❌ Error saving config: {e}")
            messagebox.showerror("Error", f"Failed to save configuration: {e}")

def main():
    root = tk.Tk()
    
    # Set window icon and properties
    try:
        root.iconbitmap('icon.ico')  # Add an icon if you have one
    except:
        pass  # No icon file found
    
    # Configure window
    root.configure(bg='#0a0a0a')
    root.resizable(True, True)
    
    app = CybersecurityBotGUI(root)
    
    # Handle window closing
    def on_closing():
        app.animation_running = False
        if app.is_monitoring:
            app.stop_monitoring()
        root.destroy()
        
    root.protocol("WM_DELETE_WINDOW", on_closing)
    
    # Center window on screen
    root.update_idletasks()
    width = root.winfo_width()
    height = root.winfo_height()
    x = (root.winfo_screenwidth() // 2) - (width // 2)
    y = (root.winfo_screenheight() // 2) - (height // 2)
    root.geometry(f'{width}x{height}+{x}+{y}')
    
    root.mainloop()

if __name__ == "__main__":
    main()