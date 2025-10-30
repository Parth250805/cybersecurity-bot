from pathlib import Path
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import time
import queue
import os
import math
from datetime import datetime
import psutil
import subprocess
import sys
import yaml

# Get the paths
MAIN_PY = Path(__file__).resolve().parents[2] / "main.py"
CONFIG_PATH = Path(__file__).resolve().parents[1] / "config" / "config.yaml"
LOCK_PATH = Path(__file__).resolve().parents[2] / ".run.lock"

# Try to remove stale lock file
try:
    LOCK_PATH.unlink(missing_ok=True)
except:
    pass

from cybersecurity_bot.core.detector import scan_for_malware
from cybersecurity_bot.core.threat_handler import handle_threat
from cybersecurity_bot.utils.emailer import send_email_alert  # Only needed for startup email
from cybersecurity_bot.utils.logger import log_detection

class SimpleCybersecurityBotGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("🛡️ Cybersecurity Bot - Simple Version")
        self.root.geometry("1000x700")
        self.root.configure(bg='#0a0a0a')
        self.current_process = None  # Store reference to current main.py process
        
        # Colors
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
            'success': '#2ed573',
            'warning': '#ffa502',
            'danger': '#ff4757'
        }
        
        # Bot state
        self.is_monitoring = False
        self.monitor_thread = None
        self.message_queue = queue.Queue()
        self.stop_event = threading.Event()
        
        # Initialize configuration
        self.load_config()
        
        # Variables from config
        self.interval_var = tk.StringVar(value=str(self.config['monitor_interval']))
        self.threshold_var = tk.StringVar(value=str(self.config['risk_threshold']))
        self.email_var = tk.BooleanVar(value=self.config['email_alerts'])
        self.popup_var = tk.BooleanVar(value=self.config['popup_alerts'])
        
        self.setup_ui()
        self.check_queue()

    def load_config(self):
        """Load configuration from config.yaml"""
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                config_data = yaml.safe_load(f) or {}
                
            # Configuration with defaults
            self.config = {
                'monitor_interval': config_data.get('monitor_interval_seconds', 5),
                'risk_threshold': config_data.get('risk_score_kill_threshold', 0.7),
                'email_alerts': config_data.get('email_alerts', True),
                'popup_alerts': config_data.get('popups', True)
            }
        except Exception as e:
            print(f"Error loading config: {e}, using defaults")
            self.config = {
                'monitor_interval': 5,
                'risk_threshold': 0.7,
                'email_alerts': True,
                'popup_alerts': True
            }
        
    def setup_ui(self):
        # Main title
        title_frame = tk.Frame(self.root, bg=self.colors['bg_primary'])
        title_frame.pack(fill='x', padx=20, pady=10)
        
        title_label = tk.Label(
            title_frame,
            text="🛡️ Cybersecurity Bot",
            font=('Arial', 24, 'bold'),
            fg=self.colors['accent_blue'],
            bg=self.colors['bg_primary']
        )
        title_label.pack()
        
        subtitle_label = tk.Label(
            title_frame,
            text="Professional Threat Detection System",
            font=('Arial', 12),
            fg=self.colors['text_secondary'],
            bg=self.colors['bg_primary']
        )
        subtitle_label.pack()
        
        # Status frame
        self.setup_status_frame()
        
        # Control frame
        self.setup_control_frame()
        
        # Configuration frame
        self.setup_config_frame()
        
        # Monitoring frame
        self.setup_monitoring_frame()
        
        # Log frame
        self.setup_log_frame()
        
    def setup_status_frame(self):
        status_frame = tk.LabelFrame(
            self.root,
            text="System Status",
            font=('Arial', 12, 'bold'),
            fg='white',
            bg=self.colors['bg_primary'],
            relief='raised',
            bd=2
        )
        status_frame.pack(fill='x', padx=20, pady=10)
        
        # Status indicators
        self.status_label = tk.Label(
            status_frame,
            text="🔴 STOPPED",
            font=('Arial', 14, 'bold'),
            fg=self.colors['danger'],
            bg=self.colors['bg_primary']
        )
        self.status_label.pack(side='left', padx=10, pady=10)
        
        # System info
        self.system_info_label = tk.Label(
            status_frame,
            text="",
            font=('Arial', 10),
            fg='white',
            bg=self.colors['bg_primary']
        )
        self.system_info_label.pack(side='right', padx=10, pady=10)
        
        self.update_system_info()
        
    def setup_control_frame(self):
        control_frame = tk.LabelFrame(
            self.root,
            text="Bot Controls",
            font=('Arial', 12, 'bold'),
            fg='white',
            bg=self.colors['bg_primary'],
            relief='raised',
            bd=2
        )
        control_frame.pack(fill='x', padx=20, pady=10)
        
        button_frame = tk.Frame(control_frame, bg=self.colors['bg_primary'])
        button_frame.pack(pady=10)
        
        self.start_button = tk.Button(
            button_frame,
            text="🚀 Start Monitoring",
            command=self.start_monitoring,
            font=('Arial', 12, 'bold'),
            bg=self.colors['success'],
            fg='white',
            relief='raised',
            bd=3,
            padx=20,
            pady=10
        )
        self.start_button.pack(side='left', padx=5)
        
        self.stop_button = tk.Button(
            button_frame,
            text="⏹️ Stop Monitoring",
            command=self.stop_monitoring,
            font=('Arial', 12, 'bold'),
            bg=self.colors['danger'],
            fg='white',
            relief='raised',
            bd=3,
            padx=20,
            pady=10,
            state='disabled'
        )
        self.stop_button.pack(side='left', padx=5)
        
        self.scan_button = tk.Button(
            button_frame,
            text="🔍 Quick Scan",
            command=self.quick_scan,
            font=('Arial', 12, 'bold'),
            bg=self.colors['accent_blue'],
            fg='white',
            relief='raised',
            bd=3,
            padx=20,
            pady=10
        )
        self.scan_button.pack(side='left', padx=5)
        
    def setup_config_frame(self):
        config_frame = tk.LabelFrame(
            self.root,
            text="Configuration",
            font=('Arial', 12, 'bold'),
            fg='white',
            bg=self.colors['bg_primary'],
            relief='raised',
            bd=2
        )
        config_frame.pack(fill='x', padx=20, pady=10)
        
        config_grid = tk.Frame(config_frame, bg=self.colors['bg_primary'])
        config_grid.pack(pady=10)
        
        # Monitor interval
        tk.Label(config_grid, text="Monitor Interval (seconds):", 
                fg='white', bg=self.colors['bg_primary'], font=('Arial', 10)).grid(row=0, column=0, sticky='w', padx=5)
        interval_entry = tk.Entry(config_grid, textvariable=self.interval_var, width=10)
        interval_entry.grid(row=0, column=1, padx=5)
        
        # Risk threshold
        tk.Label(config_grid, text="Risk Threshold:", 
                fg='white', bg=self.colors['bg_primary'], font=('Arial', 10)).grid(row=0, column=2, sticky='w', padx=5)
        threshold_entry = tk.Entry(config_grid, textvariable=self.threshold_var, width=10)
        threshold_entry.grid(row=0, column=3, padx=5)
        
        # Email alerts
        self.email_var = tk.BooleanVar(value=self.config['email_alerts'])
        email_check = tk.Checkbutton(config_grid, text="Email Alerts", 
                                   variable=self.email_var, fg='white', bg=self.colors['bg_primary'])
        email_check.grid(row=1, column=0, sticky='w', padx=5)
        
        # Popup alerts
        self.popup_var = tk.BooleanVar(value=self.config['popup_alerts'])
        popup_check = tk.Checkbutton(config_grid, text="Popup Alerts", 
                                   variable=self.popup_var, fg='white', bg=self.colors['bg_primary'])
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
            bg=self.colors['bg_primary'],
            relief='raised',
            bd=2
        )
        monitor_frame.pack(fill='both', expand=True, padx=20, pady=10)
        
        # Threat counter
        threat_frame = tk.Frame(monitor_frame, bg=self.colors['bg_primary'])
        threat_frame.pack(fill='x', padx=10, pady=5)
        
        self.threat_count_label = tk.Label(
            threat_frame,
            text="Threats Detected: 0",
            font=('Arial', 12, 'bold'),
            fg=self.colors['danger'],
            bg=self.colors['bg_primary']
        )
        self.threat_count_label.pack(side='left')
        
        self.last_scan_label = tk.Label(
            threat_frame,
            text="Last Scan: Never",
            font=('Arial', 10),
            fg='white',
            bg=self.colors['bg_primary']
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
        
        # Scrollbar
        process_scroll = ttk.Scrollbar(monitor_frame, orient='vertical', command=self.process_tree.yview)
        self.process_tree.configure(yscrollcommand=process_scroll.set)
        
        self.process_tree.pack(side='left', fill='both', expand=True, padx=(10, 0), pady=5)
        process_scroll.pack(side='right', fill='y', pady=5)
        
        self.threat_count = 0
        
    def setup_log_frame(self):
        log_frame = tk.LabelFrame(
            self.root,
            text="Activity Log",
            font=('Arial', 12, 'bold'),
            fg='white',
            bg=self.colors['bg_primary'],
            relief='raised',
            bd=2
        )
        log_frame.pack(fill='x', padx=20, pady=10)
        
        self.log_text = scrolledtext.ScrolledText(
            log_frame,
            height=6,
            font=('Consolas', 9),
            bg=self.colors['bg_tertiary'],
            fg=self.colors['accent_green'],
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
            
            info_text = f"CPU: {cpu_percent}% | RAM: {memory.percent}% | Disk: {disk.percent}%"
            self.system_info_label.config(text=info_text)
            
            # Update every 5 seconds
            self.root.after(5000, self.update_system_info)
        except Exception as e:
            self.log_message(f"Error updating system info: {e}")
            
    def log_message(self, message):
        """Add message to log display"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_entry = f"[{timestamp}] {message}\n"
        
        self.log_text.insert(tk.END, log_entry)
        self.log_text.see(tk.END)
        print(log_entry.strip())  # Also print to terminal
        
    def clear_log(self):
        """Clear the log display"""
        self.log_text.delete("1.0", tk.END)
        
    def monitor_loop(self):
        """Main monitoring loop (runs in separate thread)"""
        from cybersecurity_bot.core.detector import monitor_processes
        from cybersecurity_bot.utils.emailer import send_email_alert
        
        self.log_message("🛡️ Cybersecurity Bot monitoring started")
        self.threat_count = 0  # Reset threat counter
        
        # Send startup email if enabled
        if self.config['email_alerts']:
            try:
                startup_message = (
                    "The Cybersecurity Bot has started monitoring your system.\n\n"
                    "Current Configuration:\n"
                    f"- Monitor Interval: {self.config['monitor_interval']} seconds\n"
                    f"- Risk Threshold: {self.config['risk_threshold']}\n"
                    f"- Email Alerts: {'Enabled' if self.config['email_alerts'] else 'Disabled'}\n"
                    f"- Popup Alerts: {'Enabled' if self.config['popup_alerts'] else 'Disabled'}"
                )
                send_email_alert(
                    subject="🛡️ Cybersecurity Bot Started",
                    body=startup_message
                )
                self.log_message("📧 Startup email sent")
            except Exception as e:
                self.log_message(f"❌ Failed to send startup email: {e}")
        
        def status_callback(event_type, data):
            """Handle status updates from the monitoring process"""
            if event_type == "scan_start":
                print(f"\n� Starting scan #{data['count']}...")
            elif event_type == "threats_found":
                for process in data['processes']:
                    self.root.after(0, lambda p=process: self.handle_threat_detected(p))
                print(f"⚠️ Found {data['count']} suspicious processes in this scan.")
            elif event_type == "all_clear":
                self.root.after(0, lambda: self.log_message("✅ System scan completed - No threats detected"))
            elif event_type == "scan_complete":
                print(f"✅ Scan #{data['count']} completed!")
        
        try:
            # Start monitoring with callback for updates
            monitor_processes(
                stop_event=self.stop_event,
                config={
                    'monitor_interval_seconds': self.config['monitor_interval'],
                    'risk_threshold': self.config['risk_threshold']
                },
                callback=status_callback
            )

        except Exception as e:
            self.log_message(f"❌ Error in monitoring loop: {str(e)}")
        finally:
            if not self.stop_event.is_set():
                self.root.after(0, lambda: self.status_label.config(text="🔴 STOPPED", fg=self.colors['danger']))
                self.root.after(0, lambda: self.start_button.config(state='normal'))
                self.root.after(0, lambda: self.stop_button.config(state='disabled'))
                self.log_message("⏹️ Monitoring stopped due to error")
            
    def start_monitoring(self):
        """Start the monitoring using main.py"""
        if self.is_monitoring:
            return
        if self.monitor_thread is not None and self.monitor_thread.is_alive():
            return
            
        try:
            self.is_monitoring = True
            self.stop_event.clear()
            
            # Start main.py in a separate thread
            self.monitor_thread = threading.Thread(target=self.monitor_loop, daemon=True)
            self.monitor_thread.start()
            
            self.status_label.config(text="🟢 MONITORING", fg=self.colors['success'])
            self.start_button.config(state='disabled')
            self.stop_button.config(state='normal')
            
            self.log_message("🛡️ Cybersecurity Bot monitoring started")
            
        except Exception as e:
            self.is_monitoring = False
            self.log_message(f"❌ Failed to start monitoring: {e}")
            
    def stop_monitoring(self):
        """Stop the monitoring thread"""
        if self.is_monitoring:
            self.is_monitoring = False
            self.stop_event.set()
            
            self.log_message("🛑 Stopping Cybersecurity Bot...")
            
            try:
                if self.monitor_thread is not None:
                    self.monitor_thread.join(timeout=5.0)
            except Exception as e:
                print(f"Error stopping monitor thread: {e}")
            
            try:
                if self.monitor_thread is not None:
                    self.monitor_thread.join(timeout=1.0)
            except Exception:
                pass
            
            self.status_label.config(text="🔴 STOPPED", fg=self.colors['danger'])
            self.start_button.config(state='normal')
            self.stop_button.config(state='disabled')
            
            self.log_message("⏹️ Cybersecurity Bot monitoring stopped")
            
    def quick_scan(self):
        """Perform a quick scan directly"""
        if self.is_monitoring:
            self.log_message("⚠️ Please stop monitoring first before running a quick scan")
            return
            
        self.log_message("🔍 Starting quick scan...")
        
        def run_quick_scan():
            try:
                from cybersecurity_bot.core.detector import scan_for_malware
                
                # Create a new stop event for the quick scan
                quick_scan_event = threading.Event()
                suspicious_processes = scan_for_malware(quick_scan_event)
                threats_found = len(suspicious_processes)
                
                # Handle any threats found
                for process in suspicious_processes:
                    try:
                        self.handle_threat_detected(process)
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                    
                # Log results
                self.log_message(f"✅ Quick scan complete!")
                if threats_found > 0:
                    self.log_message(f"⚠️ Found {threats_found} suspicious processes.")
                else:
                    self.log_message("🟢 No suspicious processes found!")
                
            except Exception as e:
                self.log_message(f"❌ Quick scan error: {str(e)}")
                
        threading.Thread(target=run_quick_scan, daemon=True).start()
            
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
                    
                elif message_type == 'log':
                    self.log_message(data)
                    
                elif message_type == 'monitoring_stopped':
                    self.is_monitoring = False
                    self.status_label.config(text="🔴 STOPPED", fg=self.colors['danger'])
                    self.start_button.config(state='normal')
                    self.stop_button.config(state='disabled')
                    
        except queue.Empty:
            pass
            
        # Check again in 100ms
        self.root.after(100, self.check_queue)
        
    def handle_threat_detected(self, process):
        """Handle a detected threat using the threat handler module"""
        def handle_callback(event_type, data):
            """Handle status updates from threat handling"""
            if event_type == "alert_sent":
                if data == "email":
                    self.log_message("📧 Email alert sent")
                elif data == "popup":
                    self.log_message("🔔 Popup alert shown")
            elif event_type == "alert_failed":
                self.log_message(f"❌ Failed to send {data['type']} alert: {data['error']}")
            elif event_type == "process_terminated":
                self.log_message(f"� High-risk process terminated: PID {data}")
            elif event_type == "termination_failed":
                self.log_message(f"❌ Failed to terminate process {data['pid']}: {data['error']}")
            elif event_type == "process_error":
                self.log_message(f"⚠️ Process error: {data}")
            elif event_type == "error":
                self.log_message(f"❌ Error: {data}")

        try:
            # Handle the threat using the threat handler module
            result = handle_threat(process, self.config, handle_callback)
            
            if "error" in result:
                return
                
            # Update GUI with results
            self.process_tree.insert('', 'end', values=(
                result['pid'],
                result['name'],
                f"{result['cpu_percent']:.1f}%",
                f"{result['memory_percent']:.1f}%",
                f"{result['risk_score']:.2f}",
                result['status']
            ))
            
            # Update threat count
            self.threat_count += 1
            self.threat_count_label.config(text=f"Threats Detected: {self.threat_count}")
            
            # Log the detection
            self.log_message(
                f"🚨 Threat detected: {result['name']} "
                f"(PID: {result['pid']}) - Risk: {result['risk_score']:.2f}"
            )
            
        except Exception as e:
            self.log_message(f"❌ Error handling threat: {e}")
            
    def save_config(self):
        """Save configuration to file"""
        try:
            # Validate values before saving
            try:
                monitor_interval = int(self.interval_var.get())
                if monitor_interval < 1:
                    raise ValueError("Monitor interval must be at least 1 second")
                    
                risk_threshold = float(self.threshold_var.get())
                if not 0 <= risk_threshold <= 1:
                    raise ValueError("Risk threshold must be between 0 and 1")
                    
                # Update local config
                self.config['monitor_interval'] = monitor_interval
                self.config['risk_threshold'] = risk_threshold
                self.config['email_alerts'] = self.email_var.get()
                self.config['popup_alerts'] = self.popup_var.get()
            except ValueError as e:
                messagebox.showerror("Invalid Value", str(e))
                return
                
            # Save to file
            config_data = {
                'monitor_interval_seconds': self.config['monitor_interval'],
                'risk_score_kill_threshold': self.config['risk_threshold'],
                'email_alerts': self.config['email_alerts'],
                'popups': self.config['popup_alerts']
            }
            
            with open(CONFIG_PATH, "w", encoding="utf-8") as f:
                yaml.dump(config_data, f)
                
            self.log_message("💾 Configuration saved successfully")
            messagebox.showinfo("Success", "Configuration saved to config.yaml")
            
        except Exception as e:
            self.log_message(f"❌ Error saving config: {e}")
            messagebox.showerror("Error", f"Failed to save configuration: {e}")

def main():
    root = tk.Tk()
    app = SimpleCybersecurityBotGUI(root)
    
    # Handle window closing
    def on_closing():
        try:
            if app.is_monitoring:
                app.stop_monitoring()
                time.sleep(1)  # Wait for process cleanup
            
            # Clean up lock file one last time
            LOCK_PATH.unlink(missing_ok=True)
            
            root.destroy()
            # Force exit after 2 seconds if normal shutdown fails
            import threading
            threading.Timer(2.0, lambda: os._exit(0)).start()
        except Exception as e:
            print(f"Error during shutdown: {e}")
            os._exit(1)
        
    def force_exit(e=None):
        # Handle Ctrl+C in GUI
        try:
            if app.is_monitoring:
                app.stop_monitoring()
                time.sleep(1)  # Wait for process cleanup
            
            # Clean up lock file one last time
            LOCK_PATH.unlink(missing_ok=True)
            
            root.destroy()
            os._exit(0)
        except Exception as e:
            print(f"Error during force exit: {e}")
            os._exit(1)
        
    root.protocol("WM_DELETE_WINDOW", on_closing)
    root.bind('<Control-c>', force_exit)
    
    try:
        root.mainloop()
    except KeyboardInterrupt:
        force_exit()
    except Exception as e:
        print(f"Error in main loop: {e}")
        force_exit()

if __name__ == "__main__":
    main()