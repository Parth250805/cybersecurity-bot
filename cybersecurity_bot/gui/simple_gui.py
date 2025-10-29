from pathlib import Path

CONFIG_PATH = Path(__file__).resolve().parents[1] / "config" / "config.yaml"
#!/usr/bin/env python3
"""
Simplified version of the cybersecurity bot GUI
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
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

class SimpleCybersecurityBotGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("🛡️ Cybersecurity Bot - Simple Version")
        self.root.geometry("1000x700")
        self.root.configure(bg='#0a0a0a')
        
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
        
        # Configuration
        self.config = {
            'monitor_interval': 5,
            'risk_threshold': 0.7,
            'email_alerts': True,
            'popup_alerts': True
        }
        
        # Variables
        self.interval_var = tk.StringVar(value=str(self.config['monitor_interval']))
        self.threshold_var = tk.StringVar(value=str(self.config['risk_threshold']))
        self.email_var = tk.BooleanVar(value=self.config['email_alerts'])
        self.popup_var = tk.BooleanVar(value=self.config['popup_alerts'])
        
        self.setup_ui()
        self.check_queue()
        
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
        
    def clear_log(self):
        """Clear the log display"""
        self.log_text.delete("1.0", tk.END)
        
    def start_monitoring(self):
        """Start the monitoring thread"""
        if not self.is_monitoring:
            self.is_monitoring = True
            self.monitor_thread = threading.Thread(target=self.monitor_loop, daemon=True)
            self.monitor_thread.start()
            
            self.status_label.config(text="🟢 MONITORING", fg=self.colors['success'])
            self.start_button.config(state='disabled')
            self.stop_button.config(state='normal')
            
            self.log_message("🛡️ Cybersecurity Bot monitoring started")
            
    def stop_monitoring(self):
        """Stop the monitoring thread"""
        if self.is_monitoring:
            self.is_monitoring = False
            
            self.status_label.config(text="🔴 STOPPED", fg=self.colors['danger'])
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
                
            # Add to process tree
            status = "⚠️ Suspicious"
            if risk_score > self.config['risk_threshold']:
                status = "🚨 High Risk"
                
            self.process_tree.insert('', 'end', values=(
                pid, process_name, f"{cpu:.1f}%", f"{memory:.1f}%", 
                f"{risk_score:.2f}", status
            ))
            
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
    app = SimpleCybersecurityBotGUI(root)
    
    # Handle window closing
    def on_closing():
        if app.is_monitoring:
            app.stop_monitoring()
        root.destroy()
        
    root.protocol("WM_DELETE_WINDOW", on_closing)
    root.mainloop()

if __name__ == "__main__":
    main()