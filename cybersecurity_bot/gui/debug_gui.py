#!/usr/bin/env python3
"""
Debug version of the GUI to identify layout issues
"""

import tkinter as tk
import psutil

def create_simple_gui():
    root = tk.Tk()
    root.title("🛡️ Cybersecurity Bot - Debug")
    root.geometry("800x600")
    root.configure(bg='#0a0a0a')
    
    # Main container
    main_container = tk.Frame(root, bg='#0a0a0a')
    main_container.pack(fill='both', expand=True, padx=20, pady=20)
    
    # Header
    header_frame = tk.Frame(main_container, bg='#0a0a0a')
    header_frame.pack(fill='x', pady=(0, 20))
    
    title_label = tk.Label(
        header_frame,
        text="🛡️ Cybersecurity Bot - Debug Version",
        font=('Arial', 20, 'bold'),
        fg='#00ff00',
        bg='#0a0a0a'
    )
    title_label.pack()
    
    # Status frame
    status_frame = tk.Frame(main_container, bg='#1a1a1a', relief='raised', bd=2)
    status_frame.pack(fill='x', pady=(0, 20))
    
    status_label = tk.Label(
        status_frame,
        text="System Status: Ready",
        font=('Arial', 12),
        fg='white',
        bg='#1a1a1a'
    )
    status_label.pack(pady=10)
    
    # Control buttons
    button_frame = tk.Frame(main_container, bg='#0a0a0a')
    button_frame.pack(fill='x', pady=(0, 20))
    
    start_button = tk.Button(
        button_frame,
        text="🚀 Start Monitoring",
        font=('Arial', 12, 'bold'),
        bg='#00aa00',
        fg='white',
        relief='raised',
        bd=3,
        padx=20,
        pady=10
    )
    start_button.pack(side='left', padx=5)
    
    stop_button = tk.Button(
        button_frame,
        text="⏹️ Stop Monitoring",
        font=('Arial', 12, 'bold'),
        bg='#aa0000',
        fg='white',
        relief='raised',
        bd=3,
        padx=20,
        pady=10
    )
    stop_button.pack(side='left', padx=5)
    
    # System info
    info_frame = tk.Frame(main_container, bg='#1a1a1a', relief='raised', bd=2)
    info_frame.pack(fill='x', pady=(0, 20))
    
    try:
        cpu_percent = psutil.cpu_percent(interval=0.1)
        memory = psutil.virtual_memory()
        
        cpu_label = tk.Label(
            info_frame,
            text=f"CPU: {cpu_percent:.1f}%",
            font=('Arial', 12),
            fg='#00d4ff',
            bg='#1a1a1a'
        )
        cpu_label.pack(anchor='w', padx=10, pady=5)
        
        memory_label = tk.Label(
            info_frame,
            text=f"RAM: {memory.percent:.1f}%",
            font=('Arial', 12),
            fg='#00ff88',
            bg='#1a1a1a'
        )
        memory_label.pack(anchor='w', padx=10, pady=5)
        
    except Exception as e:
        error_label = tk.Label(
            info_frame,
            text=f"Error: {e}",
            font=('Arial', 12),
            fg='#ff4757',
            bg='#1a1a1a'
        )
        error_label.pack(anchor='w', padx=10, pady=5)
    
    # Process list
    process_frame = tk.Frame(main_container, bg='#1a1a1a', relief='raised', bd=2)
    process_frame.pack(fill='both', expand=True)
    
    process_label = tk.Label(
        process_frame,
        text="Process List",
        font=('Arial', 12, 'bold'),
        fg='white',
        bg='#1a1a1a'
    )
    process_label.pack(pady=10)
    
    # Simple listbox
    listbox = tk.Listbox(
        process_frame,
        bg='#2a2a2a',
        fg='white',
        font=('Consolas', 9)
    )
    listbox.pack(fill='both', expand=True, padx=10, pady=(0, 10))
    
    # Add some sample processes
    try:
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                listbox.insert(tk.END, f"{proc.info['pid']} - {proc.info['name']}")
                if listbox.size() > 10:  # Limit to 10 processes for demo
                    break
            except:
                continue
    except Exception as e:
        listbox.insert(tk.END, f"Error loading processes: {e}")
    
    print("Debug GUI created successfully!")
    root.mainloop()

if __name__ == "__main__":
    create_simple_gui()
