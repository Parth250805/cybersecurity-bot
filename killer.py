# killer.py
import psutil

def kill_process(process_name, pid):
    try:
        p = psutil.Process(pid)
        p.terminate()
        print(f"🛑 Terminated {process_name} (PID: {pid})")
    except psutil.NoSuchProcess:
        print(f"⚠️ Process {process_name} not found.")
    except psutil.AccessDenied:
        print(f"⛔ Access denied when trying to terminate {process_name}.")
