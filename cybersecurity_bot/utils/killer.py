import psutil

def kill_process(pid):
    """
    Safely terminate a process with graceful fallback to force kill.
    
    Args:
        pid (int): Process ID to terminate
        
    Returns:
        bool: True if successfully terminated, False otherwise
    """
    try:
        process = psutil.Process(pid)
        process_name = process.name()
        
        print(f"🔄 Attempting to terminate process: {process_name} (PID: {pid})")
        
        # Step 1: Graceful termination
        process.terminate()
        
        # Step 2: Wait for graceful shutdown
        try:
            process.wait(timeout=3)
            print(f"✅ Process {process_name} (PID: {pid}) terminated gracefully")
            return True
        except psutil.TimeoutExpired:
            print(f"⚠️ Process {process_name} (PID: {pid}) didn't terminate gracefully, forcing kill...")
            
            # Step 3: Force kill if still running
            if process.poll() is None:  # Check if process is still running
                process.kill()
                process.wait(timeout=2)  # Wait for force kill
                print(f"✅ Process {process_name} (PID: {pid}) force killed")
                return True
            else:
                print(f"✅ Process {process_name} (PID: {pid}) already terminated")
                return True
                
    except psutil.NoSuchProcess:
        print(f"⚠️ Process with PID {pid} no longer exists")
        return True  # Process already gone
        
    except psutil.AccessDenied:
        print(f"❌ Access denied: Cannot terminate process {pid} (insufficient privileges)")
        return False
        
    except psutil.ZombieProcess:
        print(f"⚠️ Process {pid} is a zombie process (already dead)")
        return True
        
    except Exception as e:
        print(f"❌ Unexpected error killing process {pid}: {e}")
        return False