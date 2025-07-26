import psutil

def kill_process(pid):
    try:
        process = psutil.Process(pid)
        process.terminate()  # politely ask to quit
        process.wait(3)      # wait 3 sec
        if process.is_running():
            process.kill()   # force kill if still running
        print(f"✅ Process {pid} terminated")
    except Exception as e:
        print(f"❌ Error killing process {pid}: {e}")
