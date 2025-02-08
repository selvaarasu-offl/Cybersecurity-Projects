import psutil
import ctypes
import time
import os

# Function to check if a process is using a keyboard hook (Windows only)
def is_keylogger(process):
    try:
        user32 = ctypes.WinDLL('user32', use_last_error=True)
        hooks = user32.GetWindowsHookExW(13)  # WH_KEYBOARD_LL hook
        return hooks != 0
    except Exception as e:
        return False

# Function to scan running processes
def scan_processes():
    print("Scanning for keyloggers...")
    for process in psutil.process_iter(['pid', 'name']):
        try:
            process_name = process.info['name'].lower()
            if any(keyword in process_name for keyword in ["keylogger", "hook", "log"]):
                print(f"[ALERT] Suspicious process detected: {process.info['name']} (PID: {process.info['pid']})")
                
            if is_keylogger(process):
                print(f"[ALERT] Possible keylogger detected: {process.info['name']} (PID: {process.info['pid']})")
                
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

if __name__ == "__main__":
    start_time = time.time()
    while True:
        scan_processes()
        if time.time() - start_time > 10:
            break
        time.sleep(1)  # Scan every 1 second


