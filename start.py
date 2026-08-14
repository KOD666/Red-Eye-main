#!/usr/bin/env python3
import os
import sys
import re
import socket
import subprocess
import time
import signal
import threading

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

def print_prefix(prefix, line):
    print(f"\033[1;36m{prefix}\033[0m {line}", end="", flush=True)

def stream_logs(process, prefix):
    for line in iter(process.stdout.readline, ''):
        print_prefix(prefix, line)

def get_detected_ip():
    default_ip = "192.168.1.50"
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        detected_ip = s.getsockname()[0]
        s.close()
        if detected_ip and not detected_ip.startswith("127."):
            return detected_ip
    except Exception:
        pass
    return default_ip

def prompt_user_ip():
    auto_ip = get_detected_ip()
    print(f"\033[1;36m[?] Enter Local IP address for C2 Gateway [Press Enter for {auto_ip}]: \033[0m", end="", flush=True)
    try:
        user_input = input().strip()
    except (KeyboardInterrupt, EOFError):
        print()
        sys.exit(0)
    
    selected_ip = user_input if user_input else auto_ip
    print(f"\033[1;32m[+] Selected Local IP: {selected_ip}\033[0m")
    return selected_ip

def sync_project_ip(target_ip, root_dir):
    print(f"\033[1;33m[+] Syncing Local IP ({target_ip}:8000) across project files...\033[0m")
    
    # 1. Update frontend/src/App.jsx
    app_jsx = os.path.join(root_dir, "frontend", "src", "App.jsx")
    if os.path.exists(app_jsx):
        try:
            with open(app_jsx, "r") as f:
                content = f.read()
            content = re.sub(r'http://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:8000', f'http://{target_ip}:8000', content)
            content = re.sub(r'C2 Console: [^(]+\(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\)', f'C2 Console: Host ({target_ip})', content)
            content = re.sub(r"ip: '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'", f"ip: '{target_ip}'", content)
            with open(app_jsx, "w") as f:
                f.write(content)
        except Exception as e:
            print(f"\033[1;31m[!] Error updating {app_jsx}: {e}\033[0m")

    # 2. Update agents/linux/agent.py & backend/agent.py
    for rel_path in ["agents/linux/agent.py", "backend/agent.py"]:
        p = os.path.join(root_dir, rel_path)
        if os.path.exists(p):
            try:
                with open(p, "r") as f:
                    content = f.read()
                content = re.sub(r'BASE_URL = "http://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:8000"', f'BASE_URL = "http://{target_ip}:8000"', content)
                with open(p, "w") as f:
                    f.write(content)
            except Exception as e:
                print(f"\033[1;31m[!] Error updating {p}: {e}\033[0m")

    # 3. Update agents/windows/Red-Eye.py
    win_agent = os.path.join(root_dir, "agents", "windows", "Red-Eye.py")
    if os.path.exists(win_agent):
        try:
            with open(win_agent, "r") as f:
                content = f.read()
            content = re.sub(r'http://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:8000', f'http://{target_ip}:8000', content)
            with open(win_agent, "w") as f:
                f.write(content)
        except Exception as e:
            print(f"\033[1;31m[!] Error updating {win_agent}: {e}\033[0m")

    # 4. Update agents/android/App.js
    android_app = os.path.join(root_dir, "agents", "android", "App.js")
    if os.path.exists(android_app):
        try:
            with open(android_app, "r") as f:
                content = f.read()
            content = re.sub(r'http://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:8000', f'http://{target_ip}:8000', content)
            with open(android_app, "w") as f:
                f.write(content)
        except Exception as e:
            print(f"\033[1;31m[!] Error updating {android_app}: {e}\033[0m")

def main():
    print("\033[1;32m[+] Starting RedEye Telemetry C2 Platform...\033[0m")
    
    root_dir = os.path.dirname(os.path.abspath(__file__))

    # Prompt user for Local IP address
    local_ip = prompt_user_ip()

    # Sync Local IP across all backend, frontend, and agent source files
    sync_project_ip(local_ip, root_dir)
    
    # 1. Start/Check PostgreSQL service
    print("\033[1;33m[+] Checking PostgreSQL database status...\033[0m")
    try:
        if os.name == 'nt':
            service_name = "postgresql-x64-18"
            status = subprocess.run(["sc", "query", service_name], capture_output=True, text=True)
            if "RUNNING" not in status.stdout:
                print(f"\033[1;31m[-] PostgreSQL ({service_name}) is not running. Attempting to start service...\033[0m")
                subprocess.run(["net", "start", service_name])
            else:
                print(f"\033[1;32m[+] PostgreSQL ({service_name}) database is active.\033[0m")
        else:
            status = subprocess.run(["systemctl", "is-active", "postgresql"], capture_output=True, text=True)
            if status.stdout.strip() != "active":
                print("\033[1;31m[-] PostgreSQL is not running. Attempting to start service (may prompt for password)...\033[0m")
                subprocess.run(["sudo", "systemctl", "start", "postgresql"])
            else:
                print("\033[1;32m[+] PostgreSQL database is active.\033[0m")
    except Exception as e:
        print(f"\033[1;31m[!] Warning: Failed to check/start PostgreSQL service automatically: {e}\033[0m")

    # Determine paths
    venv_python = sys.executable or "python" # fallback
    
    if os.name == 'nt':
        paths_to_try = [
            os.path.join(root_dir, ".venv", "Scripts", "python.exe"),
            os.path.join(root_dir, "venv_win", "Scripts", "python.exe"),
            os.path.join(root_dir, "venv", "Scripts", "python.exe"),
        ]
        for p in paths_to_try:
            if os.path.exists(p):
                venv_python = p
                break
    else:
        paths_to_try = [
            os.path.join(root_dir, ".venv", "bin", "python"),
            os.path.join(root_dir, "venv", "bin", "python"),
            os.path.join(root_dir, "venv_win", "bin", "python"),
        ]
        for p in paths_to_try:
            if os.path.exists(p):
                venv_python = p
                break

    # 2. Spawn FastAPI Gateway Server
    backend_cmd = [
        venv_python, "-m", "uvicorn", "backend.main:app",
        "--host", local_ip, "--port", "8000", "--reload"
    ]
    print(f"\033[1;33m[+] Launching FastAPI Gateway: {' '.join(backend_cmd)}\033[0m")
    
    popen_kwargs = {
        "cwd": root_dir,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.STDOUT,
        "text": True,
        "bufsize": 1,
    }
    if os.name == 'nt':
        popen_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        popen_kwargs["preexec_fn"] = os.setsid

    backend_proc = subprocess.Popen(backend_cmd, **popen_kwargs)

    # 3. Spawn Electron UI Frontend
    frontend_cmd = ["npm", "run", "electron:dev"]
    frontend_dir = os.path.join(root_dir, "frontend")
    print(f"\033[1;33m[+] Launching Electron Frontend: {' '.join(frontend_cmd)} inside {frontend_dir}\033[0m")
    
    frontend_popen_kwargs = popen_kwargs.copy()
    frontend_popen_kwargs["cwd"] = frontend_dir
    if os.name == 'nt':
        frontend_popen_kwargs["shell"] = True

    frontend_proc = subprocess.Popen(frontend_cmd, **frontend_popen_kwargs)

    # 4. Spawn Threat Intel Scanning Daemons
    scan_cmd = [venv_python, "scan_detected.py"]
    print(f"\033[1;33m[+] Launching Threat Intel Scan Daemon (Detected): {' '.join(scan_cmd)}\033[0m")
    scan_proc = subprocess.Popen(scan_cmd, **popen_kwargs)

    scan_suspicious_cmd = [venv_python, "scan_suspicious.py"]
    print(f"\033[1;33m[+] Launching Threat Intel Scan Daemon (Suspicious): {' '.join(scan_suspicious_cmd)}\033[0m")
    scan_suspicious_proc = subprocess.Popen(scan_suspicious_cmd, **popen_kwargs)

    # Start stdout/stderr streaming threads
    backend_thread = threading.Thread(target=stream_logs, args=(backend_proc, "[C2-BACKEND]"))
    frontend_thread = threading.Thread(target=stream_logs, args=(frontend_proc, "[ELECTRON-UI]"))
    scan_thread = threading.Thread(target=stream_logs, args=(scan_proc, "[SCAN-DETECTED]"))
    scan_suspicious_thread = threading.Thread(target=stream_logs, args=(scan_suspicious_proc, "[SCAN-SUSPICIOUS]"))
    backend_thread.daemon = True
    frontend_thread.daemon = True
    scan_thread.daemon = True
    scan_suspicious_thread.daemon = True
    backend_thread.start()
    frontend_thread.start()
    scan_thread.start()
    scan_suspicious_thread.start()

    # Wait loop
    try:
        while True:
            # Check if any process died
            if backend_proc.poll() is not None:
                print("\033[1;31m[-] C2 Backend has exited.\033[0m")
                break
            if frontend_proc.poll() is not None:
                print("\033[1;31m[-] Electron UI has exited.\033[0m")
                break
            if scan_proc.poll() is not None:
                print("\033[1;31m[-] Threat Intel Scan Daemon (Detected) has exited.\033[0m")
                break
            if scan_suspicious_proc.poll() is not None:
                print("\033[1;31m[-] Threat Intel Scan Daemon (Suspicious) has exited.\033[0m")
                break
            time.sleep(1)
    except KeyboardInterrupt:
        print("\033[1;32m\n[+] Received shutdown signal (Ctrl+C). Terminating processes...\033[0m")
    finally:
        # Cross-platform process termination
        for name, proc in [("C2 Backend", backend_proc), ("Electron UI", frontend_proc), ("Scan Detected", scan_proc), ("Scan Suspicious", scan_suspicious_proc)]:
            try:
                if os.name == 'nt':
                    subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)], capture_output=True)
                else:
                    os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                print(f"[+] Terminated {name} successfully.")
            except Exception:
                pass
        sys.exit(0)

if __name__ == "__main__":
    main()
