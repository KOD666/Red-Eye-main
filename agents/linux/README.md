# RedEye Linux Agent Daemon

A lightweight Python client that reports status and polls the RedEye API for instructions.

## File Structure
- `agent.py`: Main python daemon

## Code Skeleton (`agent.py`)

Save the following content to `agent.py` to test local agent communication:

```python
#!/usr/bin/env python3
import time
import socket
import platform
import subprocess
import requests

API_URL = "http://localhost:5000/api"
AGENT_ID = None

def get_sys_info():
    return {
        "hostname": socket.gethostname(),
        "platform": "Linux",
        "os_release": platform.release(),
        "ip_address": socket.gethostbyname(socket.gethostname())
    }

def register():
    global AGENT_ID
    info = get_sys_info()
    try:
        res = requests.post(f"{API_URL}/agents/register", json=info)
        if res.status_code == 200:
            AGENT_ID = res.json().get("id")
            print(f"[+] Agent registered successfully. ID: {AGENT_ID}")
    except Exception as e:
        print(f"[-] Registration failed: {e}")

def heartbeat():
    if not AGENT_ID:
        return
    try:
        requests.post(f"{API_URL}/agents/ping", json={"id": AGENT_ID})
    except Exception as e:
        print(f"[-] Heartbeat failed: {e}")

def check_commands():
    if not AGENT_ID:
        return
    try:
        res = requests.get(f"{API_URL}/agents/{AGENT_ID}/commands/pending")
        if res.status_code == 200:
            commands = res.json()
            for cmd in commands:
                execute_command(cmd)
    except Exception as e:
        print(f"[-] Command fetch failed: {e}")

def execute_command(cmd):
    cmd_id = cmd.get("id")
    cmd_text = cmd.get("command_text")
    print(f"[*] Executing command [{cmd_id}]: {cmd_text}")
    try:
        # Run system command
        proc = subprocess.Popen(cmd_text, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = proc.communicate()
        output = (stdout + stderr).decode('utf-8')
        
        # Report response
        requests.post(f"{API_URL}/commands/{cmd_id}/respond", json={
            "response": output,
            "status": "completed"
        })
    except Exception as e:
        requests.post(f"{API_URL}/commands/{cmd_id}/respond", json={
            "response": str(e),
            "status": "failed"
        })

def main():
    print("[*] Starting RedEye Linux Agent...")
    register()
    while True:
        if not AGENT_ID:
            time.sleep(10)
            register()
            continue
        heartbeat()
        check_commands()
        time.sleep(5)

if __name__ == "__main__":
    main()
```
