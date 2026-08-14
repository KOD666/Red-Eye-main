#!/usr/bin/env python3
"""
Red-Eye: Defensive Telemetry and Host Information Agent for Linux
"""

import os
import sys
import time
import socket
import uuid
import platform
import getpass

try:
    import psutil
except ImportError:
    psutil = None

try:
    import requests
except ImportError:
    requests = None

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
except ImportError:
    Observer = None
    FileSystemEventHandler = object

import threading
import glob

FIM_EVENTS = []

# Base URL pointing to the backend (adjust as needed for deployment)
BASE_URL = "http://10.118.111.211:8000"
AGENT_VERSION = "2.0.0"

def get_primary_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        try:
            ip = socket.gethostbyname(socket.gethostname())
        except Exception:
            ip = "127.0.0.1"
    finally:
        s.close()
    return ip

def get_public_ip_info():
    if not requests:
        return {"public_ip": "Unknown", "country": "Unknown", "city": "Unknown"}
    try:
        resp = requests.get("https://ipapi.co/json/", timeout=3)
        if resp.status_code == 200:
            data = resp.json()
            if "ip" in data:
                return {
                    "public_ip": data.get("ip"),
                    "country": data.get("country_name", "Unknown"),
                    "city": data.get("city", "Unknown")
                }
    except Exception:
        pass
    try:
        resp = requests.get("http://ip-api.com/json/", timeout=3)
        if resp.status_code == 200:
            data = resp.json()
            if "query" in data:
                return {
                    "public_ip": data.get("query"),
                    "country": data.get("country", "Unknown"),
                    "city": data.get("city", "Unknown")
                }
    except Exception:
        pass
    return {"public_ip": "Unknown", "country": "Unknown", "city": "Unknown"}

def get_mac_address():
    try:
        mac_num = uuid.getnode()
        mac_str = ":".join(("%012X" % mac_num)[i:i+2] for i in range(0, 12, 2))
        return mac_str
    except Exception:
        return "00:00:00:00:00:00"

def collect_user_activity():
    events = []
    try:
        import subprocess
        # Sudo events
        try:
            out = subprocess.check_output(['journalctl', '-q', '_COMM=sudo', '--since', '2 minutes ago'], stderr=subprocess.STDOUT).decode('utf-8')
            for line in out.strip().split('\n'):
                if 'COMMAND=' in line:
                    user = line.split('sudo:')[1].split(':')[0].strip() if 'sudo:' in line else 'unknown'
                    cmd = line.split('COMMAND=')[1].strip()
                    events.append({
                        "type": "Sudo Execution",
                        "user": user,
                        "source_ip": "127.0.0.1",
                        "event_id": 4648,
                        "details": cmd
                    })
        except Exception:
            pass
            
        # SSH / Failed logins
        try:
            out = subprocess.check_output(['journalctl', '-q', '_SYSTEMD_UNIT=ssh.service', '--since', '2 minutes ago'], stderr=subprocess.STDOUT).decode('utf-8')
            for line in out.strip().split('\n'):
                if 'Failed password' in line:
                    user = line.split('for ')[1].split(' from')[0].strip() if 'for ' in line and ' from' in line else 'unknown'
                    ip = line.split('from ')[1].split(' port')[0].strip() if 'from ' in line and ' port' in line else 'unknown'
                    events.append({
                        "type": "Failed Login",
                        "user": user,
                        "source_ip": ip,
                        "event_id": 4625,
                        "details": "Invalid SSH password"
                    })
                elif 'Accepted password' in line or 'Accepted publickey' in line:
                    user = line.split('for ')[1].split(' from')[0].strip() if 'for ' in line and ' from' in line else 'unknown'
                    ip = line.split('from ')[1].split(' port')[0].strip() if 'from ' in line and ' port' in line else 'unknown'
                    events.append({
                        "type": "Logon Success",
                        "user": user,
                        "source_ip": ip,
                        "event_id": 4624,
                        "details": "SSH Login"
                    })
        except Exception:
            pass
            
    except Exception as e:
        print(f"Error collecting user activity events: {e}")
    return events

INSTALLED_PACKAGES = {}

def collect_packages():
    import subprocess
    pkg_list = []
    try:
        # Get installed packages and versions
        out = subprocess.check_output(['dpkg-query', '-W', "-f=${Package}||${Version}\n"], stderr=subprocess.STDOUT).decode('utf-8')
        lines = out.strip().split('\n')
        
        current_pkgs = {}
        for line in lines:
            if '||' in line:
                name, version = line.split('||', 1)
                current_pkgs[name.strip()] = version.strip()
                
        # Calculate Delta if cache is populated
        if INSTALLED_PACKAGES:
            for pkg, ver in current_pkgs.items():
                if pkg not in INSTALLED_PACKAGES:
                    pkg_list.append({"name": pkg, "version": ver, "status": "Installed"})
                elif INSTALLED_PACKAGES[pkg] != ver:
                    pkg_list.append({"name": pkg, "version": ver, "status": "Updated"})
            for pkg, ver in INSTALLED_PACKAGES.items():
                if pkg not in current_pkgs:
                    pkg_list.append({"name": pkg, "version": ver, "status": "Removed"})
        else:
            # First run, send baseline
            for pkg, ver in current_pkgs.items():
                pkg_list.append({"name": pkg, "version": ver, "status": "Installed"})
        
        # Update cache
        INSTALLED_PACKAGES.clear()
        INSTALLED_PACKAGES.update(current_pkgs)
        
    except Exception as e:
        print(f"Error collecting packages: {e}")
        
    return {
        "installed_applications_count": len(INSTALLED_PACKAGES),
        "software_list": pkg_list
    }

USB_CACHE = {}

def collect_usb_events():
    import subprocess
    import json
    usb_events = []
    try:
        out = subprocess.check_output(['lsblk', '-o', 'NAME,SERIAL,MOUNTPOINT,TYPE,RM', '-J'], stderr=subprocess.STDOUT).decode('utf-8')
        data = json.loads(out)
        
        current_usbs = {}
        for dev in data.get('blockdevices', []):
            # RM == true means removable (USB, etc)
            if dev.get('rm'):
                name = dev.get('name', 'Unknown')
                serial = dev.get('serial') or 'Unknown'
                mount = dev.get('mountpoint') or 'Unmounted'
                current_usbs[name] = {"serial": serial, "mountpoint": mount}
        
        # Check deltas
        if USB_CACHE:
            for name, info in current_usbs.items():
                if name not in USB_CACHE:
                    usb_events.append({
                        "event_type": "inserted",
                        "device_name": name,
                        "serial_number": info["serial"],
                        "device_type": "Removable Storage"
                    })
            for name, info in USB_CACHE.items():
                if name not in current_usbs:
                    usb_events.append({
                        "event_type": "removed",
                        "device_name": name,
                        "serial_number": info["serial"],
                        "device_type": "Removable Storage"
                    })
                    
        # Update cache
        USB_CACHE.clear()
        USB_CACHE.update(current_usbs)
        
    except Exception as e:
        print(f"Error collecting USB events: {e}")
        
    return {
        "connected_usb_devices": usb_events
    }

def get_system_uptime():
    if psutil:
        try:
            return int(time.time() - psutil.boot_time())
        except Exception:
            pass
    try:
        with open("/proc/uptime", "r") as f:
            uptime_seconds = float(f.readline().split()[0])
            return int(uptime_seconds)
    except Exception:
        return 0

def get_cpu_usage():
    if psutil:
        try:
            return float(psutil.cpu_percent(interval=0.1))
        except Exception:
            pass
    return 0.0

def get_ram_usage():
    if psutil:
        try:
            return float(psutil.virtual_memory().percent)
        except Exception:
            pass
    try:
        with open("/proc/meminfo", "r") as f:
            lines = f.readlines()
            mem_total = 0
            mem_available = 0
            for line in lines:
                if line.startswith("MemTotal:"):
                    mem_total = int(line.split()[1])
                elif line.startswith("MemAvailable:"):
                    mem_available = int(line.split()[1])
            if mem_total > 0:
                return round(((mem_total - mem_available) / mem_total) * 100, 2)
    except Exception:
        pass
    return 0.0

def get_disk_usage():
    if psutil:
        try:
            return float(psutil.disk_usage("/").percent)
        except Exception:
            pass
    if hasattr(os, "statvfs"):
        try:
            st = os.statvfs("/")
            free = st.f_bavail * st.f_frsize
            total = st.f_blocks * st.f_frsize
            if total > 0:
                used = total - free
                return round((used / total) * 100, 2)
        except Exception:
            pass
    return 0.0

FILE_HASH_CACHE = {}

def get_file_checksum(file_path):
    import hashlib
    if not file_path or not os.path.exists(file_path):
        return None
    
    if file_path in FILE_HASH_CACHE:
        return FILE_HASH_CACHE[file_path]
        
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        hash_val = sha256_hash.hexdigest()
        FILE_HASH_CACHE[file_path] = hash_val
        return hash_val
    except Exception:
        return None

if Observer:
    class FIMHandler(FileSystemEventHandler):
        def _process_event(self, event, action):
            if event.is_directory:
                return
            
            # Ignore highly spammy cache and temp files
            spam_keywords = ['/.config/google-chrome', '/.config/redeye-frontend/Cache', '/dev/shm/.org.chromium.', '/tmp/#']
            for kw in spam_keywords:
                if kw in event.src_path:
                    return
            
            # Restrict hashing to files < 50MB to save CPU
            file_hash = None
            is_elf = False
            is_executable = False
            file_owner = "Unknown"
            try:
                if action in ["created", "modified"]:
                    if os.path.exists(event.src_path) and os.path.getsize(event.src_path) < 50 * 1024 * 1024:
                        file_hash = get_file_checksum(event.src_path)
                        try:
                            with open(event.src_path, 'rb') as f:
                                is_elf = f.read(4) == b'\x7fELF'
                        except Exception:
                            pass
                        is_executable = os.access(event.src_path, os.X_OK)
                        try:
                            import pwd
                            stat_info = os.stat(event.src_path)
                            file_owner = pwd.getpwuid(stat_info.st_uid).pw_name
                        except Exception:
                            pass
            except Exception:
                pass

            FIM_EVENTS.append({
                "file_path": event.src_path,
                "action": action,
                "hash": file_hash,
                "is_elf": is_elf,
                "is_executable": is_executable,
                "file_owner": file_owner
            })

        def on_created(self, event):
            self._process_event(event, "created")

        def on_modified(self, event):
            self._process_event(event, "modified")

        def on_deleted(self, event):
            self._process_event(event, "deleted")

        def on_moved(self, event):
            self._process_event(event, "renamed")

def start_fim_thread():
    if not Observer:
        print("[!] Watchdog not available, FIM disabled.")
        return
    paths_to_monitor = ['/tmp', '/dev/shm', '/etc', '/usr/bin', '/bin', '/usr/local/bin', '/opt', '/var/spool/cron/crontabs']
    try:
        paths_to_monitor.extend(glob.glob('/home/*/.config'))
        paths_to_monitor.extend(glob.glob('/home/*/.bashrc'))
        paths_to_monitor.extend(glob.glob('/home/*/.profile'))
        if os.path.exists('/root/.bashrc'): paths_to_monitor.append('/root/.bashrc')
        if os.path.exists('/root/.profile'): paths_to_monitor.append('/root/.profile')
    except Exception:
        pass

    observer = Observer()
    handler = FIMHandler()
    
    for path in paths_to_monitor:
        if os.path.exists(path):
            try:
                observer.schedule(handler, path, recursive=True)
            except Exception as e:
                print(f"[!] Error scheduling FIM for {path}: {e}")

    observer.daemon = True
    try:
        observer.start()
        print("[+] FIM watchdog thread started.")
    except Exception as e:
        print(f"[-] FIM failed to start: {e}")

def collect_network_connections():
    network_info = {
        "active_connections_count": 0,
        "listening_ports": [],
        "connections_sample": [],
        "vpn_active": False
    }
    
    if not psutil:
        return network_info
        
    try:
        conns = psutil.net_connections(kind='inet')
        network_info["active_connections_count"] = len(conns)
        
        # Sort connections: prioritize LISTEN, then ESTABLISHED. Drop TIME_WAIT
        valid_conns = []
        for c in conns:
            if c.status == 'TIME_WAIT':
                continue
            if c.status == 'LISTEN':
                valid_conns.insert(0, c)
            elif c.status == 'ESTABLISHED':
                # Insert after LISTEN
                idx = len([x for x in valid_conns if x.status == 'LISTEN'])
                valid_conns.insert(idx, c)
            else:
                valid_conns.append(c)

        for c in valid_conns:
            # Listening ports
            if c.status == 'LISTEN' and c.laddr:
                if c.laddr.port not in network_info["listening_ports"]:
                    network_info["listening_ports"].append(c.laddr.port)
            
            # Connections sample (max 100)
            if len(network_info["connections_sample"]) < 100:
                laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else ""
                raddr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else ""
                
                # Fetch process name
                proc_name = "Unknown"
                if c.pid:
                    try:
                        proc_name = psutil.Process(c.pid).name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                else:
                    # Try to infer for well-known ports if run without root
                    if c.status == 'LISTEN' and c.laddr:
                        if c.laddr.port == 22 or c.laddr.port == 9000: proc_name = "sshd"
                        elif c.laddr.port == 5432: proc_name = "postgres"
                        elif c.laddr.port == 3389: proc_name = "xrdp"
                        elif c.laddr.port == 8000: proc_name = "uvicorn"
                        
                proto = "TCP" if c.type == socket.SOCK_STREAM else "UDP"
                
                network_info["connections_sample"].append({
                    "protocol": proto,
                    "local_address": laddr,
                    "remote_ip": c.raddr.ip if c.raddr else None,
                    "remote_port": c.raddr.port if c.raddr else None,
                    "foreign_address": raddr,
                    "state": c.status,
                    "pid": c.pid,
                    "process_name": proc_name
                })
                
        # Check for vpn interface
        net_if_addrs = psutil.net_if_addrs()
        for interface in net_if_addrs.keys():
            if interface.startswith('tun') or interface.startswith('tap') or interface.startswith('wg'):
                network_info["vpn_active"] = True
                
    except Exception as e:
        print(f"Error collecting network info: {e}")
        
    return network_info
def collect_processes():
    process_list = []
    if psutil:
        try:
            for proc in psutil.process_iter(['pid', 'name', 'username', 'ppid', 'exe', 'cmdline', 'create_time', 'cpu_percent', 'memory_percent']):
                try:
                    pinfo = proc.info
                    name = pinfo.get('name') or "Unknown"
                    pid = pinfo.get('pid', 0)
                    ppid = pinfo.get('ppid')
                    user = pinfo.get('username') or "system"
                    exe = pinfo.get('exe')
                    cmdline = pinfo.get('cmdline')
                    cpu = pinfo.get('cpu_percent') or 0.0
                    mem = pinfo.get('memory_percent') or 0.0
                    
                    if cmdline:
                        cmdline = " ".join(cmdline)
                    else:
                        cmdline = ""
                    create_time = pinfo.get('create_time')
                    if create_time:
                        import datetime
                        start_time = datetime.datetime.fromtimestamp(create_time, datetime.timezone.utc).isoformat()
                    else:
                        start_time = None
                    
                    parent_name = "Unknown"
                    if ppid:
                        try:
                            parent_name = psutil.Process(ppid).name()
                        except Exception:
                            pass
                            
                    sha256_hash = None
                    is_elf = False
                    file_owner = "Unknown"
                    file_creation_time = None
                    if exe and os.path.exists(exe):
                        sha256_hash = get_file_checksum(exe)
                        try:
                            with open(exe, 'rb') as f:
                                is_elf = f.read(4) == b'\x7fELF'
                            if is_elf:
                                import pwd
                                stat_info = os.stat(exe)
                                file_owner = pwd.getpwuid(stat_info.st_uid).pw_name
                                file_creation_time = datetime.datetime.fromtimestamp(stat_info.st_ctime, datetime.timezone.utc).isoformat()
                        except Exception:
                            pass
                    
                    proc_data = {
                        "pid": pid,
                        "name": name,
                        "parent_pid": ppid,
                        "parent_process": parent_name,
                        "user": user,
                        "cpu": round(cpu, 1),
                        "mem": round(mem, 1),
                        "executable_path": exe,
                        "command_line": cmdline,
                        "start_time": start_time,
                        "sha256_hash": sha256_hash,
                        "is_elf": is_elf,
                        "file_owner": file_owner,
                        "file_creation_time": file_creation_time,
                        "action": "baseline"
                    }
                    process_list.append(proc_data)
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass
        except Exception as e:
            print(f"Error enumerating processes: {e}")
            
    return process_list

def collect_system_info():
    os_name = platform.system()
    os_release = platform.release()
    os_ver = platform.version()
    architecture = platform.machine()
    
    hostname = socket.gethostname()
    pub_info = get_public_ip_info()
    
    return {
        "hostname": hostname,
        "username": getpass.getuser(),
        "os_distribution_kernel": f"{os_name} {os_release} ({os_ver})",
        "architecture": architecture,
        "ip_address": get_primary_ip(),
        "mac_address": get_mac_address(),
        "cpu_usage": get_cpu_usage(),
        "ram_usage": get_ram_usage(),
        "disk_usage": get_disk_usage(),
        "uptime": get_system_uptime(),
        "public_ip": pub_info.get("public_ip", "Unknown"),
        "country": pub_info.get("country", "Unknown"),
        "city": pub_info.get("city", "Unknown")
    }

def main():
    global BASE_URL
    if not requests:
        print("Error: 'requests' module is required. Please run: pip install requests")
        sys.exit(1)
        
    print(f"Starting Red-Eye Linux Agent v{AGENT_VERSION}...")

    # Prompt user for C2 Gateway IP
    try:
        user_ip = input(f"[?] Enter Local IP address for C2 Gateway [Press Enter for {BASE_URL.replace('http://', '').replace(':8000', '')}]: ").strip()
        if user_ip:
            if not user_ip.startswith("http"):
                BASE_URL = f"http://{user_ip}:8000" if ":8000" not in user_ip else f"http://{user_ip}"
            else:
                BASE_URL = user_ip
    except (KeyboardInterrupt, EOFError):
        pass

    print(f"[+] Using C2 Gateway: {BASE_URL}")
    
    # Register Agent
    sys_info = collect_system_info()
    register_payload = {
        "hostname": sys_info["hostname"],
        "username": sys_info["username"],
        "os_version": sys_info["os_distribution_kernel"],
        "agent_version": AGENT_VERSION,
        "department": "IT",
        "tags": [
            "Linux", 
            "Server",
            f"mac_address:{sys_info['mac_address']}",
            f"city:{sys_info['city']}",
            f"country:{sys_info['country']}"
        ],
        "group": "Linux Workstations",
        "tenant": "default"
    }
    
    agent_id = None
    token = None
    headers = {}
    
    import json
    import os
    config_file = "agent_config.json"

    try:
        print("Registering with backend...")
        resp = requests.post(f"{BASE_URL}/api/v1/linux/register", json=register_payload, timeout=10)
        resp.raise_for_status()
        auth_data = resp.json()
        agent_id = auth_data["agent_id"]
        token = auth_data["token"]
        print(f"Registered successfully! Agent ID: {agent_id}")
        
        # Save config
        with open(config_file, "w") as f:
            json.dump({"agent_id": agent_id, "token": token}, f)
            
        headers = {"Authorization": f"Bearer {token}"}
    except Exception as e:
        print(f"Failed to register agent: {e}")
        if os.path.exists(config_file):
            print("Loading cached agent configuration...")
            try:
                with open(config_file, "r") as f:
                    cached = json.load(f)
                    agent_id = cached.get("agent_id")
                    token = cached.get("token")
                    if agent_id and token:
                        headers = {"Authorization": f"Bearer {token}"}
                        print(f"Loaded cached Agent ID: {agent_id}")
            except Exception as cache_e:
                print(f"Failed to load cache: {cache_e}")
        
        if not agent_id:
            print("No cached agent ID available. Telemetry will be buffered offline but cannot be submitted until successful registration.")
    
    print("\n--- Gathered System Information ---")
    print(f"Hostname: {sys_info['hostname']}")
    print(f"Username: {sys_info['username']}")
    print(f"OS Distribution & Kernel Version: {sys_info['os_distribution_kernel']}")
    print(f"Architecture: {sys_info['architecture']}")
    print(f"IP Address (Local): {sys_info['ip_address']}")
    print(f"IP Address (Public): {sys_info['public_ip']} ({sys_info['city']}, {sys_info['country']})")
    print(f"MAC Address: {sys_info['mac_address']}")
    print(f"Uptime (seconds): {sys_info['uptime']}")
    print(f"CPU Usage: {sys_info['cpu_usage']}%")
    print(f"RAM Usage: {sys_info['ram_usage']}%")
    print(f"Disk Usage: {sys_info['disk_usage']}%")
    print(f"Agent Version: {AGENT_VERSION}")
    print("-----------------------------------\n")
    
    start_fim_thread()
    
    # Heartbeat loop
    while True:
        try:
            sys_info = collect_system_info()
            
            ping_payload = {
                "agent_id": agent_id,
                "cpu_usage": sys_info["cpu_usage"],
                "ram_usage": sys_info["ram_usage"],
                "status": "online",
                "agent_version": AGENT_VERSION,
                "local_ip": sys_info["ip_address"],
                "public_ip": sys_info["public_ip"],
                "tags": [
                    f"mac_address:{sys_info['mac_address']}",
                    f"city:{sys_info['city']}",
                    f"country:{sys_info['country']}",
                    f"uptime:{sys_info['uptime']}"
                ]
            }
            
            try:
                resp = requests.post(f"{BASE_URL}/api/v1/linux/heartbeat", json=ping_payload, headers=headers, timeout=10)
                resp.raise_for_status()
            except Exception as hb_e:
                print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Heartbeat failed: {hb_e}")
                # We do not raise here, so we can continue to collect telemetry offline
            
            # 1. Telemetry Snapshot
            import datetime
            current_dt = datetime.datetime.now(datetime.timezone.utc).isoformat()
            
            global FIM_EVENTS
            file_events_copy = list(FIM_EVENTS)
            FIM_EVENTS.clear()

            proc_list = collect_processes()
            telemetry_payload = {
                "agent_id": agent_id,
                "timestamp": current_dt,
                "system_info": {
                    "hostname": sys_info["hostname"],
                    "username": sys_info["username"],
                    "os_version": sys_info["os_distribution_kernel"],
                    "ip_address": sys_info["ip_address"],
                    "mac_address": sys_info["mac_address"],
                    "cpu_usage": sys_info["cpu_usage"],
                    "ram_usage": sys_info["ram_usage"],
                    "disk_usage": sys_info["disk_usage"],
                    "uptime": sys_info["uptime"]
                },
                "user_activity": {
                    "recent_audit_events": collect_user_activity(),
                    "last_logged_in_user": sys_info["username"]
                },
                "file_activity": file_events_copy,
                "security_status": {
                    "antivirus_status": "Active",
                    "firewall_status": "Active",
                    "privilege_escalation_warnings": []
                },
                "processes": {
                    "running_processes_count": len(proc_list),
                    "sample_processes": proc_list,
                    "suspicious_processes": []
                },
                "installed_software": collect_packages(),
                "usb_devices": collect_usb_events(),
                "network": collect_network_connections(),
                "threats": {
                    "security_alerts": []
                },
                "exam_integrity": {
                    "violations_found": False,
                    "violations": [],
                    "vpn_enabled": False,
                    "rdp_active": False
                }
            }
            
            try:
                # If we have offline telemetry buffered, try to send it first
                offline_file = "offline_telemetry.json"
                if os.path.exists(offline_file):
                    try:
                        with open(offline_file, "r") as f:
                            offline_data = json.load(f)
                        if isinstance(offline_data, list) and len(offline_data) > 0:
                            print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Attempting to send {len(offline_data)} buffered offline payloads...")
                            success_count = 0
                            for payload in offline_data:
                                # Ensure agent_id is attached if it wasn't during offline collection
                                if payload.get("agent_id") is None and agent_id:
                                    payload["agent_id"] = agent_id
                                if payload.get("agent_id"):
                                    resp_tel = requests.post(f"{BASE_URL}/api/v1/linux/telemetry/submit", json=payload, headers=headers, timeout=15)
                                    resp_tel.raise_for_status()
                                    success_count += 1
                            if success_count == len(offline_data):
                                print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] All offline payloads sent successfully. Clearing buffer.")
                                os.remove(offline_file)
                            else:
                                # Keep the unsent ones
                                with open(offline_file, "w") as f:
                                    json.dump(offline_data[success_count:], f)
                    except Exception as offline_e:
                        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Failed to send offline telemetry: {offline_e}")
                
                if agent_id:
                    resp_tel = requests.post(f"{BASE_URL}/api/v1/linux/telemetry/submit", json=telemetry_payload, headers=headers, timeout=15)
                    if resp_tel.status_code == 422:
                        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Validation Error: {resp_tel.text}")
                    resp_tel.raise_for_status()
                    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Telemetry submitted successfully.")
                else:
                    raise Exception("Agent ID is not available (not registered).")
            except Exception as e:
                print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Failed to submit telemetry: {e}")
                print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Buffering telemetry offline...")
                offline_file = "offline_telemetry.json"
                try:
                    offline_data = []
                    if os.path.exists(offline_file):
                        with open(offline_file, "r") as f:
                            try:
                                offline_data = json.load(f)
                            except:
                                offline_data = []
                    if not isinstance(offline_data, list):
                        offline_data = []
                    offline_data.append(telemetry_payload)
                    with open(offline_file, "w") as f:
                        json.dump(offline_data, f)
                except Exception as buffer_e:
                    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Error buffering telemetry: {buffer_e}")
                
        except Exception as e:
            print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Heartbeat/Collection Error: {e}")
            
        time.sleep(60)

if __name__ == "__main__":
    main()
