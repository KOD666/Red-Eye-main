#!/usr/bin/env python3
"""
Red-Eye: Defensive Telemetry and Host Information Agent
Designed for SOC monitoring and host telemetry reporting.
"""

import os
import sys
import time
import json
import socket
import uuid
import platform
import getpass
import logging
import logging.handlers
import argparse
from datetime import datetime

# Disable SSL CA Bundle file resolution in compiled PyInstaller binaries
os.environ["CURL_CA_BUNDLE"] = ""
os.environ["REQUESTS_CA_BUNDLE"] = ""
os.environ["SSL_CERT_FILE"] = ""

# Optional dependencies with graceful fallback
try:
    import psutil
except ImportError:
    psutil = None

try:
    import requests
    import urllib3
    urllib3.disable_warnings()
except ImportError:
    requests = None


try:
    import win32com.client
except ImportError:
    win32com = None

try:
    import winreg
except ImportError:
    winreg = None

try:
    import win32evtlog
    import win32evtlogutil
    import win32security
except ImportError:
    win32evtlog = None

try:
    import win32service
    import win32serviceutil
    import win32event
    import servicemanager
except ImportError:
    win32service = None
    win32serviceutil = None
    win32event = None
    servicemanager = None


def query_windows_event_log(log_name, event_ids, max_events=50):
    """Queries Windows Event Log using win32evtlog (WinAPI), returning structured event dictionaries."""
    if not win32evtlog:
        return None
    try:
        # Open the event log
        hand = win32evtlog.OpenEventLog(None, log_name)
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        events = []
        count = 0
        
        while count < max_events:
            records = win32evtlog.ReadEventLog(hand, flags, 0)
            if not records:
                break
            for r in records:
                # Mask EventID to get the 16-bit ID
                event_id = r.EventID & 0xFFFF
                if event_id in event_ids:
                    # Parse timestamp
                    try:
                        time_str = r.TimeGenerated.Format('%Y-%m-%dT%H:%M:%SZ')
                    except Exception:
                        time_str = datetime.utcnow().isoformat() + "Z"
                        
                    # Format message using pywin32 utilities or join StringInserts as fallback
                    try:
                        msg = win32evtlogutil.SafeFormatMessage(r, log_name) or ""
                    except Exception:
                        msg = ""
                    if not msg and r.StringInserts:
                        msg = " | ".join(str(s) for s in r.StringInserts)
                        
                    user = "System"
                    if r.Sid:
                        try:
                            # Try to look up account name from SID
                            name, _, _ = win32security.LookupAccountSid(None, r.Sid)
                            user = name
                        except Exception:
                            pass
                    if not user and r.StringInserts:
                        user = r.StringInserts[0]
                        
                    events.append({
                        "event_id": event_id,
                        "time": time_str,
                        "message": msg,
                        "user": user,
                        "xml_data": r.StringInserts if r.StringInserts else []
                    })
                    count += 1
                    if count >= max_events:
                        break
        win32evtlog.CloseEventLog(hand)
        return events
    except Exception:
        return None


def query_wmi(query_str, namespace="root\\cimv2"):
    """Queries WMI in-process using win32com client if available."""
    if not win32com:
        return None
    try:
        import pythoncom
        pythoncom.CoInitialize()
        wmi = win32com.client.GetObject(f"winmgmts:\\\\.\\{namespace}")
        results = wmi.ExecQuery(query_str)
        items = []
        for obj in results:
            item = {}
            for prop in obj.Properties_:
                item[prop.Name] = prop.Value
            items.append(item)
        return items
    except Exception:
        return None


def get_primary_ip():
    """Retrieves the primary local IP address using a dummy UDP connection."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Doesn't need to be reachable, just triggers routing logic
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        # Fallback to hostname resolution or localhost
        try:
            ip = socket.gethostbyname(socket.gethostname())
        except Exception:
            ip = "127.0.0.1"
    finally:
        s.close()
    return ip


def get_mac_address():
    """Retrieves the MAC address of the system."""
    try:
        mac_num = uuid.getnode()
        mac_str = ":".join(("%012X" % mac_num)[i:i+2] for i in range(0, 12, 2))
        return mac_str
    except Exception:
        return "00:00:00:00:00:00"


def get_system_uptime():
    """Retrieves system uptime in seconds."""
    if psutil:
        try:
            return int(time.time() - psutil.boot_time())
        except Exception:
            pass
            
    # Fallback for Linux
    if platform.system() == "Linux":
        try:
            with open("/proc/uptime", "r") as f:
                uptime_seconds = float(f.readline().split()[0])
                return int(uptime_seconds)
        except Exception:
            pass
            
    # Fallback for Windows (using ctypes to call GetTickCount64)
    if platform.system() == "Windows":
        try:
            import ctypes
            lib = ctypes.windll.kernel32
            t = lib.GetTickCount64()
            return int(t / 1000)
        except Exception:
            pass
            
    return 0


def get_cpu_usage():
    """Retrieves current CPU usage percentage."""
    if psutil:
        try:
            return float(psutil.cpu_percent(interval=0.1))
        except Exception:
            pass
    return 0.0


def get_ram_usage():
    """Retrieves current RAM usage percentage."""
    if psutil:
        try:
            return float(psutil.virtual_memory().percent)
        except Exception:
            pass
            
    # Fallback for Linux
    if platform.system() == "Linux":
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
    """Retrieves root/system partition disk usage percentage."""
    if psutil:
        try:
            path = "/" if platform.system() != "Windows" else os.path.splitdrive(os.getcwd())[0] + "\\"
            return float(psutil.disk_usage(path).percent)
        except Exception:
            # Fallback to current dir path
            try:
                return float(psutil.disk_usage(".").percent)
            except Exception:
                pass
                
    # Fallback for Unix-like systems
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


def collect_system_info():
    """Gathers all requested system information."""
    os_name = platform.system()
    os_release = platform.release()
    os_ver = platform.version()
    
    return {
        "hostname": socket.gethostname(),
        "username": getpass.getuser(),
        "os_version": f"{os_name} {os_release} ({os_ver})",
        "ip_address": get_primary_ip(),
        "mac_address": get_mac_address(),
        "cpu_usage": get_cpu_usage(),
        "ram_usage": get_ram_usage(),
        "disk_usage": get_disk_usage(),
        "uptime": get_system_uptime()
    }


def get_linux_logins():
    events = []
    import subprocess
    # Parse last (successful logins)
    try:
        out = subprocess.check_output(["last", "-n", "20", "-F"], stderr=subprocess.DEVNULL).decode()
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 10 and not line.startswith("wtmp") and not line.startswith("reboot"):
                username = parts[0]
                tty = parts[1]
                ip = parts[2]
                if ip == "system" or ip == "boot" or (":" not in parts[3] and "." not in ip):
                    ip = "Local"
                
                if tty.startswith("pts/") or tty.startswith("tty"):
                    event_type = "Logon"
                    if ip != "Local" and ip != "127.0.0.1":
                        event_type = "RDPLogon" if "rdp" in line.lower() else "Logon (SSH)"
                else:
                    event_type = "Logon"
                
                try:
                    time_str = f"{parts[4]} {parts[5]} {parts[7]} {parts[6]}"
                    dt = datetime.strptime(time_str, "%b %d %Y %H:%M:%S")
                    iso_time = dt.isoformat() + "Z"
                except Exception:
                    iso_time = datetime.utcnow().isoformat() + "Z"
                
                events.append({
                    "event_id": 4624,
                    "type": event_type,
                    "time": iso_time,
                    "user": username,
                    "source_ip": ip
                })
    except Exception:
        pass

    # Parse lastb (failed logins)
    try:
        out = subprocess.check_output(["lastb", "-n", "10", "-F"], stderr=subprocess.DEVNULL).decode()
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 10 and not line.startswith("btmp"):
                username = parts[0]
                ip = parts[2]
                if ip == "system" or ip == "boot" or "." not in ip:
                    ip = "Local"
                try:
                    time_str = f"{parts[4]} {parts[5]} {parts[7]} {parts[6]}"
                    dt = datetime.strptime(time_str, "%b %d %Y %H:%M:%S")
                    iso_time = dt.isoformat() + "Z"
                except Exception:
                    iso_time = datetime.utcnow().isoformat() + "Z"
                
                events.append({
                    "event_id": 4625,
                    "type": "FailedLogon",
                    "time": iso_time,
                    "user": username,
                    "source_ip": ip
                })
    except Exception:
        pass
        
    return events


def get_linux_account_changes():
    events = []
    log_files = ["/var/log/auth.log", "/var/log/secure"]
    for log_path in log_files:
        if os.path.exists(log_path) and os.access(log_path, os.R_OK):
            try:
                with open(log_path, "r") as f:
                    lines = f.readlines()[-1000:]
                    for line in lines:
                        if "useradd" in line or "new user" in line:
                            parts = line.split()
                            user = "unknown"
                            for part in parts:
                                if part.startswith("name="):
                                    user = part.split("=")[1].rstrip(",")
                            events.append({
                                "event_id": 4720,
                                "type": "AccountCreated",
                                "time": datetime.utcnow().isoformat() + "Z",
                                "user": user,
                                "source_ip": "Local"
                            })
                        elif "userdel" in line or "delete user" in line:
                            parts = line.split()
                            user = "unknown"
                            for part in parts:
                                if part.startswith("name="):
                                    user = part.split("=")[1].rstrip(",")
                            events.append({
                                "event_id": 4726,
                                "type": "AccountDeleted",
                                "time": datetime.utcnow().isoformat() + "Z",
                                "user": user,
                                "source_ip": "Local"
                            })
            except Exception:
                pass
            break
    return events


def collect_user_activity():
    """Collects system logon events, account administrative actions, and audit clears from event logs."""
    events = []
    
    # 1. Windows Security and System Event Log collection
    if platform.system() == "Windows":
        # 1. Try win32evtlog (in-process, fast)
        api_events = None
        if win32evtlog:
            sec_ids = {4624, 4625, 4634, 4720, 4722, 4724, 4726, 4728, 4732, 4738, 4756, 1102}
            sec_events = query_windows_event_log("Security", sec_ids, 50)
            sys_events = query_windows_event_log("System", {4697}, 10)
            
            all_raw = []
            if sec_events:
                all_raw.extend(sec_events)
            if sys_events:
                all_raw.extend(sys_events)
                
            if all_raw:
                # Sort descending by time
                all_raw.sort(key=lambda x: x["time"], reverse=True)
                api_events = all_raw[:50]
                
        if api_events is not None:
            # Process and format events to match the schema
            for ev in api_events:
                eid = ev["event_id"]
                xml_data = ev["xml_data"]
                
                # Default type/user/ip
                etype = "SecurityEvent"
                user = ev["user"]
                ip = "Local"
                
                # Extract structured fields from StringInserts if possible to match powershell schema
                if eid == 4624 and len(xml_data) > 18:
                    logon_type = str(xml_data[8])
                    if logon_type == "10":
                        etype = "RDPLogon"
                    else:
                        etype = "Logon"
                    user = xml_data[5] or user
                    ip = xml_data[18] or ip
                elif eid == 4625 and len(xml_data) > 19:
                    etype = "FailedLogon"
                    user = xml_data[5] or user
                    ip = xml_data[19] or ip
                elif eid == 4634 and len(xml_data) > 5:
                    etype = "Logoff"
                    user = xml_data[1] or user
                elif eid == 4720 and len(xml_data) > 0:
                    etype = "AccountCreated"
                    user = xml_data[0] or user
                elif eid == 4726 and len(xml_data) > 0:
                    etype = "AccountDeleted"
                    user = xml_data[0] or user
                elif eid == 4722 and len(xml_data) > 0:
                    etype = "AccountEnabled"
                    user = xml_data[0] or user
                elif eid == 4724 and len(xml_data) > 0:
                    etype = "PasswordResetAttempt"
                    user = xml_data[0] or user
                elif eid in [4732, 4728, 4756] and len(xml_data) > 0:
                    etype = "GroupMemberAdded"
                    user = xml_data[0] or user
                elif eid == 4738 and len(xml_data) > 0:
                    etype = "AccountModified"
                    user = xml_data[0] or user
                elif eid == 1102:
                    etype = "AuditLogCleared"
                elif eid == 4697 and len(xml_data) > 6:
                    etype = "ServiceInstalled"
                    user = xml_data[6] or user
                    
                if ip in ["-", "::1", "127.0.0.1"]:
                    ip = "Local"
                    
                events.append({
                    "event_id": eid,
                    "type": etype,
                    "time": ev["time"],
                    "user": user,
                    "source_ip": ip
                })
        else:
            # 2. Fallback to PowerShell
            import subprocess
            ps_cmd = """
            $sec_ids = 4624,4625,4634,4720,4722,4724,4726,4728,4732,4738,4756,1102;
            $events = Get-WinEvent -FilterHashtable @{LogName='Security';ID=$sec_ids} -MaxEvents 50 -ErrorAction SilentlyContinue;
            $sys_events = Get-WinEvent -FilterHashtable @{LogName='System';ID=4697} -MaxEvents 10 -ErrorAction SilentlyContinue;
            
            $all_events = @()
            if ($events) { $all_events += $events }
            if ($sys_events) { $all_events += $sys_events }
            
            if ($all_events) {
                $result = foreach ($ev in $all_events | Sort-Object TimeCreated -Descending | Select-Object -First 50) {
                    try {
                        $xml = [xml]$ev.ToXml();
                        $eventData = @{};
                        if ($xml.Event.EventData.Data) {
                            foreach ($data in $xml.Event.EventData.Data) {
                                if ($data.Name) { $eventData[$data.Name] = $data.'#text' }
                            }
                        }
                        
                        $type = 'SecurityEvent';
                        $user = $eventData['TargetUserName'] ? $eventData['TargetUserName'] : ($eventData['SubjectUserName'] ? $eventData['SubjectUserName'] : 'System');
                        $ip = $eventData['IpAddress'] ? $eventData['IpAddress'] : 'Local';
                        if ($ip -eq '-' -or $ip -eq '::1' -or $ip -eq '127.0.0.1') { $ip = 'Local' }
                        
                        if ($ev.Id -eq 4624) {
                            if ($eventData['LogonType'] -eq '10') { $type = 'RDPLogon' }
                            else { $type = 'Logon' }
                        }
                        elif ($ev.Id -eq 4625) { $type = 'FailedLogon' }
                        elif ($ev.Id -eq 4634) { $type = 'Logoff' }
                        elif ($ev.Id -eq 4720) { $type = 'AccountCreated'; $user = $eventData['TargetUserName'] }
                        elif ($ev.Id -eq 4726) { $type = 'AccountDeleted'; $user = $eventData['TargetUserName'] }
                        elif ($ev.Id -eq 4722) { $type = 'AccountEnabled'; $user = $eventData['TargetUserName'] }
                        elif ($ev.Id -eq 4724) { $type = 'PasswordResetAttempt'; $user = $eventData['TargetUserName'] }
                        elif ($ev.Id -eq 4732 -or $ev.Id -eq 4728 -or $ev.Id -eq 4756) { $type = 'GroupMemberAdded'; $user = $eventData['MemberName'] }
                        elif ($ev.Id -eq 4738) { $type = 'AccountModified'; $user = $eventData['TargetUserName'] }
                        elif ($ev.Id -eq 1102) { $type = 'AuditLogCleared' }
                        elif ($ev.Id -eq 4697) { $type = 'ServiceInstalled'; $user = $eventData['ServiceAccountName'] }
                        
                        [PSCustomObject]@{
                            event_id = $ev.Id;
                            type = $type;
                            time = $ev.TimeCreated.ToString('yyyy-MM-ddTHH:mm:ssZ');
                            user = $user;
                            source_ip = $ip;
                        }
                    } catch {}
                }
                $result | ConvertTo-Json -Compress;
            } else {
                '[]';
            }
            """
            try:
                cmd = ["powershell", "-Command", ps_cmd]
                out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL).decode()
                if out.strip() and out.strip() != "[]":
                    parsed = json.loads(out)
                    if isinstance(parsed, dict):
                        events = [parsed]
                    elif isinstance(parsed, list):
                        events = parsed
            except Exception:
                pass

    # 2. Linux Logins and accounts collection
    else:
        events.extend(get_linux_logins())
        events.extend(get_linux_account_changes())

    if not events:
        events.append({
            "event_id": 4624,
            "type": "Logon",
            "time": datetime.utcnow().isoformat() + "Z",
            "user": getpass.getuser(),
            "source_ip": "Local"
        })
        
    return {
        "recent_audit_events": events,
        "last_logged_in_user": getpass.getuser()
    }


def check_firewall_status():
    """Checks the Windows firewall status and returns 'On', 'Off', or 'Unknown'."""
    if platform.system() != "Windows":
        return "Active (iptables/ufw)"
    import subprocess
    try:
        out = subprocess.check_output("netsh advfirewall show allprofiles state", shell=True, stderr=subprocess.DEVNULL).decode()
        if "OFF" in out and "ON" not in out:
            return "Off"
        elif "ON" in out:
            return "On"
        return "Unknown"
    except Exception:
        return "Unknown"


def check_antivirus_status():
    """Checks Windows Defender and other registered antivirus status using WMI with PowerShell fallback."""
    if platform.system() != "Windows":
        return "Non-Windows Platform"
        
    av_list = []
    
    # 1. Check SecurityCenter2 registered AV products
    wmi_data = query_wmi("SELECT displayName, productState FROM AntiVirusProduct", namespace="root\\SecurityCenter2")
    if wmi_data is not None:
        for av in wmi_data:
            name = av.get("displayName")
            state = av.get("productState")
            status_str = "Active"
            if state is not None:
                try:
                    state_hex = hex(int(state))
                    status_byte = state_hex[-4:-2]
                    if status_byte in ["10", "11"]:
                        status_str = "Active"
                    else:
                        status_str = "Inactive"
                except Exception:
                    pass
            av_list.append(f"{name} ({status_str})")
    else:
        # Fallback to PowerShell
        import subprocess
        try:
            cmd = "powershell -Command \"Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | Select-Object displayName, productState | ConvertTo-Json\""
            out = subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL).decode()
            if out.strip():
                data = json.loads(out)
                if isinstance(data, dict):
                    data = [data]
                for av in data:
                    name = av.get("displayName")
                    state = av.get("productState")
                    status_str = "Active"
                    if state is not None:
                        try:
                            state_hex = hex(int(state))
                            status_byte = state_hex[-4:-2]
                            if status_byte in ["10", "11"]:
                                status_str = "Active"
                            else:
                                status_str = "Inactive"
                        except Exception:
                            pass
                    av_list.append(f"{name} ({status_str})")
        except Exception:
            pass

    # 2. Specifically check Defender status
    defender_wmi = query_wmi("SELECT AMServiceEnabled, RealTimeProtectionEnabled FROM MSFT_MpComputerStatus", namespace="root\\Microsoft\\Windows\\Defender")
    if defender_wmi:
        for defender in defender_wmi:
            rtp = defender.get("RealTimeProtectionEnabled")
            ams = defender.get("AMServiceEnabled")
            status_str = "Active" if (rtp is True or ams is True) else "Inactive"
            if not any("Defender" in av for av in av_list):
                av_list.append(f"Windows Defender ({status_str})")
    else:
        # Fallback to PowerShell
        import subprocess
        try:
            cmd = "powershell -Command \"Get-MpComputerStatus | Select-Object AMServiceEnabled, RealTimeProtectionEnabled | ConvertTo-Json\""
            out = subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL).decode()
            if out.strip():
                defender = json.loads(out)
                rtp = defender.get("RealTimeProtectionEnabled")
                ams = defender.get("AMServiceEnabled")
                status_str = "Active" if (rtp is True or ams is True) else "Inactive"
                if not any("Defender" in av for av in av_list):
                    av_list.append(f"Windows Defender ({status_str})")
        except Exception:
            if not av_list:
                av_list.append("Windows Defender (Active)")
                
    return ", ".join(av_list) if av_list else "None Detected"


def check_defender_events():
    """Checks Microsoft-Windows-Windows Defender/Operational event logs for start/stop/config changes."""
    events = []
    if platform.system() != "Windows":
        return events
        
    # 1. Try win32evtlog (in-process, fast)
    api_events = None
    if win32evtlog:
        api_events = query_windows_event_log("Microsoft-Windows-Windows Defender/Operational", {1151, 5000, 5001, 5007, 5025}, 30)
        
    if api_events is not None:
        for ev in api_events:
            events.append({
                "event_id": ev.get("event_id"),
                "time": ev.get("time"),
                "message": ev.get("message")
            })
    else:
        # 2. Fallback to PowerShell
        import subprocess
        # Query IDs: 1151 (started), 5007 (config changed), 5025 (stopped), 5001 (disabled), 5000 (enabled)
        ps_cmd = """
        $events = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational';ID=1151,5000,5001,5007,5025} -MaxEvents 30 -ErrorAction SilentlyContinue;
        if ($events) {
            $result = foreach ($ev in $events) {
                [PSCustomObject]@{
                    event_id = $ev.Id;
                    time = $ev.TimeCreated.ToString('yyyy-MM-ddTHH:mm:ssZ');
                    message = $ev.Message;
                }
            }
            $result | ConvertTo-Json -Compress;
        } else { '[]' }
        """
        try:
            cmd = ["powershell", "-Command", ps_cmd]
            out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL).decode()
            if out.strip() and out.strip() != "[]":
                data = json.loads(out)
                if isinstance(data, dict):
                    data = [data]
                for ev in data:
                    events.append({
                        "event_id": ev.get("event_id"),
                        "time": ev.get("time"),
                        "message": ev.get("message")
                    })
        except Exception:
            pass
    return events


def collect_security_status():
    """Gathers antivirus and firewall status controls status, including Windows Defender signals."""
    av_status = check_antivirus_status()
    fw_status = check_firewall_status()
    
    warnings = []
    events = check_defender_events()
    for ev in events:
        eid = ev.get("event_id")
        msg = ev.get("message", "")
        # Flag disabled or service stopped conditions
        if eid in [5001, 5025]:
            warnings.append({
                "severity": "CRITICAL",
                "category": "Antivirus Protection Disabled",
                "message": f"Windows Defender was disabled or stopped: {msg}",
                "evidence": f"Event ID: {eid}, Time: {ev.get('time')}"
            })
        elif eid == 5007:
            warnings.append({
                "severity": "WARNING",
                "category": "Antivirus Config Changed",
                "message": f"Windows Defender configuration was modified: {msg}",
                "evidence": f"Event ID: {eid}, Time: {ev.get('time')}"
            })
            
    return {
        "antivirus_status": av_status,
        "firewall_status": fw_status,
        "privilege_escalation_warnings": warnings
    }


def check_windows_process_creation_events():
    """Queries Windows security event log 4688 for new process creation telemetry."""
    events = []
    if platform.system() != "Windows":
        return events
        
    # 1. Try win32evtlog (in-process, fast)
    api_events = None
    if win32evtlog:
        api_events = query_windows_event_log("Security", {4688}, 30)
        
    if api_events is not None:
        for ev in api_events:
            xml_data = ev["xml_data"]
            pid = None
            name = None
            parent_process = None
            user = ev["user"]
            
            if len(xml_data) > 13:
                pid = xml_data[4]
                name = xml_data[5]
                parent_process = xml_data[13]
                user = xml_data[1] or user
                
            events.append({
                "time": ev["time"],
                "pid": pid,
                "name": name,
                "parent_process": parent_process,
                "user": user
            })
    else:
        # 2. Fallback to PowerShell
        import subprocess
        ps_cmd = """
        $events = Get-WinEvent -FilterHashtable @{LogName='Security';ID=4688} -MaxEvents 30 -ErrorAction SilentlyContinue;
        if ($events) {
            $result = foreach ($ev in $events) {
                try {
                    $xml = [xml]$ev.ToXml();
                    $eventData = @{};
                    foreach ($data in $xml.Event.EventData.Data) {
                        if ($data.Name) { $eventData[$data.Name] = $data.'#text' }
                    }
                    [PSCustomObject]@{
                        time = $ev.TimeCreated.ToString('yyyy-MM-ddTHH:mm:ssZ');
                        pid = $eventData['NewProcessId'];
                        name = $eventData['NewProcessName'];
                        parent_process = $eventData['ParentProcessName'];
                        user = $eventData['SubjectUserName'];
                    }
                } catch {}
            }
            $result | ConvertTo-Json -Compress;
        } else { '[]' }
        """
        try:
            cmd = ["powershell", "-Command", ps_cmd]
            out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL).decode()
            if out.strip() and out.strip() != "[]":
                data = json.loads(out)
                if isinstance(data, dict):
                    data = [data]
                for item in data:
                    events.append({
                        "time": item.get("time"),
                        "pid": item.get("pid"),
                        "name": item.get("name"),
                        "parent_process": item.get("parent_process"),
                        "user": item.get("user")
                    })
        except Exception:
            pass
    return events


def collect_processes():
    """Identifies active running processes, extracts executable paths, command lines, SHA256 hashes, remote attacker IPs/ports, and applies EDR risk scoring."""
    global SUSPICIOUS_KEYWORDS
    process_list = []
    suspicious_detected = []

    # Map active network socket connections by PID
    connections_by_pid = {}
    if psutil:
        try:
            for c in psutil.net_connections(kind='inet'):
                if c.pid:
                    connections_by_pid.setdefault(c.pid, []).append(c)
        except Exception:
            pass

    # Expanded threat patterns and malware signatures
    threat_patterns = {
        "mimikatz", "nmap", "wireshark", "netcat", "nc.exe", "hydra", "john", "hashcat", "metasploit",
        "psexec", "vssadmin", "certutil", "bitsadmin", "wmic", "whoami", "nltest", "klist",
        "procdump", "bloodhound", "sharphound", "rubeus", "seatbelt", "chisel", "ngrok", "ligolo",
        "keylogger", "stealer", "trojan", "ransomware", "miner", "xmrig", "covenant", "sliver",
        "cobaltstrike", "meterpreter"
    }
    if SUSPICIOUS_KEYWORDS:
        threat_patterns.update(set(SUSPICIOUS_KEYWORDS))

    cmdline_patterns = [
        "-encodedcommand", "-enc ", "downloadstring", "invoke-expression", "iex(", "iex (",
        "bypass", "-w hidden", "-windowstyle hidden", "vssadmin delete shadows", "bcdedit /set",
        "wbadmin delete", "certutil -urlcache", "bitsadmin /transfer", "sekurlsa", "lsadump",
        "amsiutils", "amsiinitfailed", "reflection.assembly", "net.webclient"
    ]

    suspicious_paths = [
        "\\appdata\\local\\temp\\",
        "\\appdata\\roaming\\",
        "\\users\\public\\",
        "\\windows\\temp\\",
        "\\temp\\",
        "\\downloads\\"
    ]

    if psutil:
        try:
            for proc in psutil.process_iter(['pid', 'name', 'username', 'ppid', 'exe', 'cmdline', 'create_time', 'cpu_percent', 'memory_percent']):
                try:
                    pinfo = proc.info
                    name = pinfo.get('name') or "Unknown"
                    pid = pinfo.get('pid', 0)
                    ppid = pinfo.get('ppid')
                    user = pinfo.get('username') or "system"
                    exe_path = pinfo.get('exe') or ""

                    cmdline_raw = pinfo.get('cmdline')
                    command_line = ""
                    if isinstance(cmdline_raw, list):
                        command_line = " ".join(cmdline_raw)
                    elif isinstance(cmdline_raw, str):
                        command_line = cmdline_raw

                    # Parent process name
                    parent_name = "Unknown"
                    if ppid:
                        try:
                            parent_name = psutil.Process(ppid).name()
                        except Exception:
                            pass

                    # Parse SHA256 checksum if executable exists
                    sha256 = ""
                    if exe_path and os.path.isfile(exe_path):
                        try:
                            sha256 = get_file_checksum(exe_path) or ""
                        except Exception:
                            pass

                    cpu_val = round(pinfo.get('cpu_percent') or 0.0, 1)
                    mem_val = round(pinfo.get('memory_percent') or 0.0, 1)

                    start_time_str = ""
                    ctime = pinfo.get('create_time')
                    if ctime and ctime > 0:
                        try:
                            start_time_str = datetime.fromtimestamp(ctime).strftime('%Y-%m-%d %H:%M:%S')
                        except Exception:
                            pass

                    # Check for Attacker Remote IP and Port from active process connections
                    remote_ip = None
                    remote_port = 0
                    foreign_address = "None"
                    has_active_outbound = False
                    proc_conns = connections_by_pid.get(pid, [])

                    for c in proc_conns:
                        raddr = getattr(c, 'raddr', None)
                        if raddr:
                            rip = getattr(raddr, 'ip', None) or (raddr[0] if isinstance(raddr, tuple) and len(raddr) > 0 else None)
                            rport = getattr(raddr, 'port', None) or (raddr[1] if isinstance(raddr, tuple) and len(raddr) > 1 else 0)
                            if rip and rip not in ("127.0.0.1", "0.0.0.0", "::1", "::"):
                                remote_ip = rip
                                remote_port = rport
                                foreign_address = f"{rip}:{rport}"
                                status = getattr(c, 'status', '')
                                if status in ("ESTABLISHED", "SYN_SENT", "SYN_RECV"):
                                    has_active_outbound = True
                                break

                    # Risk Scoring Engine
                    proc_lower = name.lower()
                    exe_lower = exe_path.lower()
                    cmd_lower = command_line.lower()
                    score = 0
                    reasons = []

                    # System process whitelist check for network connections
                    is_system_trusted = False
                    if exe_lower:
                        trusted_dirs = [
                            "c:\\windows\\system32\\",
                            "c:\\windows\\syswow64\\",
                            "c:\\windows\\systemapps\\",
                            "c:\\windows\\explorer.exe",
                            "c:\\program files\\",
                            "c:\\program files (x86)\\"
                        ]
                        if any(exe_lower.startswith(td) or exe_lower == td for td in trusted_dirs):
                            if proc_lower in ["svchost.exe", "smartscreen.exe", "searchapp.exe", "explorer.exe", "onedrive.exe", "sihost.exe", "taskhostw.exe", "ctfmon.exe", "lsass.exe", "services.exe", "spoolsv.exe"]:
                                is_system_trusted = True

                    # 1. Threat tool / Malware Keyword check (+50)
                    for kw in threat_patterns:
                        if kw in proc_lower or (exe_lower and kw in exe_lower):
                            score += 50
                            reasons.append(f"Threat tool/malware keyword matched: '{kw}'")

                    # 2. Suspicious command line arguments (+40)
                    for pat in cmdline_patterns:
                        if pat in cmd_lower:
                            score += 40
                            reasons.append(f"Suspicious command line argument: '{pat}'")

                    # 3. Untrusted path execution (+30)
                    is_untrusted_path = False
                    for spath in suspicious_paths:
                        if spath in exe_lower and not any(exe_lower.endswith(leg) for leg in ["setup.exe", "installer.exe"]):
                            is_untrusted_path = True
                            score += 30
                            reasons.append(f"Process running from untrusted directory: '{exe_path}'")
                            break

                    # 4. Attacker Remote IP & Socket Connection (+40 to +60)
                    if remote_ip and not is_system_trusted:
                        if is_untrusted_path or score > 0:
                            score += 50
                            reasons.append(f"ATTACKER REMOTE IP DETECTED: {remote_ip}:{remote_port} (Active Outbound Socket Connection)")
                        elif has_active_outbound:
                            score += 30
                            reasons.append(f"Active remote socket connection to {remote_ip}:{remote_port}")

                    # 5. Suspicious Parent-Child Process Chain (+30)
                    office_browsers = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "chrome.exe", "msedge.exe", "firefox.exe"}
                    if parent_name.lower() in office_browsers and (proc_lower in ["powershell.exe", "cmd.exe", "cscript.exe", "wscript.exe", "mshta.exe"]):
                        score += 30
                        reasons.append(f"Suspicious parent-child process execution chain: {parent_name} -> {name}")

                    # Cap score at 100
                    score = min(100, score)

                    if score >= 80:
                        classification = "Critical Malware"
                    elif score >= 60:
                        classification = "High Risk"
                    elif score >= 30:
                        classification = "Suspicious"
                    else:
                        classification = "Safe"

                    proc_data = {
                        "pid": pid,
                        "name": name,
                        "process_name": name,
                        "parent_pid": ppid,
                        "parent_process": parent_name,
                        "user": user,
                        "username": user,
                        "executable_path": exe_path,
                        "path": exe_path,
                        "command_line": command_line,
                        "cmdline": command_line,
                        "sha256_hash": sha256,
                        "hash": sha256,
                        "cpu": cpu_val,
                        "cpu_usage": cpu_val,
                        "mem": mem_val,
                        "ram_usage": mem_val,
                        "start_time": start_time_str,
                        "remote_ip": remote_ip or "N/A",
                        "remote_port": remote_port,
                        "foreign_address": foreign_address,
                        "threat_score": score,
                        "threat_classification": classification,
                        "threat_reasons": reasons,
                        "vt_rate": "0/0",
                        "mb_listed": False
                    }
                    process_list.append(proc_data)

                    if score >= 30 or reasons:
                        suspicious_detected.append({
                            "pid": pid,
                            "name": name,
                            "process_name": name,
                            "parent_pid": ppid,
                            "parent_process": parent_name,
                            "user": user,
                            "executable_path": exe_path,
                            "command_line": command_line,
                            "sha256_hash": sha256,
                            "threat_score": score,
                            "threat_classification": classification,
                            "remote_ip": remote_ip or "N/A",
                            "remote_port": remote_port,
                            "foreign_address": foreign_address,
                            "reason": f"Flagged by EDR threat engine ({classification}): {'; '.join(reasons)}"
                        })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        except Exception:
            pass

    if not process_list:
        process_list = [
            {
                "pid": os.getpid(),
                "name": "Red-Eye",
                "process_name": "Red-Eye",
                "parent_pid": os.getppid(),
                "parent_process": "system",
                "user": getpass.getuser(),
                "username": getpass.getuser(),
                "executable_path": sys.executable,
                "path": sys.executable,
                "command_line": " ".join(sys.argv),
                "cmdline": " ".join(sys.argv),
                "sha256_hash": get_file_checksum(sys.executable) or "",
                "hash": get_file_checksum(sys.executable) or "",
                "cpu": 0.1,
                "cpu_usage": 0.1,
                "mem": 1.0,
                "ram_usage": 1.0,
                "start_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                "remote_ip": "N/A",
                "remote_port": 0,
                "foreign_address": "None",
                "threat_score": 0,
                "threat_classification": "Safe",
                "threat_reasons": [],
                "vt_rate": "0/0",
                "mb_listed": False
            }
        ]

    # 2. Gather Windows event log process creation records (4688)
    creation_events = check_windows_process_creation_events()
    for ev in creation_events:
        name = ev.get("name", "")
        proc_lower = os.path.basename(name).lower()
        base_name = proc_lower[:-4] if proc_lower.endswith(".exe") else proc_lower
        if any(kw in base_name for kw in threat_patterns):
            suspicious_detected.append({
                "pid": ev.get("pid"),
                "name": os.path.basename(name),
                "parent_process": ev.get("parent_process"),
                "executable_path": name,
                "user": ev.get("user"),
                "threat_score": 75,
                "threat_classification": "High Risk",
                "remote_ip": "N/A",
                "remote_port": 0,
                "foreign_address": "None",
                "reason": f"Suspicious new process creation detected: '{name}' by user '{ev.get('user')}'"
            })

    return {
        "running_processes_count": len(process_list),
        "sample_processes": process_list,
        "suspicious_processes": suspicious_detected
    }


def collect_installed_software():
    """Queries installed applications on Windows and detects additions/removals compared to cached state."""
    installed = []
    alerts = []
    
    if platform.system() != "Windows":
        return {
            "installed_applications_count": 0,
            "software_list": [],
            "alerts": []
        }
        
    # 1. Direct registry access via winreg (in-process, fast)
    if winreg:
        paths = [
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Uninstall"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Uninstall")
        ]
        for hive, path in paths:
            try:
                with winreg.OpenKey(hive, path) as key:
                    info = winreg.QueryInfoKey(key)
                    for i in range(info[0]):
                        try:
                            subkey_name = winreg.EnumKey(key, i)
                            with winreg.OpenKey(key, subkey_name) as subkey:
                                try:
                                    name, _ = winreg.QueryValueEx(subkey, "DisplayName")
                                    try:
                                        version, _ = winreg.QueryValueEx(subkey, "DisplayVersion")
                                    except Exception:
                                        version = "Unknown"
                                    if name:
                                        installed.append({"name": name, "version": str(version)})
                                except Exception:
                                    pass
                        except Exception:
                            pass
            except Exception:
                pass
    
    # 2. Fallback to PowerShell if winreg returned nothing or failed
    if not installed:
        import subprocess
        ps_cmd = """
        Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*, HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*, HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName } | Select-Object DisplayName, DisplayVersion | ConvertTo-Json -Compress
        """
        try:
            cmd = ["powershell", "-Command", ps_cmd]
            out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL).decode()
            if out.strip() and out.strip() != "[]":
                data = json.loads(out)
                if isinstance(data, dict):
                    data = [data]
                for item in data:
                    name = item.get("DisplayName")
                    version = item.get("DisplayVersion") or "Unknown"
                    if name:
                        installed.append({"name": name, "version": version})
        except Exception:
            pass

    # Read/Write cached state to detect changes
    state_file = get_state_file_path("redeye_software_state.json")
    previous_software = {}
    
    if os.path.exists(state_file):
        try:
            with open(state_file, "r") as f:
                previous_software = json.load(f)
        except Exception:
            pass

    current_software = {item["name"]: item["version"] for item in installed}
    
    # Save current state for next iteration
    try:
        with open(state_file, "w") as f:
            json.dump(current_software, f, indent=4)
    except Exception:
        pass
        
    # If state file was empty (first run), we do not trigger alerts (just caching the baseline)
    if not previous_software:
        return {
            "installed_applications_count": len(installed),
            "software_list": installed,
            "alerts": []
        }
        
    # Check for new installations
    for name, version in current_software.items():
        if name not in previous_software:
            alerts.append({
                "severity": "WARNING",
                "category": "Software Installed",
                "message": f"New software installed: '{name}' (Version: {version})",
                "evidence": f"Package name: {name}"
            })
            
    # Check for removals
    for name, version in previous_software.items():
        if name not in current_software:
            alerts.append({
                "severity": "WARNING",
                "category": "Software Removed",
                "message": f"Software uninstalled/removed: '{name}' (Version: {version})",
                "evidence": f"Package name: {name}"
            })
            
    return {
        "installed_applications_count": len(installed),
        "software_list": installed,
        "alerts": alerts
    }


def collect_usb_devices():
    """Detects USB storage insertions and removals statefully on Windows, retrieving serial numbers."""
    connected = []
    alerts = []
    
    if platform.system() != "Windows":
        return {
            "connected_usb_devices": [],
            "alerts": []
        }
        
    # 1. Try WMI in-process query (Win32_PnPEntity)
    wmi_devices = query_wmi("SELECT Caption, Name, DeviceID FROM Win32_PnPEntity WHERE Service = 'USBSTOR' OR DeviceID LIKE 'USBSTOR%'")
    if wmi_devices is not None:
        for d in wmi_devices:
            name = d.get("Caption") or d.get("Name") or "Unknown USB Drive"
            device_id = d.get("DeviceID") or ""
            serial = "Unknown Serial"
            if "\\" in device_id:
                serial = device_id.split("\\")[-1]
                if "&" in serial:
                    serial = serial.split("&")[0]
            connected.append({"device_name": name, "serial_number": serial})
    else:
        # 2. Fallback to PowerShell
        import subprocess
        ps_cmd = """
        $devices = Get-CimInstance Win32_PnPEntity | Where-Object { $_.Service -eq 'USBSTOR' -or $_.DeviceID -like 'USBSTOR*' };
        if ($devices) {
            $result = foreach ($d in $devices) {
                $serial = $d.DeviceID.Split('\\\\')[-1];
                if ($serial.Contains('&')) { $serial = $serial.Split('&')[0] }
                [PSCustomObject]@{
                    device_name = $d.Caption ? $d.Caption : $d.Name;
                    serial_number = $serial;
                }
            }
            $result | ConvertTo-Json -Compress;
        } else { '[]' }
        """
        try:
            cmd = ["powershell", "-Command", ps_cmd]
            out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL).decode()
            if out.strip() and out.strip() != "[]":
                data = json.loads(out)
                if isinstance(data, dict):
                    data = [data]
                for item in data:
                    name = item.get("device_name") or "Unknown USB Drive"
                    serial = item.get("serial_number") or "Unknown Serial"
                    connected.append({"device_name": name, "serial_number": serial})
        except Exception:
            pass
        
    # State file for USB tracking
    state_file = get_state_file_path("redeye_usb_state.json")
    first_run = not os.path.exists(state_file)
    previous_usb = {}
    
    if os.path.exists(state_file):
        try:
            with open(state_file, "r") as f:
                previous_usb = json.load(f)
        except Exception:
            pass
            
    current_usb = {item["serial_number"]: item["device_name"] for item in connected}
    
    # Cache current state for next run
    try:
        with open(state_file, "w") as f:
            json.dump(current_usb, f, indent=4)
    except Exception:
        pass
        
    # Baseline caching (skip alerts on first agent launch)
    if first_run:
        return {
            "connected_usb_devices": connected,
            "alerts": []
        }
        
    # Check for insertions
    for serial, name in current_usb.items():
        if serial not in previous_usb:
            alerts.append({
                "severity": "CRITICAL",
                "category": "USB Inserted",
                "message": f"USB Storage Device Inserted: '{name}' (Serial: {serial})",
                "evidence": f"Serial Number: {serial}, Name: {name}"
            })
            
    # Check for removals
    for serial, name in previous_usb.items():
        if serial not in current_usb:
            alerts.append({
                "severity": "WARNING",
                "category": "USB Removed",
                "message": f"USB Storage Device Removed: '{name}' (Serial: {serial})",
                "evidence": f"Serial Number: {serial}, Name: {name}"
            })
            
    return {
        "connected_usb_devices": connected,
        "alerts": alerts
    }


def collect_network_info():
    """Collects network monitoring telemetry: active connections, listening ports, VPN status, and DNS caching logs."""
    connections_sample = []
    listening_ports = []
    active_count = 0
    vpn_active = False
    alerts = []

    # Check for active VPN adapters
    if platform.system() == "Windows":
        vpn_adapters = ["vpn", "tun", "tap", "wireguard", "openvpn", "fortinet", "cisco", "tailscale", "zerotier"]
        # Try psutil first
        if psutil:
            try:
                stats = psutil.net_if_stats()
                for name, stat in stats.items():
                    if stat.isup:
                        name_lower = name.lower()
                        if any(vpn in name_lower for vpn in vpn_adapters):
                            vpn_active = True
                            break
            except Exception:
                pass
        
        # Try WMI as secondary method
        wmi_adapters = None
        if not vpn_active:
            wmi_adapters = query_wmi("SELECT Name, Description FROM Win32_NetworkAdapter WHERE NetEnabled=True")
            if wmi_adapters:
                for adapter in wmi_adapters:
                    name = (adapter.get("Name") or "").lower()
                    desc = (adapter.get("Description") or "").lower()
                    if any(vpn in name or vpn in desc for vpn in vpn_adapters):
                        vpn_active = True
                        break
                        
        # Fallback to PowerShell only if previous methods failed/aren't supported
        if not vpn_active and wmi_adapters is None:
            import subprocess
            try:
                out = subprocess.check_output("powershell -Command \"Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | Select-Object Name, InterfaceDescription | ConvertTo-Json\"", shell=True, stderr=subprocess.DEVNULL).decode()
                if out.strip():
                    data = json.loads(out)
                    if isinstance(data, dict):
                        data = [data]
                    for adapter in data:
                        name = (adapter.get("Name") or "").lower()
                        desc = (adapter.get("InterfaceDescription") or "").lower()
                        if any(vpn in name or vpn in desc for vpn in vpn_adapters):
                            vpn_active = True
                            break
            except Exception:
                pass
    else:
        # Linux /proc/net/dev check or interface list
        if os.path.exists("/sys/class/net"):
            try:
                for iface in os.listdir("/sys/class/net"):
                    if any(x in iface.lower() for x in ["tun", "tap", "vpn", "wg"]):
                        vpn_active = True
                        break
            except Exception:
                pass

    # Process connections via psutil
    if psutil:
        try:
            conns = psutil.net_connections(kind='inet')
            for conn in conns:
                protocol = "TCP" if conn.type == 1 else "UDP"  # SOCK_STREAM=1, SOCK_DGRAM=2
                
                # Format local address
                local_ip = conn.laddr.ip if conn.laddr else "0.0.0.0"
                local_port = conn.laddr.port if conn.laddr else 0
                local_addr_str = f"{local_ip}:{local_port}"
                
                # Format foreign address
                foreign_ip = conn.raddr.ip if conn.raddr else None
                foreign_port = conn.raddr.port if conn.raddr else None
                foreign_addr_str = f"{foreign_ip}:{foreign_port}" if foreign_ip else None
                
                state = conn.status
                
                # Count and sample
                if state == "LISTEN":
                    if local_port not in listening_ports:
                        listening_ports.append(local_port)
                
                # Add to connection list
                if state == "ESTABLISHED":
                    active_count += 1
                
                # Limit connections sample to prevent huge payloads
                if len(connections_sample) < 50:
                    connections_sample.append({
                        "protocol": protocol,
                        "local_address": local_addr_str,
                        "foreign_address": foreign_addr_str,
                        "state": state,
                        "vpn_active": vpn_active
                    })
        except Exception:
            pass

    # Identify harmful listening ports
    system_listening_ports = {135, 137, 138, 139, 445, 5357, 5358}  # Windows RPC/SMB/WSD
    for conn in connections_sample:
        if conn["state"] == "LISTEN":
            try:
                local_parts = conn["local_address"].split(":")
                local_ip = local_parts[0]
                local_port = int(local_parts[1])
                # If listening on all interfaces (exposed) and not standard system ports
                if local_ip in ["0.0.0.0", "::", "[::]"] and local_port not in system_listening_ports and local_port > 1024:
                    alerts.append({
                        "severity": "CRITICAL",
                        "category": "Exposed Listening Port",
                        "message": f"Suspicious network service listening on port {local_port} exposed on all interfaces.",
                        "evidence": f"Address: {conn['local_address']}, Protocol: {conn['protocol']}"
                    })
            except Exception:
                pass

    # DNS Logs: Windows DNS cache collection
    dns_logs = []
    prohibited_dns_keywords = {
        "torrent", "piratebay", "rutracker", "fitgirl", "yts", "uplay", "epicgames",
        "steamcommunity", "roblox", "discordapp", "discord.com", "anydesk", "teamviewer",
        "tunnelbear", "nordvpn", "expressvpn", "protonvpn", "proxy", "bypass", "unblock",
        "ultrasurf", "torproject", "hidemyass", "vpnbook", "windscribe"
    }
    
    if platform.system() == "Windows":
        # 1. Try WMI in-process query (root\StandardCimv2 MSFT_DNSClientCache)
        wmi_dns = query_wmi("SELECT Entry, Name, RecordName, Type, Section FROM MSFT_DNSClientCache", namespace="root\\StandardCimv2")
        if wmi_dns is not None:
            seen_dns = set()
            for item in wmi_dns:
                name = item.get("Entry") or item.get("Name") or item.get("RecordName")
                if name and name not in seen_dns and len(seen_dns) < 30:
                    name_lower = name.lower()
                    if ".local" in name_lower or ".internal" in name_lower:
                        continue
                    seen_dns.add(name)
                    dns_logs.append({
                        "query": name,
                        "type": item.get("Type") or "A",
                        "section": item.get("Section") or "Answer"
                    })
                    
                    # Check if DNS query contains prohibited keywords
                    if any(kw in name_lower for kw in prohibited_dns_keywords):
                        alerts.append({
                            "severity": "WARNING",
                            "category": "Prohibited DNS Resolution",
                            "message": f"Prohibited website domain resolved: '{name}'",
                            "evidence": f"DNS Cache record: {name}"
                        })
        else:
            # 2. Fallback to PowerShell
            try:
                cmd = "powershell -Command \"Get-DnsClientCache | Where-Object { $_.RecordName -and $_.RecordName -notlike '*.local*' -and $_.RecordName -notlike '*.internal*' } | Select-Object RecordName, Type, Section | ConvertTo-Json\""
                out = subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL).decode()
                if out.strip() and out.strip() != "[]":
                    data = json.loads(out)
                    if isinstance(data, dict):
                        data = [data]
                    seen_dns = set()
                    for item in data:
                        name = item.get("RecordName")
                        if name and name not in seen_dns and len(seen_dns) < 30:
                            seen_dns.add(name)
                            dns_logs.append({
                                "query": name,
                                "type": item.get("Type") or "A",
                                "section": item.get("Section") or "Answer"
                            })
                            
                            # Check if DNS query contains prohibited keywords
                            name_lower = name.lower()
                            if any(kw in name_lower for kw in prohibited_dns_keywords):
                                alerts.append({
                                    "severity": "WARNING",
                                    "category": "Prohibited DNS Resolution",
                                    "message": f"Prohibited website domain resolved: '{name}'",
                                    "evidence": f"DNS Cache record: {name}"
                                })
            except Exception:
                pass

    return {
        "active_connections_count": active_count if active_count > 0 else len([c for c in connections_sample if c["state"] == "ESTABLISHED"]),
        "listening_ports": listening_ports,
        "connections_sample": connections_sample,
        "vpn_active": vpn_active,
        "dns_logs": dns_logs,
        "alerts": alerts
    }


def collect_exam_integrity():
    """Returns static empty exam integrity structures to comply with the backend API schemas."""
    return {
        "violations_found": False,
        "violations": [],
        "vpn_enabled": False,
        "rdp_active": False
    }


def get_state_file_path(filename):
    """Resolves state file paths (like software/USB states) based on the operating system."""
    if platform.system() == "Windows":
        prog_data = os.environ.get("ProgramData", "C:\\ProgramData")
        folder = os.path.join(prog_data, "RedEye")
    else:
        home_dir = os.path.expanduser("~")
        folder = os.path.join(home_dir, ".redeye")
    os.makedirs(folder, exist_ok=True)
    return os.path.join(folder, filename)


def get_file_checksum(file_path):
    """Computes the SHA-256 checksum of a file."""
    import hashlib
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception:
        return None


# Agent local logging setup
LOGGER = None

def setup_local_logging():
    """Initializes local rolling file and stream logging for the agent."""
    global LOGGER
    if LOGGER is not None:
        return LOGGER
        
    import platform as plat
    if plat.system() == "Windows":
        prog_data = os.environ.get("ProgramData", "C:\\ProgramData")
        log_dir = os.path.join(prog_data, "RedEye", "logs")
    else:
        home_dir = os.path.expanduser("~")
        log_dir = os.path.join(home_dir, ".redeye", "logs")
        
    os.makedirs(log_dir, exist_ok=True)
    log_path = os.path.join(log_dir, "redeye_agent.log")
    
    LOGGER = logging.getLogger("RedEyeAgent")
    LOGGER.setLevel(logging.INFO)
    LOGGER.propagate = False
    
    # Avoid duplicate handlers if already initialized
    if not LOGGER.handlers:
        # 1. Rotating File Handler (10MB max per file, 5 backup files)
        file_handler = logging.handlers.RotatingFileHandler(
            log_path, maxBytes=10 * 1024 * 1024, backupCount=5
        )
        file_formatter = logging.Formatter(
            "%(asctime)s [%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
        )
        file_handler.setFormatter(file_formatter)
        LOGGER.addHandler(file_handler)
        
        # 2. Console Stream Handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_formatter = logging.Formatter(
            "%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S"
        )
        console_handler.setFormatter(console_formatter)
        LOGGER.addHandler(console_handler)
        
    return LOGGER

def log_info(msg):
    setup_local_logging().info(msg)

def log_warning(msg):
    setup_local_logging().warning(msg)

def log_error(msg):
    setup_local_logging().error(msg)


def get_config_path():
    """Resolves the configuration file path based on permissions and platform."""
    if platform.system() == "Windows":
        prog_data = os.environ.get("ProgramData", "C:\\ProgramData")
        primary = os.path.join(prog_data, "RedEye", "config.json")
        try:
            pdir = os.path.dirname(primary)
            os.makedirs(pdir, exist_ok=True)
            test_file = os.path.join(pdir, ".permtest")
            with open(test_file, "w") as f:
                f.write("1")
            os.remove(test_file)
            return primary
        except Exception:
            local_app = os.environ.get("LOCALAPPDATA", os.path.expanduser("~"))
            return os.path.join(local_app, "RedEye", "config.json")
    else:
        home_dir = os.path.expanduser("~")
        return os.path.join(home_dir, ".redeye", "config.json")


def load_config():
    """Loads stored agent configuration. Returns config dict or generates defaults if missing."""
    config_path = get_config_path()
    default_config = {
        "server_url": "https://api.desaivraj.site",
        "tenant": "default",
        "token": None,
        "report_interval": "60s",
        "version": "1.2.0",
        "policy": [],
        "agent_uuid": None,
        "secret": None
    }
    if not os.path.exists(config_path):
        save_config(default_config)
        return default_config
    try:
        with open(config_path, "r") as f:
            data = json.load(f)
            for k, v in default_config.items():
                if k not in data:
                    data[k] = v
            return data
    except Exception as e:
        log_warning(f"Failed to read config file: {e}")
        return default_config


def save_config(config_dict):
    """Saves agent configuration to persistent config.json storage."""
    config_path = get_config_path()
    try:
        config_dir = os.path.dirname(config_path)
        if not os.path.exists(config_dir):
            os.makedirs(config_dir, exist_ok=True)
        with open(config_path, "w") as f:
            json.dump(config_dict, f, indent=4)
        return True
    except Exception as e:
        log_error(f"Error saving configuration: {e}")
        return False
        log_error(f"Error saving configuration: {e}")
        return False


def load_stored_identity():
    """Loads stored agent identity details from the config file."""
    config = load_config()
    if config.get("agent_uuid") and config.get("secret"):
        return {
            "agent_uuid": config["agent_uuid"],
            "secret": config["secret"],
            "hostname": config.get("hostname", "Unknown")
        }
    return None


def save_stored_identity(agent_uuid, secret, hostname):
    """Saves agent identity details to the config file."""
    config = load_config()
    config["agent_uuid"] = str(agent_uuid)
    config["secret"] = secret
    config["hostname"] = hostname
    return save_config(config)


def get_queue_dir():
    """Resolves the offline queue directory path based on the operating system."""
    if platform.system() == "Windows":
        prog_data = os.environ.get("ProgramData", "C:\\ProgramData")
        return os.path.join(prog_data, "RedEye", "queue")
    else:
        # Fallback for Linux / macOS testing
        home_dir = os.path.expanduser("~")
        return os.path.join(home_dir, ".redeye", "queue")


def queue_telemetry_payload(payload):
    """Saves a telemetry payload to the offline queue directory."""
    queue_dir = get_queue_dir()
    try:
        if not os.path.exists(queue_dir):
            os.makedirs(queue_dir, exist_ok=True)
        # Name file with nanosecond timestamp to ensure uniqueness and chronological order
        filename = f"telemetry_{time.time_ns()}.json"
        file_path = os.path.join(queue_dir, filename)
        with open(file_path, "w") as f:
            json.dump(payload, f, indent=4)
        print(f"[+] Saved telemetry payload to offline queue: {file_path}")
        return True
    except Exception as e:
        print(f"[-] Error saving telemetry payload to offline queue: {e}", file=sys.stderr)
        return False


def process_offline_queue(api_url, agent_id, token, secret):
    """Attempts to upload all queued telemetry payloads in chronological order."""
    global NEXT_RETRY_TIME
    if not requests:
        return token
    if time.time() < NEXT_RETRY_TIME:
        return token
        
    queue_dir = get_queue_dir()
    if not os.path.exists(queue_dir):
        return token
        
    try:
        # Find all JSON telemetry files in the queue dir
        files = sorted([f for f in os.listdir(queue_dir) if f.startswith("telemetry_") and f.endswith(".json")])
        if not files:
            return token
            
        log_info(f"[*] Found {len(files)} queued telemetry payloads. Attempting to upload...")
        url = f"{api_url.rstrip('/')}/api/v1/telemetry/submit"
        
        for filename in files:
            file_path = os.path.join(queue_dir, filename)
            try:
                with open(file_path, "r") as f:
                    payload = json.load(f)
                    
                # Ensure the payload has the current agent's ID
                payload["agent_id"] = agent_id
                
                import gzip
                json_data = json.dumps(payload).encode('utf-8')
                compressed_data = gzip.compress(json_data)
                
                headers = {
                    "Authorization": f"Bearer {token}",
                    "Content-Encoding": "gzip",
                    "Content-Type": "application/json"
                }
                response = requests.post(url, data=compressed_data, headers=headers, timeout=10, verify=False)
                
                if response.status_code == 401:
                    log_warning("[!] Unauthorized (401) during queue upload. Refreshing token...")
                    new_token = refresh_agent_token(api_url, agent_id, secret)
                    if new_token:
                        token = new_token
                        headers["Authorization"] = f"Bearer {token}"
                        # Retry with the refreshed token
                        response = requests.post(url, data=compressed_data, headers=headers, timeout=10, verify=False)
                    else:
                        log_error("[-] Token refresh failed during queue upload. Continuing with current session...")
                        return token
                        
                if response.status_code == 200:
                    log_info(f"[+] Successfully uploaded queued payload: {filename}")
                    handle_network_success()
                    try:
                        os.remove(file_path)
                    except Exception:
                        pass
                elif response.status_code in (401, 403):
                    log_error(f"[-] Upload authorization rejected for {filename}: {response.text}")
                    return token
                elif response.status_code >= 500:
                    log_error(f"[-] Server error during queue upload of {filename} ({response.status_code}): {response.text}")
                    handle_network_failure()
                    # Stop processing to preserve chronological order
                    break
                else:
                    log_error(f"[-] Failed to upload queued payload {filename} ({response.status_code}): {response.text}")
                    # Stop processing to preserve chronological order
                    break
            except Exception as e:
                log_error(f"[-] Connection error during offline queue upload of {filename}: {e}. Pausing queue processing.")
                handle_network_failure()
                break
    except Exception as e:
        log_error(f"[-] Error reading queue directory: {e}")
        
    return token


def register_agent(api_url, info, tenant="default"):
    """Enrolls the agent with the RedEye server."""
    global NEXT_RETRY_TIME
    if not requests:
        print("[-] Error: 'requests' library is not installed. Cannot register with the server.", file=sys.stderr)
        return None
    if time.time() < NEXT_RETRY_TIME:
        return None
        
    url = f"{api_url.rstrip('/')}/api/v1/agents/register"
    payload = {
        "hostname": info["hostname"],
        "username": info["username"],
        "os_version": info["os_version"],
        "agent_version": "2.0.0",
        "department": "Security Operations",
        "tags": ["Red-Eye", platform.system()],
        "group": "Monitoring",
        "tenant": tenant
    }
    
    try:
        response = requests.post(url, json=payload, timeout=5, verify=False)
        if response.status_code == 201:
            data = response.json()
            agent_id = data.get("agent_id")
            secret = data.get("secret")
            token = data.get("token")
            print(f"[+] Agent enrolled successfully. ID: {agent_id}")
            handle_network_success()
            return agent_id, secret, token
        elif response.status_code >= 500:
            log_error(f"[-] Registration server error ({response.status_code}): {response.text}")
            handle_network_failure()
        else:
            log_error(f"[-] Registration rejected by server ({response.status_code}): {response.text}")
    except Exception as e:
        log_error(f"[-] Failed to connect to server for registration: {e}")
        handle_network_failure()
        
    return None


def refresh_agent_token(api_url, agent_id, secret):
    """Retrieves a new JWT access token from the server."""
    global NEXT_RETRY_TIME
    if not requests:
        return None
    if time.time() < NEXT_RETRY_TIME:
        return None
        
    url = f"{api_url.rstrip('/')}/api/v1/agents/token"
    payload = {
        "agent_id": agent_id,
        "secret": secret
    }
    try:
        response = requests.post(url, json=payload, timeout=5, verify=False)
        if response.status_code == 200:
            data = response.json()
            handle_network_success()
            return data.get("token")
        elif response.status_code >= 500:
            log_error(f"[-] Token refresh server error ({response.status_code}): {response.text}")
            handle_network_failure()
        else:
            log_error(f"[-] Token refresh rejected by server ({response.status_code}): {response.text}")
    except Exception as e:
        log_error(f"[-] Failed to connect to server for token refresh: {e}")
        handle_network_failure()
    return None


def trigger_auto_update(api_url, token, update_url, expected_checksum=None):
    """Downloads updated agent script from the server, verifies checksum, updates local file, and restarts."""
    log_info("[*] Version mismatch or integrity violation detected. Auto-update available!")
    if update_url.startswith("/"):
        full_url = f"{api_url.rstrip('/')}{update_url}"
    else:
        full_url = update_url
    headers = {"Authorization": f"Bearer {token}"}
    try:
        log_info(f"[*] Downloading update from {full_url}...")
        response = requests.get(full_url, headers=headers, timeout=15, verify=False)
        if response.status_code == 200:
            import hashlib
            sha256_hash = hashlib.sha256(response.content)
            downloaded_checksum = sha256_hash.hexdigest()
            
            if expected_checksum and downloaded_checksum != expected_checksum:
                log_error(f"[-] Auto-update aborted: downloaded file checksum mismatch. Expected: {expected_checksum}, Got: {downloaded_checksum}")
                return
                
            script_path = os.path.abspath(sys.argv[0])
            log_info(f"[*] Saving updated agent to {script_path}...")
            if script_path.lower().endswith(".exe"):
                old_path = script_path + ".old"
                temp_path = script_path + ".new"
                with open(temp_path, "wb") as f:
                    f.write(response.content)
                if os.path.exists(old_path):
                    try:
                        os.remove(old_path)
                    except Exception:
                        pass
                os.rename(script_path, old_path)
                os.rename(temp_path, script_path)
                log_info("[+] Update completed successfully. Launching updated binary...")
                import subprocess
                subprocess.Popen([script_path] + sys.argv[1:])
                sys.exit(0)
            else:
                with open(script_path, "wb") as f:
                    f.write(response.content)
                log_info("[+] Update completed successfully. Restarting agent...")
                os.execv(sys.executable, [sys.executable] + sys.argv)
        else:
            log_error(f"[-] Failed to download update: HTTP {response.status_code}")
    except Exception as e:
        log_error(f"[-] Error during auto-update process: {e}")


def send_heartbeat(api_url, agent_id, token, info, version="2.0.0"):
    """Sends periodic heartbeats/pings to the server."""
    global NEXT_RETRY_TIME
    if not requests:
        return False
    if time.time() < NEXT_RETRY_TIME:
        return False
        
    running_path = os.path.abspath(sys.argv[0])
    checksum = get_file_checksum(running_path)
    
    url = f"{api_url.rstrip('/')}/api/v1/agents/ping"
    headers = {"Authorization": f"Bearer {token}"}
    payload = {
        "agent_id": agent_id,
        "cpu_usage": info["cpu_usage"],
        "ram_usage": info["ram_usage"],
        "status": "online",
        "agent_version": version,
        "checksum": checksum
    }
    
    try:
        response = requests.post(url, json=payload, headers=headers, timeout=5, verify=False)
        if response.status_code == 401:
            raise requests.exceptions.HTTPError("Unauthorized", response=response)
        if response.status_code == 200:
            handle_network_success()
            return True
        elif response.status_code >= 500:
            handle_network_failure()
            return False
        return False
    except requests.exceptions.HTTPError:
        raise
    except Exception as e:
        print(f"[-] Heartbeat connection error: {e}", file=sys.stderr)
        handle_network_failure()
        return False


# Dynamic SOC Policy rule configurations
SUSPICIOUS_KEYWORDS = {
    "steam", "epicgames", "gta", "minecraft", "valorant", "fifa", "pubg", "fortnite",
    "chrome_canvas", "uplay", "origin", "discord", "skype", "teamviewer", "anydesk", 
    "wireshark", "nmap", "utorrent", "bittorrent", "qbittorrent", "leagueoflegends",
    "cheatengine", "obs64", "obs", "overwatch", "roblox", "csgo", "apexlegends"
}


def fetch_policy(api_url, token):
    """Retrieves EDR detection configuration policy from the server."""
    global NEXT_RETRY_TIME, SUSPICIOUS_KEYWORDS
    if not requests:
        return
    if time.time() < NEXT_RETRY_TIME:
        return
        
    url = f"{api_url.rstrip('/')}/api/v1/policies"
    headers = {"Authorization": f"Bearer {token}"}
    try:
        response = requests.get(url, headers=headers, timeout=5, verify=False)
        if response.status_code == 200:
            data = response.json()
            keywords = data.get("suspicious_keywords", [])
            if keywords:
                SUSPICIOUS_KEYWORDS = set(keywords)
                print(f"[+] EDR policy updated successfully: {len(SUSPICIOUS_KEYWORDS)} keywords loaded.")
                try:
                    config = load_config()
                    config["policy"] = list(SUSPICIOUS_KEYWORDS)
                    save_config(config)
                except Exception:
                    pass
            handle_network_success()
        elif response.status_code >= 500:
            print(f"[-] Policy server error ({response.status_code}): {response.text}", file=sys.stderr)
            handle_network_failure()
    except Exception as e:
        print(f"[-] Failed to fetch SOC detection policy: {e}", file=sys.stderr)
        handle_network_failure()


def check_and_execute_commands(api_url, agent_id, token):
    """Polls the server for pending commands, executes them, and posts responses."""
    if not requests:
        return
    url = f"{api_url.rstrip('/')}/api/v1/agents/{agent_id}/commands/pending"
    headers = {"Authorization": f"Bearer {token}"}
    try:
        response = requests.get(url, headers=headers, timeout=5, verify=False)
        if response.status_code == 200:
            commands = response.json()
            if not commands:
                return
                
            import subprocess
            for cmd in commands:
                cmd_id = cmd.get("id")
                cmd_text = cmd.get("command_text")
                log_info(f"[*] Received command execution request: '{cmd_text}' (ID: {cmd_id})")
                
                try:
                    res = subprocess.run(cmd_text, shell=True, capture_output=True, text=True, timeout=10)
                    stdout = res.stdout if res.stdout else ""
                    stderr = res.stderr if res.stderr else ""
                    output = stdout + stderr
                    status = "completed" if res.returncode == 0 else "failed"
                    if not output.strip():
                        output = f"Command exited with return code {res.returncode} (no output)"
                except subprocess.TimeoutExpired:
                    output = "Error: Command execution timed out after 10 seconds."
                    status = "failed"
                except Exception as e:
                    output = f"Error: Command execution failed to launch: {e}"
                    status = "failed"
                    
                respond_url = f"{api_url.rstrip('/')}/api/v1/commands/{cmd_id}/respond"
                payload = {
                    "response_text": output,
                    "status": status
                }
                resp = requests.post(respond_url, json=payload, headers=headers, timeout=5, verify=False)
                if resp.status_code == 200:
                    log_info(f"[+] Successfully returned command output for command ID: {cmd_id}")
                else:
                    log_error(f"[-] Failed to submit command response: HTTP {resp.status_code}")
        elif response.status_code == 401:
            log_warning("[!] Unauthorized command polling. Refreshing token next cycle.")
    except Exception as e:
        log_error(f"[-] Connection error during command polling: {e}")


CURRENT_BACKOFF = 0
NEXT_RETRY_TIME = 0.0


def handle_network_failure():
    global CURRENT_BACKOFF, NEXT_RETRY_TIME
    if CURRENT_BACKOFF == 0:
        CURRENT_BACKOFF = 60
    else:
        CURRENT_BACKOFF = min(CURRENT_BACKOFF * 2, 960)
    NEXT_RETRY_TIME = time.time() + CURRENT_BACKOFF
    print(f"[-] Network operation failed. Backing off for {CURRENT_BACKOFF} seconds.")


def handle_network_success():
    global CURRENT_BACKOFF, NEXT_RETRY_TIME
    CURRENT_BACKOFF = 0
    NEXT_RETRY_TIME = 0.0


CACHED_SOFTWARE_DATA = None
LAST_SOFTWARE_COLLECTION_TIME = 0.0

PREVIOUSLY_SENT_SOFTWARE = None
PREVIOUSLY_SENT_PROCESSES = None
PREVIOUSLY_SENT_USB = None
PREVIOUSLY_SENT_NETWORK = None


def reset_telemetry_state():
    """Resets previously sent telemetry states and retry variables (used in tests)."""
    global PREVIOUSLY_SENT_SOFTWARE, PREVIOUSLY_SENT_PROCESSES, PREVIOUSLY_SENT_USB, PREVIOUSLY_SENT_NETWORK
    global CACHED_SOFTWARE_DATA, LAST_SOFTWARE_COLLECTION_TIME
    global CURRENT_BACKOFF, NEXT_RETRY_TIME
    PREVIOUSLY_SENT_SOFTWARE = None
    PREVIOUSLY_SENT_PROCESSES = None
    PREVIOUSLY_SENT_USB = None
    PREVIOUSLY_SENT_NETWORK = None
    CACHED_SOFTWARE_DATA = None
    LAST_SOFTWARE_COLLECTION_TIME = 0.0
    CURRENT_BACKOFF = 0
    NEXT_RETRY_TIME = 0.0
    config_path = get_config_path()
    if os.path.exists(config_path):
        try:
            os.remove(config_path)
        except Exception:
            pass


def submit_telemetry(api_url, agent_id, token):
    """Submits the complete telemetry payload to the server."""
    global NEXT_RETRY_TIME
    if not requests:
        return False
    if time.time() < NEXT_RETRY_TIME:
        return False
        
    url = f"{api_url.rstrip('/')}/api/v1/telemetry/submit"
    headers = {"Authorization": f"Bearer {token}"}
    
    sys_info = collect_system_info()
    user_act = collect_user_activity()
    sec_status = collect_security_status()
    proc_data = collect_processes()
    
    global CACHED_SOFTWARE_DATA, LAST_SOFTWARE_COLLECTION_TIME
    current_time = time.time()
    if CACHED_SOFTWARE_DATA is None or (current_time - LAST_SOFTWARE_COLLECTION_TIME >= 3600.0):
        sw_data = collect_installed_software()
        CACHED_SOFTWARE_DATA = sw_data
        LAST_SOFTWARE_COLLECTION_TIME = current_time
    else:
        sw_data = CACHED_SOFTWARE_DATA
    usb_data = collect_usb_devices()
    net_data = collect_network_info()
    
    # --- Compute Incremental Diffs ---
    global PREVIOUSLY_SENT_SOFTWARE
    current_software_list = sw_data.get("software_list", [])
    current_sw_set = {(item["name"], item["version"]) for item in current_software_list}
    if PREVIOUSLY_SENT_SOFTWARE is None:
        software_payload_list = [
            {"name": name, "version": version, "action": "baseline"}
            for name, version in current_sw_set
        ]
        PREVIOUSLY_SENT_SOFTWARE = current_sw_set
    else:
        added_sw = current_sw_set - PREVIOUSLY_SENT_SOFTWARE
        removed_sw = PREVIOUSLY_SENT_SOFTWARE - current_sw_set
        software_payload_list = []
        for name, version in added_sw:
            software_payload_list.append({"name": name, "version": version, "action": "added"})
        for name, version in removed_sw:
            software_payload_list.append({"name": name, "version": version, "action": "removed"})
        PREVIOUSLY_SENT_SOFTWARE = current_sw_set

    global PREVIOUSLY_SENT_PROCESSES
    current_processes = proc_data.get("sample_processes", [])
    current_proc_dict = {p["pid"]: p for p in current_processes}
    if PREVIOUSLY_SENT_PROCESSES is None:
        processes_payload_list = []
        for pid, p in current_proc_dict.items():
            p_copy = p.copy()
            p_copy["action"] = "baseline"
            processes_payload_list.append(p_copy)
        PREVIOUSLY_SENT_PROCESSES = {pid: (p["name"], p.get("user")) for pid, p in current_proc_dict.items()}
    else:
        processes_payload_list = []
        for pid, p in current_proc_dict.items():
            if pid not in PREVIOUSLY_SENT_PROCESSES:
                p_copy = p.copy()
                p_copy["action"] = "started"
                processes_payload_list.append(p_copy)
            else:
                prev_name, prev_user = PREVIOUSLY_SENT_PROCESSES[pid]
                if p["name"] != prev_name or p.get("user") != prev_user:
                    processes_payload_list.append({
                        "pid": pid,
                        "name": prev_name,
                        "user": prev_user,
                        "action": "terminated"
                    })
                    p_copy = p.copy()
                    p_copy["action"] = "started"
                    processes_payload_list.append(p_copy)
        for pid, (name, user) in PREVIOUSLY_SENT_PROCESSES.items():
            if pid not in current_proc_dict:
                processes_payload_list.append({
                    "pid": pid,
                    "name": name,
                    "user": user,
                    "action": "terminated"
                })
        PREVIOUSLY_SENT_PROCESSES = {pid: (p["name"], p.get("user")) for pid, p in current_proc_dict.items()}

    global PREVIOUSLY_SENT_USB
    current_usb_list = usb_data.get("connected_usb_devices", [])
    current_usb_set = {(item["device_name"], item["serial_number"]) for item in current_usb_list}
    if PREVIOUSLY_SENT_USB is None:
        usb_payload_list = [
            {"device_name": name, "serial_number": serial, "action": "baseline"}
            for name, serial in current_usb_set
        ]
        PREVIOUSLY_SENT_USB = current_usb_set
    else:
        added_usb = current_usb_set - PREVIOUSLY_SENT_USB
        removed_usb = PREVIOUSLY_SENT_USB - current_usb_set
        usb_payload_list = []
        for name, serial in added_usb:
            usb_payload_list.append({"device_name": name, "serial_number": serial, "action": "inserted"})
        for name, serial in removed_usb:
            usb_payload_list.append({"device_name": name, "serial_number": serial, "action": "removed"})
        PREVIOUSLY_SENT_USB = current_usb_set

    global PREVIOUSLY_SENT_NETWORK
    current_net_list = net_data.get("connections_sample", [])
    current_net_set = {
        (item["protocol"], item["local_address"], item.get("foreign_address"), item.get("state"), item.get("vpn_active", False))
        for item in current_net_list
    }
    if PREVIOUSLY_SENT_NETWORK is None:
        net_payload_list = []
        for item in current_net_list:
            item_copy = item.copy()
            item_copy["action"] = "baseline"
            net_payload_list.append(item_copy)
        PREVIOUSLY_SENT_NETWORK = current_net_set
    else:
        added_net = current_net_set - PREVIOUSLY_SENT_NETWORK
        removed_net = PREVIOUSLY_SENT_NETWORK - current_net_set
        net_payload_list = []
        for proto, local, foreign, state, vpn in added_net:
            net_payload_list.append({
                "protocol": proto,
                "local_address": local,
                "foreign_address": foreign,
                "state": state,
                "vpn_active": vpn,
                "action": "opened"
            })
        for proto, local, foreign, state, vpn in removed_net:
            net_payload_list.append({
                "protocol": proto,
                "local_address": local,
                "foreign_address": foreign,
                "state": state,
                "vpn_active": vpn,
                "action": "closed"
            })
        PREVIOUSLY_SENT_NETWORK = current_net_set

    # Generate threat alerts for status anomalies
    alerts = []
    
    # 1. Add Defender event warnings
    for warn in sec_status.get("privilege_escalation_warnings", []):
        alerts.append({
            "severity": warn["severity"],
            "category": warn["category"],
            "message": warn["message"],
            "evidence": warn["evidence"]
        })
        
    # 2. Check if AV is disabled/inactive
    av = sec_status.get("antivirus_status", "")
    if "Inactive" in av or "None" in av:
        alerts.append({
            "severity": "CRITICAL",
            "category": "Antivirus Protection Inactive",
            "message": f"Antivirus protection is inactive: {av}",
            "evidence": f"Current status: {av}"
        })
        
    # 3. Check if firewall is Off
    fw = sec_status.get("firewall_status", "")
    if fw == "Off":
        alerts.append({
            "severity": "WARNING",
            "category": "Firewall Disabled",
            "message": "Local Windows firewall profile(s) are turned off.",
            "evidence": f"Current status: {fw}"
        })

    # 4. Check for suspicious processes / games detected
    for susp in proc_data.get("suspicious_processes", []):
        alerts.append({
            "severity": "CRITICAL",
            "category": "Suspicious Process",
            "message": susp["reason"],
            "evidence": f"PID: {susp.get('pid')}, Parent: {susp.get('parent_process')}"
        })

    # 5. Add Software Installation / Removal alerts
    for sw_alert in sw_data.get("alerts", []):
        alerts.append({
            "severity": sw_alert["severity"],
            "category": sw_alert["category"],
            "message": sw_alert["message"],
            "evidence": sw_alert["evidence"]
        })

    # 6. Add USB Insertion / Removal alerts
    for usb_alert in usb_data.get("alerts", []):
        alerts.append({
            "severity": usb_alert["severity"],
            "category": usb_alert["category"],
            "message": usb_alert["message"],
            "evidence": usb_alert["evidence"]
        })

    # 7. Add Network security alerts
    for net_alert in net_data.get("alerts", []):
        alerts.append({
            "severity": net_alert["severity"],
            "category": net_alert["category"],
            "message": net_alert["message"],
            "evidence": net_alert["evidence"]
        })
    
    payload = {
        "agent_id": agent_id,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "system_info": sys_info,
        "user_activity": user_act,
        "security_status": sec_status,
        "processes": {
            "running_processes_count": proc_data["running_processes_count"],
            "sample_processes": processes_payload_list,
            "suspicious_processes": proc_data["suspicious_processes"]
        },
        "installed_software": {
            "installed_applications_count": sw_data["installed_applications_count"],
            "software_list": software_payload_list
        },
        "usb_devices": {
            "connected_usb_devices": usb_payload_list
        },
        "network": {
            "active_connections_count": net_data["active_connections_count"],
            "listening_ports": net_data["listening_ports"],
            "connections_sample": net_payload_list,
            "vpn_active": net_data["vpn_active"]
        },
        "threats": {
            "security_alerts": alerts
        },
        "exam_integrity": collect_exam_integrity()
    }
    
    try:
        import gzip
        json_data = json.dumps(payload).encode('utf-8')
        compressed_data = gzip.compress(json_data)
        
        headers["Content-Encoding"] = "gzip"
        headers["Content-Type"] = "application/json"
        
        response = requests.post(url, data=compressed_data, headers=headers, timeout=10)
        if response.status_code == 401:
            raise requests.exceptions.HTTPError("Unauthorized", response=response)
        if response.status_code == 200:
            data = response.json()
            log_info(f"Telemetry sent successfully. Processed events count: {data.get('processed_records', 0)}")
            handle_network_success()
            return True
        elif response.status_code >= 500:
            log_error(f"Telemetry server error ({response.status_code}): {response.text}")
            queue_telemetry_payload(payload)
            handle_network_failure()
            return False
        else:
            log_error(f"Telemetry rejected by server ({response.status_code}): {response.text}")
            queue_telemetry_payload(payload)
            return False
    except requests.exceptions.HTTPError as e:
        if e.response is not None and e.response.status_code >= 500:
            handle_network_failure()
        raise
    except Exception as e:
        log_error(f"Telemetry connection error: {e}. Queuing payload...")
        queue_telemetry_payload(payload)
        handle_network_failure()
        return False


def parse_interval(interval_str):
    """Parses interval string (e.g. '60s', '5m', '10m', '120') into seconds."""
    s = str(interval_str).lower().strip()
    if s.isdigit():
        return int(s)
    
    if s.endswith('s'):
        try:
            return int(s[:-1])
        except ValueError:
            pass
    elif s.endswith('m'):
        try:
            return int(s[:-1]) * 60
        except ValueError:
            pass
    elif s.endswith('h'):
        try:
            return int(s[:-1]) * 3600
        except ValueError:
            pass
            
    print(f"[!] Warning: Could not parse interval '{interval_str}', defaulting to 60 seconds.")
    return 60


def run_daemon(api_url, interval):
    """Runs the agent in background reporting/daemon mode."""
    config = load_config()
    config["server_url"] = api_url
        
    if interval != 60 or not config.get("report_interval"):
        config["report_interval"] = f"{interval}s"
    else:
        interval = parse_interval(config.get("report_interval", "60s"))
        
    config["version"] = "2.0.0"
    save_config(config)
    
    log_info(f"Starting Red-Eye Daemon mode. Target server: {api_url}")
    log_info(f"Reporting interval: {interval} seconds")
    
    agent_id = config.get("agent_uuid")
    secret = config.get("secret")
    token = config.get("token")
    tenant = config.get("tenant", "default")
    version = config.get("version", "2.0.0")
    
    if config.get("policy"):
        global SUSPICIOUS_KEYWORDS
        SUSPICIOUS_KEYWORDS = set(config["policy"])
        log_info(f"Loaded EDR blocklist policy containing {len(SUSPICIOUS_KEYWORDS)} keywords from configuration.")
    
    # Attempt to load persistent identity on startup
    try:
        info = collect_system_info()
        stored = load_stored_identity()
        if stored and stored.get("hostname") == info.get("hostname"):
            log_info(f"Loaded persistent identity. ID: {stored['agent_uuid']}")
            agent_id = stored["agent_uuid"]
            secret = stored["secret"]
            refreshed_token = refresh_agent_token(api_url, agent_id, secret)
            if refreshed_token:
                token = refreshed_token
                log_info("Successfully authenticated using saved identity.")
                config["token"] = token
                save_config(config)
                fetch_policy(api_url, token)
            else:
                print("[!] Stored identity was rejected or server unreachable. Resetting credentials.")
                agent_id = None
                secret = None
                token = None
    except Exception as e:
        print(f"[!] Warning: Identity initialization failed: {e}", file=sys.stderr)
    
    last_heartbeat_time = 0.0
    last_telemetry_time = 0.0
    last_process_check_time = 0.0
    last_policy_fetch_time = time.time()
    
    # Store running PIDs from last check to detect changes
    previous_pids = set()
    
    # Tick interval is 5 seconds to support real-time process monitoring and exact heartbeat/telemetry timings
    tick_interval = 5.0
    
    while True:
        try:
            current_time = time.time()
            
            # Register if not registered yet
            if not agent_id or not secret or not token:
                info = collect_system_info()
                if agent_id and secret and not token:
                    print("[*] Token is missing/expired, attempting refresh...")
                    token = refresh_agent_token(api_url, agent_id, secret)
                    if token:
                        config["token"] = token
                        save_config(config)
                        continue
                        
                if not agent_id or not secret or not token:
                    reg_result = register_agent(api_url, info, tenant)
                    if not reg_result:
                        wait_time = max(10, int(NEXT_RETRY_TIME - time.time())) if NEXT_RETRY_TIME > time.time() else 10
                        log_warning(f"Registration/Authentication failed, retrying in {wait_time} seconds...")
                        time.sleep(wait_time)
                        continue
                    agent_id, secret, token = reg_result
                    
                    config["agent_uuid"] = str(agent_id)
                    config["secret"] = secret
                    config["token"] = token
                    save_config(config)
                    
                    # Fetch dynamic EDR policy
                    fetch_policy(api_url, token)
                
                # Reset timers on fresh registration
                last_heartbeat_time = 0.0
                last_telemetry_time = 0.0
                last_process_check_time = 0.0
                last_policy_fetch_time = current_time
                previous_pids = set()
            
            # Process offline queue first
            new_token = process_offline_queue(api_url, agent_id, token, secret)
            if not new_token:
                log_warning("Resetting registration due to queue upload authorization failure.")
                config_path = get_config_path()
                if os.path.exists(config_path):
                    try:
                        os.remove(config_path)
                    except Exception:
                        pass
                agent_id = None
                secret = None
                token = None
                config["token"] = None
                config["agent_uuid"] = None
                config["secret"] = None
                save_config(config)
                continue
            elif new_token != token:
                token = new_token
                config["token"] = token
                save_config(config)
            
            # Fetch policy periodically (every 10 minutes)
            if current_time - last_policy_fetch_time >= 600.0:
                fetch_policy(api_url, token)
                last_policy_fetch_time = current_time
            
            # Poll and execute pending commands at each tick
            check_and_execute_commands(api_url, agent_id, token)
            
            # Real-time process check (every 5 seconds)
            trigger_telemetry = False
            if current_time - last_process_check_time >= tick_interval:
                last_process_check_time = current_time
                proc_data = collect_processes()
                current_pids = {p["pid"] for p in proc_data.get("sample_processes", [])}
                
                # Detect new process creations
                if previous_pids:
                    new_pids = current_pids - previous_pids
                    if new_pids:
                        log_info(f"Real-time detection: {len(new_pids)} new process(es) started.")
                        trigger_telemetry = True
                
                # Detect any suspicious processes
                if proc_data.get("suspicious_processes"):
                    trigger_telemetry = True
                    
                previous_pids = current_pids
                
            # Send heartbeat if 30 seconds have elapsed (or CLI specified interval if smaller)
            heartbeat_interval = min(30.0, float(interval))
            if current_time - last_heartbeat_time >= heartbeat_interval:
                try:
                    info = collect_system_info()
                    if send_heartbeat(api_url, agent_id, token, info, version):
                        last_heartbeat_time = current_time
                except requests.exceptions.HTTPError as e:
                    if e.response is not None and e.response.status_code == 401:
                        token = None
                        config["token"] = None
                        save_config(config)
                        continue
                    else:
                        raise
            
            # Send telemetry if specified interval has elapsed (default: 5 mins / 300s), or if triggered by process change
            telemetry_interval = float(interval) if float(interval) > 30.0 else 300.0
            if trigger_telemetry or (current_time - last_telemetry_time >= telemetry_interval):
                try:
                    if submit_telemetry(api_url, agent_id, token):
                        last_telemetry_time = current_time
                except requests.exceptions.HTTPError as e:
                    if e.response is not None and e.response.status_code == 401:
                        token = None
                        config["token"] = None
                        save_config(config)
                        continue
                    else:
                        raise
                        
        except KeyboardInterrupt:
            log_info("Exiting Red-Eye daemon mode.")
            break
        except Exception as e:
            log_error(f"Unexpected error in main loop: {e}")
            
        time.sleep(tick_interval)


class RedEyeAgentService:
    pass

if win32serviceutil:
    class RedEyeAgentService(win32serviceutil.ServiceFramework):
        _svc_name_ = "RedEyeAgent"
        _svc_display_name_ = "RedEye Telemetry Agent"
        _svc_description_ = "Collects system information and sends telemetry updates to RedEye SOC Gateway."

        def __init__(self, args):
            win32serviceutil.ServiceFramework.__init__(self, args)
            self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
            self.is_running = True

        def SvcStop(self):
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            win32event.SetEvent(self.hWaitStop)
            self.is_running = False

        def SvcDoRun(self):
            servicemanager.LogMsg(
                servicemanager.EVENTLOG_INFORMATION_TYPE,
                servicemanager.PYS_SERVICE_STARTED,
                (self._svc_name_, "")
            )
            self.main()

        def main(self):
            config = load_config()
            api_url = config.get("server_url", "https://api.desaivraj.site")
            interval = parse_interval(config.get("report_interval", "60s"))
            
            # Sub-run logic resembling run_daemon but check event state periodically
            agent_id = config.get("agent_uuid")
            secret = config.get("secret")
            token = config.get("token")
            tenant = config.get("tenant", "default")
            version = config.get("version", "2.0.0")
            
            if config.get("policy"):
                global SUSPICIOUS_KEYWORDS
                SUSPICIOUS_KEYWORDS = set(config["policy"])

            # Attempt startup loading of persistent identity
            try:
                info = collect_system_info()
                stored = load_stored_identity()
                if stored and stored.get("hostname") == info.get("hostname"):
                    agent_id = stored["agent_uuid"]
                    secret = stored["secret"]
                    refreshed_token = refresh_agent_token(api_url, agent_id, secret)
                    if refreshed_token:
                        token = refreshed_token
                        config["token"] = token
                        save_config(config)
            except Exception:
                pass

            last_heartbeat_time = 0.0
            last_telemetry_time = 0.0
            last_process_check_time = 0.0
            last_policy_fetch_time = time.time()
            tick_interval = 5.0
            previous_pids = set()

            while self.is_running:
                # Check win32 stop signal
                rc = win32event.WaitForSingleObject(self.hWaitStop, int(tick_interval * 1000))
                if rc == win32event.WAIT_OBJECT_0:
                    break
                    
                try:
                    current_time = time.time()
                    if not agent_id or not secret or not token:
                        info = collect_system_info()
                        if agent_id and secret and not token:
                            new_t = refresh_agent_token(api_url, agent_id, secret)
                            if new_t:
                                token = new_t
                                config["token"] = token
                                save_config(config)
                                continue
                        if not agent_id or not secret or not token:
                            reg_result = register_agent(api_url, info, tenant)
                            if not reg_result:
                                wait_sec = max(10, int(NEXT_RETRY_TIME - time.time())) if NEXT_RETRY_TIME > time.time() else 10
                                # Custom wait loop checking stop signal
                                for _ in range(wait_sec):
                                    if not self.is_running:
                                        break
                                    time.sleep(1)
                                continue
                            agent_id, secret, token = reg_result
                            config["agent_uuid"] = str(agent_id)
                            config["secret"] = secret
                            config["token"] = token
                            save_config(config)
                            fetch_policy(api_url, token)

                        last_heartbeat_time = 0.0
                        last_telemetry_time = 0.0
                        last_process_check_time = 0.0
                        last_policy_fetch_time = current_time
                        previous_pids = set()

                    new_token = process_offline_queue(api_url, agent_id, token, secret)
                    if not new_token:
                        config_path = get_config_path()
                        if os.path.exists(config_path):
                            try: os.remove(config_path)
                            except Exception: pass
                        agent_id, secret, token = None, None, None
                        config["token"], config["agent_uuid"], config["secret"] = None, None, None
                        save_config(config)
                        continue
                    elif new_token != token:
                        token = new_token
                        config["token"] = token
                        save_config(config)

                    if current_time - last_policy_fetch_time >= 600.0:
                        fetch_policy(api_url, token)
                        last_policy_fetch_time = current_time

                    trigger_telemetry = False
                    if current_time - last_process_check_time >= tick_interval:
                        last_process_check_time = current_time
                        proc_data = collect_processes()
                        current_pids = {p["pid"] for p in proc_data.get("sample_processes", [])}
                        if previous_pids:
                            new_pids = current_pids - previous_pids
                            if new_pids:
                                trigger_telemetry = True
                        if proc_data.get("suspicious_processes"):
                            trigger_telemetry = True
                        previous_pids = current_pids

                    heartbeat_interval = min(30.0, float(interval))
                    if current_time - last_heartbeat_time >= heartbeat_interval:
                        try:
                            info = collect_system_info()
                            if send_heartbeat(api_url, agent_id, token, info, version):
                                last_heartbeat_time = current_time
                        except requests.exceptions.HTTPError as e:
                            if e.response is not None and e.response.status_code == 401:
                                token = None
                                config["token"] = None
                                save_config(config)
                                continue

                    telemetry_interval = float(interval) if float(interval) > 30.0 else 300.0
                    if trigger_telemetry or (current_time - last_telemetry_time >= telemetry_interval):
                        try:
                            if submit_telemetry(api_url, agent_id, token):
                                last_telemetry_time = current_time
                        except requests.exceptions.HTTPError as e:
                            if e.response is not None and e.response.status_code == 401:
                                token = None
                                config["token"] = None
                                save_config(config)
                                continue
                except Exception as e:
                    log_warning(f"Service loop warning: {e}")


def run_win_service_installer(action):
    """Handles Windows Service installer operations and configures failure recovery & autostart."""
    if not win32serviceutil:
        print("[-] Windows service modules (pywin32) not installed on this node.", file=sys.stderr)
        return False
        
    try:
        if action == "install":
            print("[*] Installing RedEye Telemetry Agent Windows Service...")
            # Set up command args so that pywin32 installs with automatic startup type
            sys.argv = [sys.argv[0], "--startup", "auto", "install"]
            win32serviceutil.HandleCommandLine(RedEyeAgentService)
            
            # Configure service recovery options using built-in sc command
            import subprocess
            cmd = "sc failure RedEyeAgent reset= 86400 actions= restart/60000/restart/60000/restart/60000"
            print(f"[*] Configuring failure recovery actions: {cmd}")
            subprocess.run(cmd, shell=True, capture_output=True)
            print("[+] Service successfully installed and recovery actions configured.")
            return True
            
        elif action == "start":
            print("[*] Starting RedEye Telemetry Agent Windows Service...")
            sys.argv = [sys.argv[0], "start"]
            win32serviceutil.HandleCommandLine(RedEyeAgentService)
            return True
            
        elif action == "stop":
            print("[*] Stopping RedEye Telemetry Agent Windows Service...")
            sys.argv = [sys.argv[0], "stop"]
            win32serviceutil.HandleCommandLine(RedEyeAgentService)
            return True
            
        elif action == "remove":
            print("[*] Removing RedEye Telemetry Agent Windows Service...")
            sys.argv = [sys.argv[0], "remove"]
            win32serviceutil.HandleCommandLine(RedEyeAgentService)
            return True
            
    except Exception as e:
        print(f"[-] Service installer action '{action}' failed: {e}", file=sys.stderr)
        return False


def main():
    parser = argparse.ArgumentParser(description="Red-Eye: Defensive Telemetry Agent")
    parser.add_argument(
        "-d", "--daemon", 
        action="store_true", 
        help="Run in daemon mode reporting to RedEye API gateway"
    )
    parser.add_argument(
        "-s", "--server", 
        default="https://api.desaivraj.site", 
        help="RedEye Gateway API Server URL (default: https://api.desaivraj.site)"
    )
    parser.add_argument(
        "-i", "--interval", 
        type=str, 
        default="60s", 
        help="Report interval (e.g. 60, 60s, 5m, 10m. Default: 60s)"
    )
    parser.add_argument(
        "--install",
        action="store_true",
        help="Install the agent as a Windows Service"
    )
    parser.add_argument(
        "--start",
        action="store_true",
        help="Start the installed Windows Service"
    )
    parser.add_argument(
        "--stop",
        action="store_true",
        help="Stop the running Windows Service"
    )
    parser.add_argument(
        "--remove",
        action="store_true",
        help="Remove the installed Windows Service"
    )
    
    # Check if running as administrator on Windows; if not, request elevation.
    if platform.system() == "Windows":
        import ctypes
        try:
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
        except Exception:
            is_admin = False
            
        if not is_admin:
            # Re-run the program with admin rights
            # sys.executable is the python interpreter, or the compiled exe path itself
            script_path = sys.argv[0]
            # When packaged with pyinstaller, sys.frozen is True
            is_frozen = getattr(sys, 'frozen', False)
            if is_frozen:
                executable = sys.executable
                params = " ".join(sys.argv[1:])
            else:
                executable = sys.executable
                params = " ".join([f'"{script_path}"'] + sys.argv[1:])
                
            try:
                # 3 is SW_SHOWDEFAULT
                ctypes.windll.shell32.ShellExecuteW(None, "runas", executable, params, None, 3)
            except Exception:
                pass
            sys.exit(0)

    # Check if run by the Windows Service Control Manager or running as a service
    if win32serviceutil:
        if len(sys.argv) > 1 and sys.argv[1] in ["install", "start", "stop", "remove", "restart"]:
            win32serviceutil.HandleCommandLine(RedEyeAgentService)
            return
        elif len(sys.argv) == 1:
            try:
                servicemanager.Initialize()
                servicemanager.PrepareToHostSingle(RedEyeAgentService)
                servicemanager.StartServiceCtrlDispatcher()
                return
            except Exception:
                # Not running as a service (e.g. interactive shell execution), fall back to normal CLI
                pass

    args = parser.parse_args()
    
    interval_seconds = parse_interval(args.interval)
    server_url = args.server

    # Ensure config reflects current server_url
    config = load_config()
    if config.get("server_url") != server_url:
        config["server_url"] = server_url
        save_config(config)
    
    # Handle explicit service requests
    if args.install:
        run_win_service_installer("install")
        return
    elif args.start:
        run_win_service_installer("start")
        return
    elif args.stop:
        run_win_service_installer("stop")
        return
    elif args.remove:
        run_win_service_installer("remove")
        return
        
    # Default: Run daemon mode to establish live C2 connection & stream telemetry
    run_daemon(server_url, interval_seconds)


if __name__ == "__main__":
    main()
