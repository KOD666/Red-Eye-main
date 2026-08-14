# RedEye Agent & Stager Compiler Specifications

## 1. Overview
This document summarizes the changes made to the RedEye C2 Agents, Server Endpoints, and Frontend Executable interface.

---

## 2. Agent Modifications

### Windows Agent (`agents/windows/Red-Eye.py` & `agents/windows/Red-Eye-new.py`)
- **Default Server URL**: Set default C2 server URL to `https://api.desaivraj.site`.
- **Interactive Prompt Removed**: Removed the CLI `input()` prompt asking for IP address.
- **Config Initialization**: Updated `main()` to save `server_url` into `C:\ProgramData\RedEye\config.json` before executing `--install` or `--start`.

### Linux Agent (`agents/linux/agent.py` & `agents/linux/install.sh`)
- **Default Server URL**: Set `BASE_URL = "https://api.desaivraj.site"`.
- **Automated One-Liner**: Script hosted at `https://api.desaivraj.site/agents/linux/install.sh`.

### Android Agent (`agents/android/RedEye.apk`)
- Static route mounted on C2 backend for direct `.apk` binary downloads at `https://api.desaivraj.site/agents/android/RedEye.apk`.

---

## 3. Frontend & Electron EXE Features (`frontend-exe/frontend` & `frontend`)

1. **Automatic Download & File Saving**:
   - **Windows**: Downloads `Red-Eye-new.exe` from `https://api.desaivraj.site/api/v1/operator/agent/download?format=exe&platform_type=Windows`.
   - **Linux**: Downloads `redeye-agent` binary from `http://api.desaivraj.site/agents/linux/redeye-agent`.
   - **Android**: Downloads `RedEye.apk` from `https://api.desaivraj.site/agents/android/RedEye.apk`.

2. **Console Instructions**:
   - On selecting target OS and submitting, a green success box renders in the dashboard:
     - **Windows**:
       ```bash
       Agent is successfully downloaded.
       so now open terminal on agent install Path and run commands:
       Red-Eye-new.exe --install
       Red-Eye-new.exe --start
       ```
     - **Linux**:
       ```bash
       Agent is successfully downloaded.
       so now open terminal on agent install Path and run commands:
       chmod +x redeye-agent
       ./redeye-agent
       ```
     - **Android**:
       ```bash
       Agent is successfully downloaded.
       Transfer RedEye.apk to target Android device and tap to install.
       ```
