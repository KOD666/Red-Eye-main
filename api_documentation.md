# RedEye C2 & EDR Platform — API Documentation (`api_documentation.md`)

This document provides complete technical specifications for the **RedEye C2 & EDR Backend API**. The API powers agent registration, telemetry ingestion, EDR threat scoring, file reputation checks, and remote operator command-and-control operations across **Windows**, **Linux**, and **Android** endpoints.

---

## 1. General Specifications

- **Base URL**: `https://api.desaivraj.site` (Production) / `http://localhost:8000` (Local)
- **Data Format**: `JSON` (`application/json`)
- **Authentication Mechanisms**:
  - **Agent Authentication**: JWT Bearer Token (`Authorization: Bearer <agent_token>`) or `X-Agent-Token` header.
  - **Operator Authentication**: JWT Bearer Token (`Authorization: Bearer <operator_token>`).

---

## 2. Authentication & Authorization

### 2.1 Operator Login
Authenticates an SOC operator or administrator to gain access to C2 management endpoints.

- **Endpoint**: `POST /api/v1/operator/login`
- **Headers**: `Content-Type: application/json`
- **Request Body**:
```json
{
  "username": "admin",
  "password": "your_secure_password"
}
```
- **Response** (`200 OK`):
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "role": "operator"
}
```

---

## 3. Agent Lifecycle & Registration APIs

### 3.1 Register New Agent
Registers a newly installed endpoint agent (Windows, Linux, or Android) with the C2 platform.

- **Endpoints**: 
  - `POST /api/v1/agents/register` (Generic)
  - `POST /api/v1/windows/register` (Windows)
  - `POST /api/v1/linux/register` (Linux)
  - `POST /api/v1/android/register` (Android)
- **Request Body**:
```json
{
  "agent_id": "RE-WIN-89A12B",
  "hostname": "DESKTOP-FINANCE-01",
  "os_release": "Windows 11 Enterprise (23H2)",
  "platform": "Windows",
  "internal_ip": "192.168.1.105",
  "mac_address": "00:1A:2B:3C:4D:5E",
  "agent_version": "1.0.0",
  "reporting_interval": 60
}
```
- **Response** (`201 Created`):
```json
{
  "agent_id": "RE-WIN-89A12B",
  "status": "registered",
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "server_time": "2026-08-16T16:24:28Z"
}
```

---

### 3.2 Obtain Agent Access Token
Exchanges agent registration credentials or refreshes an expired access token.

- **Endpoints**: 
  - `POST /api/v1/agents/token`
  - `POST /api/v1/windows/token`
  - `POST /api/v1/linux/token`
  - `POST /api/v1/android/token`
- **Request Body**:
```json
{
  "agent_id": "RE-WIN-89A12B",
  "secret_key": "optional_pre_shared_secret"
}
```
- **Response** (`200 OK`):
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "expires_in": 86400
}
```

---

### 3.3 Agent Ping & Heartbeat
Periodic heartbeat sent by agents to signal online status and verify active configuration.

- **Endpoints**: 
  - `POST /api/v1/agents/ping`
  - `POST /api/v1/windows/ping` (or `/heartbeat`)
  - `POST /api/v1/linux/ping` (or `/heartbeat`)
  - `POST /api/v1/android/ping` (or `/heartbeat`)
- **Headers**: `Authorization: Bearer <agent_token>`
- **Request Body**:
```json
{
  "agent_id": "RE-WIN-89A12B",
  "status": "online",
  "timestamp": "2026-08-16T16:24:28Z"
}
```
- **Response** (`200 OK`):
```json
{
  "status": "acknowledged",
  "update_available": false,
  "pending_commands_count": 1
}
```

---

### 3.4 Fetch EDR Blocklist Policies
Fetches threat intelligence blocklists, blacklisted process names, and network rules.

- **Endpoints**: 
  - `GET /api/v1/policies`
  - `GET /api/v1/windows/policies`
  - `GET /api/v1/linux/policies`
  - `GET /api/v1/android/policies`
- **Response** (`200 OK`):
```json
{
  "blocklist": ["mimikatz.exe", "xmrig.exe", "netcat", "chisel"],
  "suspicious_paths": ["C:\\Users\\Public\\", "/tmp/."],
  "suspicious_cmdlines": ["-encodedcommand", "downloadstring", "nc -e"],
  "reporting_interval": 30
}
```

---

### 3.5 Download Agent Payload / OTA Update
Download pre-compiled binaries or update packages.

- **Endpoint**: `GET /api/v1/agents/download`
- **Query Parameters**:
  - `format`: `exe`, `binary`, `apk`, `py`
  - `platform_type`: `Windows`, `Linux`, `Android`
- **Response**: Binary stream (`application/octet-stream` or `application/vnd.android.package-archive`).

---

## 4. Telemetry & Threat Detection APIs

### 4.1 Submit Agent Telemetry
Submits process activity, network sockets, login events, USB insertions, and system performance metrics.

- **Endpoints**:
  - `POST /api/v1/telemetry/submit`
  - `POST /api/v1/windows/telemetry/submit`
  - `POST /api/v1/linux/telemetry/submit`
  - `POST /api/v1/android/telemetry/submit`
- **Headers**: `Authorization: Bearer <agent_token>`
- **Request Body**:
```json
{
  "agent_id": "RE-WIN-89A12B",
  "timestamp": "2026-08-16T16:24:28Z",
  "cpu_percent": 12.5,
  "memory_percent": 42.1,
  "processes": [
    {
      "pid": 4824,
      "name": "cmd.exe",
      "user": "DESKTOP-FINANCE-01\\admin",
      "path": "C:\\Windows\\System32\\cmd.exe",
      "cmdline": "cmd.exe /c whoami",
      "threat_score": 0,
      "remote_ip": null
    }
  ],
  "sockets": [
    {
      "protocol": "TCP",
      "local_address": "192.168.1.105:52134",
      "foreign_address": "198.51.100.25:443",
      "state": "ESTABLISHED",
      "pid": 4824
    }
  ],
  "logins": [],
  "usb_events": []
}
```
- **Response** (`200 OK`):
```json
{
  "status": "processed",
  "alerts_generated": 0
}
```

---

### 4.2 File Reputation Check (VirusTotal / MalwareBazaar)
Queries executable file SHA-256 hashes against threat intelligence databases.

- **Endpoints**:
  - `POST /api/v1/windows/file-reputation/check`
  - `POST /api/v1/linux/file-reputation/check`
- **Request Body**:
```json
{
  "sha256": "2545b8925e4193fc132578508e284982a5170d32b575306d1dbb8584852c0020"
}
```
- **Response** (`200 OK`):
```json
{
  "sha256": "2545b8925e4193fc132578508e284982a5170d32b575306d1dbb8584852c0020",
  "threat_label": "Trojan.Generic",
  "vt_detection_rate": "48/72",
  "mb_listed": true,
  "risk_score": 90
}
```

---

### 4.3 Android Package Sync
Syncs installed Android application packages, permissions, and risk classifications.

- **Endpoints**:
  - `POST /api/v1/android/apps/sync`
  - `POST /api/android/apps/sync`
- **Request Body**:
```json
{
  "agent_id": "RE-AND-77B12",
  "apps": [
    {
      "app_name": "Suspicious Utility",
      "package_name": "com.suspicious.app",
      "version_name": "1.0",
      "apk_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "risk_level": "yellow",
      "system_app": false
    }
  ]
}
```
- **Response** (`200 OK`):
```json
{
  "status": "synced",
  "count": 1
}
```

---

## 5. Operator Management & Remote C2 APIs

### 5.1 List All Active Agents
Returns all registered endpoint agents and their latest status telemetry.

- **Endpoint**: `GET /api/v1/operator/agents`
- **Headers**: `Authorization: Bearer <operator_token>`
- **Response** (`200 OK`):
```json
[
  {
    "id": "RE-WIN-89A12B",
    "hostname": "DESKTOP-FINANCE-01",
    "platform": "Windows",
    "os_release": "Windows 11 Enterprise (23H2)",
    "ip_address": "192.168.1.105",
    "status": "online",
    "last_seen": "2026-08-16T16:24:20Z",
    "unread_alerts_count": 0
  }
]
```

---

### 5.2 Get Detailed Agent Telemetry
Retrieves complete historical telemetry, active processes, sockets, and hardware specs for a single agent.

- **Endpoint**: `GET /api/v1/operator/agents/{agent_id}`
- **Headers**: `Authorization: Bearer <operator_token>`
- **Response** (`200 OK`):
```json
{
  "agent": {
    "id": "RE-WIN-89A12B",
    "hostname": "DESKTOP-FINANCE-01",
    "platform": "Windows",
    "status": "online"
  },
  "activity": {
    "processes": [],
    "network": [],
    "logins": [],
    "usb_events": []
  },
  "alerts": []
}
```

---

### 5.3 Queue Remote Command
Schedules a terminal command, PowerShell script, or shell instruction for execution on the target endpoint agent.

- **Endpoint**: `POST /api/v1/operator/agents/{agent_id}/command`
- **Headers**: `Authorization: Bearer <operator_token>`
- **Request Body**:
```json
{
  "command_text": "taskkill /F /PID 4824"
}
```
- **Response** (`201 Created`):
```json
{
  "command_id": "CMD-99412",
  "agent_id": "RE-WIN-89A12B",
  "command_text": "taskkill /F /PID 4824",
  "status": "pending",
  "created_at": "2026-08-16T16:24:28Z"
}
```

---

### 5.4 Poll Pending Commands (Agent Side)
Polled by endpoint agents to retrieve queued instructions.

- **Endpoints**:
  - `GET /api/v1/agents/{agent_id}/commands/pending`
  - `GET /api/v1/windows/agents/{agent_id}/commands/pending`
  - `GET /api/v1/linux/agents/{agent_id}/commands/pending`
  - `GET /api/v1/android/agents/{agent_id}/commands/pending`
- **Response** (`200 OK`):
```json
[
  {
    "command_id": "CMD-99412",
    "command_text": "taskkill /F /PID 4824"
  }
]
```

---

### 5.5 Submit Command Execution Result (Agent Side)
Submits stdout, stderr, or execution status back to the C2 server.

- **Endpoints**:
  - `POST /api/v1/commands/{command_id}/respond`
  - `POST /api/v1/windows/commands/{command_id}/respond`
  - `POST /api/v1/android/commands/{command_id}/respond`
- **Request Body**:
```json
{
  "status": "completed",
  "response_text": "SUCCESS: The process with PID 4824 has been terminated."
}
```
- **Response** (`200 OK`):
```json
{
  "status": "recorded"
}
```

---

### 5.6 Trigger VirusTotal Batch Scan
Triggers background VirusTotal API scanning across all suspicious processes or installed Android packages for an agent.

- **Endpoint**: `POST /api/v1/operator/agents/{agent_id}/vt_batch_scan`
- **Headers**: `Authorization: Bearer <operator_token>`
- **Response** (`200 OK`):
```json
{
  "status": "started",
  "scanned_count": 3
}
```

---

### 5.7 Trigger VirusTotal Rescan by PID
Scans a specific running process by PID using VirusTotal threat intelligence.

- **Endpoint**: `POST /api/v1/operator/agents/{agent_id}/processes/{pid}/vt_rescan`
- **Headers**: `Authorization: Bearer <operator_token>`
- **Response** (`200 OK`):
```json
{
  "pid": 4824,
  "sha256": "2545b8925e4193fc132578508e284982a5170d32b575306d1dbb8584852c0020",
  "vt_rate": "12/72",
  "threat_classification": "Suspicious"
}
```

---

### 5.8 Retrieve Security Alerts Feed
Fetches active EDR alerts, malware detections, and system security events.

- **Endpoints**:
  - `GET /api/v1/operator/alerts`
  - `GET /api/v1/operator/events`
  - `GET /api/v1/operator/system_logs`
- **Response** (`200 OK`):
```json
[
  {
    "id": 101,
    "agent_id": "RE-WIN-89A12B",
    "category": "Process Activity",
    "severity": "CRITICAL",
    "message": "ATTACKER REMOTE IP DETECTED: 198.51.100.25:4444 on PID 4824",
    "timestamp": "2026-08-16T16:24:00Z"
  }
]
```

---

### 5.9 De-register & Purge Agent
Permanently removes an endpoint agent and purges its stored telemetry records.

- **Endpoint**: `DELETE /api/v1/operator/agents/{agent_id}`
- **Headers**: `Authorization: Bearer <operator_token>`
- **Response**: `204 No Content`

---

## 6. HTTP Status Summary Table

| Status Code | Meaning | Usage Scenario |
| :--- | :--- | :--- |
| `200 OK` | Success | Standard successful query or action acknowledgment. |
| `201 Created` | Created | Agent registration or command queue created successfully. |
| `204 No Content` | Deleted | Successful agent deletion or policy removal. |
| `400 Bad Request` | Invalid Input | Missing parameters or invalid JSON schema. |
| `401 Unauthorized` | Auth Failed | Missing or expired JWT Bearer token. |
| `404 Not Found` | Resource Missing | Specified agent ID, process PID, or command ID not found. |
| `500 Server Error` | Database/Internal Error | Internal server or database transaction failure. |
