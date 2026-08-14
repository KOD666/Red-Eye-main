from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime
from uuid import UUID

# --- Registration Models ---
class AgentRegisterRequest(BaseModel):
    hostname: str = Field(..., example="HR-PC-01")
    username: str = Field(..., example="vraj")
    os_version: str = Field(..., example="Windows 11 Home")
    agent_version: str = Field(..., example="1.2.0")
    department: Optional[str] = Field(None, example="HR")
    tags: Optional[List[str]] = Field(default_factory=list, example=["Critical", "Office"])
    group: Optional[str] = Field("Workstations", example="Workstations")
    tenant: Optional[str] = Field("default", example="default")

class AgentRegisterResponse(BaseModel):
    agent_id: UUID
    secret: str
    token: str
    registration_status: str

# --- Token Authentication Models ---
class AgentTokenRequest(BaseModel):
    agent_id: UUID
    secret: str

class AgentTokenResponse(BaseModel):
    token: str
    token_type: str = "bearer"

# --- Heartbeat Models ---
class AgentPingRequest(BaseModel):
    agent_id: UUID
    cpu_usage: float = Field(..., ge=0.0, le=100.0)
    ram_usage: float = Field(..., ge=0.0, le=100.0)
    status: str = Field("online", example="online")
    agent_version: Optional[str] = None
    checksum: Optional[str] = None
    local_ip: Optional[str] = None
    public_ip: Optional[str] = None
    tags: Optional[List[str]] = None

class AgentPingResponse(BaseModel):
    status: str
    timestamp: datetime
    latest_version: Optional[str] = None
    update_available: Optional[bool] = None
    update_url: Optional[str] = None
    expected_checksum: Optional[str] = None
    needs_app_sync: Optional[bool] = None

# --- Telemetry Subschemas ---
class SystemInfoSchema(BaseModel):
    hostname: str
    username: str
    os_version: str
    ip_address: str
    mac_address: str
    cpu_usage: float
    ram_usage: float
    disk_usage: float
    uptime: int

class UserActivitySchema(BaseModel):
    recent_audit_events: List[Dict[str, Any]]
    last_logged_in_user: str

class SecurityStatusSchema(BaseModel):
    antivirus_status: str
    firewall_status: str
    privilege_escalation_warnings: List[Dict[str, Any]]

class ProcessesSchema(BaseModel):
    running_processes_count: int
    sample_processes: List[Dict[str, Any]]
    suspicious_processes: List[Dict[str, Any]]

class SoftwareSchema(BaseModel):
    installed_applications_count: int
    software_list: List[Dict[str, Any]]

class USBSchema(BaseModel):
    connected_usb_devices: List[Dict[str, Any]]

class NetworkSchema(BaseModel):
    active_connections_count: int
    listening_ports: List[int]
    connections_sample: List[Dict[str, Any]]
    vpn_active: bool

class ThreatsSchema(BaseModel):
    security_alerts: List[Dict[str, Any]]

class ExamViolationDetail(BaseModel):
    type: str
    severity: str
    message: str
    evidence_process: Optional[str] = None
    recommended_action: Optional[str] = None

class ExamIntegritySchema(BaseModel):
    violations_found: bool
    violations: List[Dict[str, Any]]
    vpn_enabled: bool
    rdp_active: bool

# --- Main Telemetry Submit Models ---
class TelemetrySubmitRequest(BaseModel):
    agent_id: UUID
    timestamp: datetime
    system_info: SystemInfoSchema
    user_activity: UserActivitySchema
    security_status: SecurityStatusSchema
    processes: ProcessesSchema
    installed_software: SoftwareSchema
    usb_devices: USBSchema
    network: NetworkSchema
    threats: ThreatsSchema
    exam_integrity: ExamIntegritySchema
    file_activity: Optional[List[Dict[str, Any]]] = None
    persistence_items: Optional[List[Dict[str, Any]]] = None

class TelemetrySubmitResponse(BaseModel):
    status: str
    processed_records: int


class PolicyResponse(BaseModel):
    suspicious_keywords: List[str]


class PolicyRuleRequest(BaseModel):
    keyword: str


class PolicyRuleResponse(BaseModel):
    id: int
    keyword: str
    status: str


class CommandCreateRequest(BaseModel):
    command_text: str


class CommandResponse(BaseModel):
    id: UUID
    agent_id: UUID
    command_text: str
    response_text: Optional[str] = None
    status: str
    created_at: datetime
    executed_at: Optional[datetime] = None

    class Config:
        orm_mode = True
        from_attributes = True


class OperatorLoginRequest(BaseModel):
    username: str
    password: str


class OperatorLoginResponse(BaseModel):
    token: str
    token_type: str = "bearer"


class AndroidAppDetail(BaseModel):
    app_name: str
    package_name: str
    version_name: Optional[str] = None
    version_code: Optional[int] = None
    install_time: Optional[int] = None
    update_time: Optional[int] = None
    system_app: Optional[bool] = False
    enabled: Optional[bool] = True
    installer: Optional[str] = None
    target_sdk: Optional[int] = None
    certificate: Optional[str] = "Unknown"
    requested_permissions: Optional[List[str]] = []
    services: Optional[List[str]] = []
    receivers: Optional[List[str]] = []
    exported_components_count: Optional[int] = 0
    has_accessibility: Optional[bool] = False
    has_device_admin: Optional[bool] = False
    has_foreground_service: Optional[bool] = False
    has_overlay: Optional[bool] = False
    has_boot_receiver: Optional[bool] = False
    read_sms_granted: Optional[bool] = False
    read_contacts_granted: Optional[bool] = False
    camera_granted: Optional[bool] = False
    record_audio_granted: Optional[bool] = False
    keylogger_detected: Optional[bool] = False
    has_battery_exemption: Optional[bool] = False
    persistence_score: Optional[int] = 0
    accessibility_service_name: Optional[str] = ""
    accessibility_service_enabled: Optional[bool] = False
    accessibility_capabilities: Optional[List[str]] = []
    overlay_granted: Optional[bool] = False
    device_admin_active: Optional[bool] = False
    is_device_owner: Optional[bool] = False
    is_profile_owner: Optional[bool] = False
    certificate_reputation: Optional[str] = "unknown"
    apk_sha256: Optional[str] = "Unknown"
    has_launcher: Optional[bool] = True
    granted_permissions: Optional[List[str]] = []
    pending_permissions: Optional[List[str]] = []
    threat_score: Optional[int] = 0
    threat_category: Optional[str] = "Safe"
    mitre_tactics: Optional[List[str]] = []
    installer_reputation: Optional[str] = "Unknown"
    vt_detection_rate: Optional[str] = "0/0"
    mb_listed: Optional[bool] = False
    deleted: Optional[bool] = False


class AndroidAppsSyncRequest(BaseModel):
    device_id: str
    apps: List[AndroidAppDetail]


class AndroidAppsResponse(BaseModel):
    total_apps: int
    apps: List[Dict[str, Any]]


class FileReputationCheckRequest(BaseModel):
    agent_id: UUID
    file_path: str
    file_name: str
    sha1: Optional[str] = None
    sha256: str
    file_size: Optional[int] = 0


class FileReputationCheckResponse(BaseModel):
    verdict: str  # clean, suspicious, malicious, unknown
    vt_rate: str = "0/0"
    mb_listed: bool = False
    sha256: str
    cached: bool = False
    upload_required: bool = False
