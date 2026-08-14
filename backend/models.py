import uuid
from sqlalchemy import Column, String, Integer, Boolean, Numeric, DateTime, ForeignKey, ARRAY, BigInteger, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func
from .database import Base

class Agent(Base):
    __tablename__ = "agents"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    secret = Column(String(255), nullable=False)
    hostname = Column(String(255), nullable=False)
    username = Column(String(255), nullable=False)
    platform = Column(String(50), nullable=False)
    os_version = Column(String(255), nullable=False)
    agent_version = Column(String(50), nullable=False)
    department = Column(String(100))
    tags = Column(ARRAY(String))
    group_name = Column(String(100))
    status = Column(String(20), nullable=False, default="pending")
    last_seen = Column(DateTime(timezone=True), default=func.now(), onupdate=func.now())
    created_at = Column(DateTime(timezone=True), default=func.now())


class AgentHeartbeat(Base):
    __tablename__ = "agent_heartbeats"

    id = Column(Integer, primary_key=True, index=True)
    agent_id = Column(UUID(as_uuid=True), ForeignKey("agents.id", ondelete="CASCADE"), nullable=False)
    cpu_usage = Column(Numeric(5, 2), nullable=False)
    ram_usage = Column(Numeric(5, 2), nullable=False)
    status = Column(String(20), nullable=False)
    timestamp = Column(DateTime(timezone=True), default=func.now())


class ProcessEvent(Base):
    __tablename__ = "process_events"

    id = Column(Integer, primary_key=True, index=True)
    agent_id = Column(UUID(as_uuid=True), ForeignKey("agents.id", ondelete="CASCADE"), nullable=False)
    pid = Column(Integer, nullable=False)
    process_name = Column(String(255), nullable=False)
    parent_pid = Column(Integer)
    parent_process = Column(String(255))
    username = Column(String(255))
    event_type = Column(String(20), nullable=False)
    runtime_duration = Column(Integer)
    cpu_usage = Column(Numeric(5, 2))
    ram_usage = Column(Numeric(5, 2))
    executable_path = Column(String(1024))
    command_line = Column(Text)
    start_time = Column(DateTime(timezone=True))
    sha256_hash = Column(String(64))
    threat_score = Column(Integer, default=0)
    threat_reasons = Column(Text)
    threat_classification = Column(String(255))
    vt_rate = Column(String(50))
    mb_listed = Column(Boolean, default=False)
    timestamp = Column(DateTime(timezone=True), default=func.now())


class LoginEvent(Base):
    __tablename__ = "login_events"

    id = Column(Integer, primary_key=True, index=True)
    agent_id = Column(UUID(as_uuid=True), ForeignKey("agents.id", ondelete="CASCADE"), nullable=False)
    event_id = Column(Integer, nullable=False)
    event_type = Column(String(50), nullable=False)
    username = Column(String(255), nullable=False)
    source_ip = Column(String(45))
    timestamp = Column(DateTime(timezone=True), default=func.now())


class USBEvent(Base):
    __tablename__ = "usb_events"

    id = Column(Integer, primary_key=True, index=True)
    agent_id = Column(UUID(as_uuid=True), ForeignKey("agents.id", ondelete="CASCADE"), nullable=False)
    event_type = Column(String(20), nullable=False)
    device_name = Column(String(255))
    serial_number = Column(String(255))
    vendor_id = Column(String(50))
    device_type = Column(String(100))
    timestamp = Column(DateTime(timezone=True), default=func.now())


class NetworkEvent(Base):
    __tablename__ = "network_events"

    id = Column(Integer, primary_key=True, index=True)
    agent_id = Column(UUID(as_uuid=True), ForeignKey("agents.id", ondelete="CASCADE"), nullable=False)
    protocol = Column(String(10), nullable=False)
    local_address = Column(String(100), nullable=False)
    foreign_address = Column(String(100))
    state = Column(String(50))
    process_name = Column(String(100))
    pid = Column(Integer)
    vpn_active = Column(Boolean, default=False)
    timestamp = Column(DateTime(timezone=True), default=func.now())


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    agent_id = Column(UUID(as_uuid=True), ForeignKey("agents.id", ondelete="CASCADE"), nullable=False)
    severity = Column(String(20), nullable=False)
    category = Column(String(50), nullable=False)
    message = Column(String, nullable=False)
    evidence = Column(String(500))
    timestamp = Column(DateTime(timezone=True), default=func.now())


class ExamViolation(Base):
    __tablename__ = "exam_violations"

    id = Column(Integer, primary_key=True, index=True)
    agent_id = Column(UUID(as_uuid=True), ForeignKey("agents.id", ondelete="CASCADE"), nullable=False)
    violation_type = Column(String(100), nullable=False)
    severity = Column(String(20), nullable=False)
    message = Column(String, nullable=False)
    evidence_process = Column(String(255))
    recommended_action = Column(String)
    timestamp = Column(DateTime(timezone=True), default=func.now())


class SystemLog(Base):
    __tablename__ = "system_logs"

    id = Column(Integer, primary_key=True, index=True)
    log_level = Column(String(10), nullable=False)
    message = Column(String, nullable=False)
    created_at = Column(DateTime(timezone=True), default=func.now())


class PolicyRule(Base):
    __tablename__ = "policy_rules"

    id = Column(Integer, primary_key=True, index=True)
    keyword = Column(String(255), unique=True, nullable=False)
    created_at = Column(DateTime(timezone=True), default=func.now())


class Command(Base):
    __tablename__ = "commands"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    agent_id = Column(UUID(as_uuid=True), ForeignKey("agents.id", ondelete="CASCADE"), nullable=False)
    command_text = Column(String, nullable=False)
    response_text = Column(String)
    status = Column(String(20), nullable=False, default="pending")
    created_at = Column(DateTime(timezone=True), default=func.now())
    executed_at = Column(DateTime(timezone=True))


class FileEvent(Base):
    __tablename__ = "file_events"

    id = Column(Integer, primary_key=True, index=True)
    agent_id = Column(UUID(as_uuid=True), ForeignKey("agents.id", ondelete="CASCADE"), nullable=False)
    file_path = Column(String(1024), nullable=False)
    action = Column(String(50), nullable=False)
    sha256_hash = Column(String(64))
    timestamp = Column(DateTime(timezone=True), default=func.now())


class InstalledSoftware(Base):
    __tablename__ = "installed_software"

    id = Column(Integer, primary_key=True, index=True)
    agent_id = Column(UUID(as_uuid=True), ForeignKey("agents.id", ondelete="CASCADE"), nullable=False)
    software_name = Column(String(255), nullable=False)
    version = Column(String(255))
    status = Column(String(50), default="Installed")
    timestamp = Column(DateTime(timezone=True), default=func.now())

class AndroidApp(Base):
    __tablename__ = "android_apps"

    id = Column(Integer, primary_key=True, index=True)
    agent_id = Column(UUID(as_uuid=True), ForeignKey("agents.id", ondelete="CASCADE"), nullable=True)
    device_id = Column(String(255), nullable=False)
    app_name = Column(String(255), nullable=False)
    package_name = Column(String(255), nullable=False)
    version_name = Column(String(255))
    version_code = Column(BigInteger)
    install_time = Column(BigInteger)
    update_time = Column(BigInteger)
    system_app = Column(Boolean, default=False)
    enabled = Column(Boolean, default=True)
    installer = Column(String(255))
    target_sdk = Column(Integer)
    risk_level = Column(String(20), default="green")
    certificate = Column(String(500), default="Unknown")
    requested_permissions = Column(ARRAY(String), default=[])
    services = Column(ARRAY(String), default=[])
    receivers = Column(ARRAY(String), default=[])
    exported_components_count = Column(Integer, default=0)
    has_accessibility = Column(Boolean, default=False)
    has_device_admin = Column(Boolean, default=False)
    has_foreground_service = Column(Boolean, default=False)
    has_overlay = Column(Boolean, default=False)
    has_boot_receiver = Column(Boolean, default=False)
    read_sms_granted = Column(Boolean, default=False)
    read_contacts_granted = Column(Boolean, default=False)
    camera_granted = Column(Boolean, default=False)
    record_audio_granted = Column(Boolean, default=False)
    keylogger_detected = Column(Boolean, default=False)
    has_battery_exemption = Column(Boolean, default=False)
    persistence_score = Column(Integer, default=0)
    accessibility_service_name = Column(String(500), nullable=True)
    accessibility_service_enabled = Column(Boolean, default=False)
    accessibility_capabilities = Column(ARRAY(String), default=[])
    overlay_granted = Column(Boolean, default=False)
    device_admin_active = Column(Boolean, default=False)
    is_device_owner = Column(Boolean, default=False)
    is_profile_owner = Column(Boolean, default=False)
    certificate_reputation = Column(String(50), default="unknown")
    apk_sha256 = Column(String(64), default="Unknown")
    has_launcher = Column(Boolean, default=True)
    granted_permissions = Column(ARRAY(String), default=[])
    pending_permissions = Column(ARRAY(String), default=[])
    threat_score = Column(Integer, default=0)
    threat_category = Column(String(100), default="Safe")
    mitre_tactics = Column(ARRAY(String), default=[])
    installer_reputation = Column(String(50), default="Unknown")
    vt_detection_rate = Column(String(20), default="0/0")
    mb_listed = Column(Boolean, default=False)
    deleted = Column(Boolean, default=False)
    last_seen = Column(DateTime(timezone=True), default=func.now(), onupdate=func.now())


class FileReputation(Base):
    __tablename__ = "file_reputations"

    id = Column(Integer, primary_key=True, index=True)
    agent_id = Column(UUID(as_uuid=True), ForeignKey("agents.id", ondelete="CASCADE"), nullable=False)
    file_path = Column(String(1024), nullable=False)
    file_name = Column(String(255), nullable=False)
    sha1 = Column(String(40))
    sha256 = Column(String(64), nullable=False)
    file_size = Column(BigInteger)
    verdict = Column(String(50), nullable=False, default="unknown")  # clean, suspicious, malicious, unknown
    vt_rate = Column(String(50), default="0/0")
    mb_listed = Column(Boolean, default=False)
    timestamp = Column(DateTime(timezone=True), default=func.now())


class PersistenceItem(Base):
    __tablename__ = "persistence_items"

    id = Column(Integer, primary_key=True, index=True)
    agent_id = Column(UUID(as_uuid=True), ForeignKey("agents.id", ondelete="CASCADE"), nullable=False)
    item_type = Column(String(50), nullable=False)  # registry, startup_folder, scheduled_task, service, wmi_subscription
    location = Column(String(1024), nullable=False)
    name = Column(String(255), nullable=False)
    value = Column(Text)
    source = Column(String(50))  # winreg, powershell, filesystem, wmi
    is_new = Column(Boolean, default=False)
    timestamp = Column(DateTime(timezone=True), default=func.now())
