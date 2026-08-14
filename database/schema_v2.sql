-- RedEye Defensive SOC/EDR Database Schema (v2)
-- Database Name: Demo_RE
-- Target DB: PostgreSQL 18+

-- Drop tables if they already exist in reverse dependency order
DROP TABLE IF EXISTS exam_violations CASCADE;
DROP TABLE IF EXISTS alerts CASCADE;
DROP TABLE IF EXISTS network_events CASCADE;
DROP TABLE IF EXISTS usb_events CASCADE;
DROP TABLE IF EXISTS login_events CASCADE;
DROP TABLE IF EXISTS process_events CASCADE;
DROP TABLE IF EXISTS agent_heartbeats CASCADE;
DROP TABLE IF EXISTS commands CASCADE;
DROP TABLE IF EXISTS agents CASCADE;
DROP TABLE IF EXISTS system_logs CASCADE;
DROP TABLE IF EXISTS policy_rules CASCADE;

-- 1. Agents Table: Stores identity and inventory configuration
CREATE TABLE agents (
    id UUID PRIMARY KEY,
    secret VARCHAR(255) NOT NULL,
    hostname VARCHAR(255) NOT NULL,
    username VARCHAR(255) NOT NULL,
    platform VARCHAR(50) NOT NULL, -- 'Windows', 'Linux', 'Android'
    os_version VARCHAR(255) NOT NULL,
    agent_version VARCHAR(50) NOT NULL,
    department VARCHAR(100),
    tags VARCHAR(255)[], -- Array of tags (e.g. Critical, Remote)
    group_name VARCHAR(100),
    status VARCHAR(20) NOT NULL DEFAULT 'pending', -- 'online', 'offline', 'pending'
    last_seen TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 1b. Commands Table: Tracks commands sent to agents and their responses
CREATE TABLE commands (
    id UUID PRIMARY KEY,
    agent_id UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    command_text TEXT NOT NULL,
    response_text TEXT,
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    executed_at TIMESTAMP WITH TIME ZONE
);

-- 2. Agent Heartbeats Table: Tracks pings and simple resource usage
CREATE TABLE agent_heartbeats (
    id SERIAL PRIMARY KEY,
    agent_id UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    cpu_usage NUMERIC(5, 2) NOT NULL,
    ram_usage NUMERIC(5, 2) NOT NULL,
    status VARCHAR(20) NOT NULL,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 3. Process Events Table: Logs process launches and exits
CREATE TABLE process_events (
    id SERIAL PRIMARY KEY,
    agent_id UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    pid INTEGER NOT NULL,
    process_name VARCHAR(255) NOT NULL,
    parent_pid INTEGER,
    parent_process VARCHAR(255),
    username VARCHAR(255),
    event_type VARCHAR(20) NOT NULL, -- 'creation', 'termination'
    runtime_duration INTEGER, -- duration in seconds (if termination)
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 4. Login Events Table: Tracks auth state changes
CREATE TABLE login_events (
    id SERIAL PRIMARY KEY,
    agent_id UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    event_id INTEGER NOT NULL, -- e.g. 4624, 4625
    event_type VARCHAR(50) NOT NULL, -- 'Logon', 'FailedLogon', 'Logoff'
    username VARCHAR(255) NOT NULL,
    source_ip VARCHAR(45),
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 5. USB Events Table: Tracks hot-plugged devices
CREATE TABLE usb_events (
    id SERIAL PRIMARY KEY,
    agent_id UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    event_type VARCHAR(20) NOT NULL, -- 'inserted', 'removed'
    device_name VARCHAR(255),
    serial_number VARCHAR(255),
    vendor_id VARCHAR(50),
    device_type VARCHAR(100),
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 6. Network Events Table: Logs active sockets
CREATE TABLE network_events (
    id SERIAL PRIMARY KEY,
    agent_id UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    protocol VARCHAR(10) NOT NULL, -- 'TCP', 'UDP'
    local_address VARCHAR(100) NOT NULL,
    foreign_address VARCHAR(100),
    state VARCHAR(50),
    vpn_active BOOLEAN DEFAULT FALSE,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 7. Alerts Table: Logs suspicious heuristics from the local agent
CREATE TABLE alerts (
    id SERIAL PRIMARY KEY,
    agent_id UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    severity VARCHAR(20) NOT NULL, -- 'Informational', 'Low', 'Medium', 'High', 'Critical'
    category VARCHAR(50) NOT NULL, -- 'USB', 'Authentication', 'Network', 'Process Activity', 'Threat Detection'
    message TEXT NOT NULL,
    evidence VARCHAR(500),
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 8. Exam Violations Table: Tracks exam cheating indications
CREATE TABLE exam_violations (
    id SERIAL PRIMARY KEY,
    agent_id UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    violation_type VARCHAR(100) NOT NULL, -- 'FORBIDDEN_PROCESS', 'VPN_DETECTED', 'RDP_ACTIVE'
    severity VARCHAR(20) NOT NULL, -- 'WARNING', 'CRITICAL'
    message TEXT NOT NULL,
    evidence_process VARCHAR(255),
    recommended_action TEXT,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 9. System Logs Table: Global server logs
CREATE TABLE system_logs (
    id SERIAL PRIMARY KEY,
    log_level VARCHAR(10) NOT NULL,
    message TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for performance query optimization
CREATE INDEX idx_agents_status ON agents(status);
CREATE INDEX idx_heartbeats_agent ON agent_heartbeats(agent_id, timestamp DESC);
CREATE INDEX idx_process_events_agent ON process_events(agent_id, timestamp DESC);
CREATE INDEX idx_login_events_agent ON login_events(agent_id, timestamp DESC);
CREATE INDEX idx_usb_events_agent ON usb_events(agent_id, timestamp DESC);
CREATE INDEX idx_network_events_agent ON network_events(agent_id, timestamp DESC);
CREATE INDEX idx_alerts_agent ON alerts(agent_id, timestamp DESC);
CREATE INDEX idx_exam_violations_agent ON exam_violations(agent_id, timestamp DESC);

-- 10. Policy Rules Table: Stores dynamic keywords to block
CREATE TABLE policy_rules (
    id SERIAL PRIMARY KEY,
    keyword VARCHAR(255) NOT NULL UNIQUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_policy_rules_keyword ON policy_rules(keyword);

-- 11. Android Apps Table: Stores application telemetry inventory for Android agents
CREATE TABLE android_apps (
    id SERIAL PRIMARY KEY,
    agent_id UUID REFERENCES agents(id) ON DELETE CASCADE,
    device_id VARCHAR(255) NOT NULL,
    app_name VARCHAR(255) NOT NULL,
    package_name VARCHAR(255) NOT NULL,
    version_name VARCHAR(100),
    version_code BIGINT,
    install_time BIGINT,
    update_time BIGINT,
    system_app BOOLEAN DEFAULT FALSE,
    enabled BOOLEAN DEFAULT TRUE,
    installer VARCHAR(255),
    target_sdk INTEGER,
    risk_level VARCHAR(20) DEFAULT 'green',
    last_seen TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_android_apps_agent ON android_apps(agent_id);
CREATE INDEX idx_android_apps_device ON android_apps(device_id);
