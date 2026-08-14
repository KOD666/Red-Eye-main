-- RedEye Command & Control Database Schema
-- Database Name: Demo_RE
-- Target DB: PostgreSQL 18+

-- Drop tables if they already exist
DROP TABLE IF EXISTS commands;
DROP TABLE IF EXISTS agents;
DROP TABLE IF EXISTS system_logs;

-- Agents table: Stores information about active targets
CREATE TABLE agents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    hostname VARCHAR(255) NOT NULL,
    platform VARCHAR(50) NOT NULL, -- 'Windows', 'Linux', 'Android'
    os_release VARCHAR(255) NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'offline', -- 'online', 'offline'
    last_seen TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Commands table: Stores commands queued for agents and their results
CREATE TABLE commands (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    command_text TEXT NOT NULL,
    response_text TEXT,
    status VARCHAR(20) NOT NULL DEFAULT 'pending', -- 'pending', 'sent', 'completed', 'failed'
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    executed_at TIMESTAMP WITH TIME ZONE
);

-- System logs table: Audit log for the RedEye dashboard actions
CREATE TABLE system_logs (
    id SERIAL PRIMARY KEY,
    log_level VARCHAR(10) NOT NULL, -- 'INFO', 'WARN', 'ERROR', 'CRITICAL'
    message TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Indexing for performance optimization
CREATE INDEX idx_agents_status ON agents(status);
CREATE INDEX idx_agents_last_seen ON agents(last_seen);
CREATE INDEX idx_commands_agent_status ON commands(agent_id, status);
CREATE INDEX idx_commands_created ON commands(created_at DESC);
CREATE INDEX idx_system_logs_created ON system_logs(created_at DESC);
