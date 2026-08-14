import unittest
from unittest.mock import patch, MagicMock
import os
os.environ["TESTING"] = "True"
import uuid
import time
import sqlite3
import json
sqlite3.register_adapter(list, json.dumps)
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.types import ARRAY

# Register custom compiler for ARRAY on SQLite so metadata.create_all() works
@compiles(ARRAY, "sqlite")
def compile_array_sqlite(type_, compiler, **kw):
    return "TEXT"

# Import app, Base, get_db, models
from backend.main import app
from backend.database import Base, get_db
from backend import models

# File-based SQLite database for testing (allows tables persistence across FastAPI session calls)
import os
DB_FILE = "test_auth.db"
SQLALCHEMY_DATABASE_URL = f"sqlite:///{DB_FILE}"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

class TestAuthFlow(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.path.exists(DB_FILE):
            try:
                os.remove(DB_FILE)
            except Exception:
                pass
        Base.metadata.create_all(bind=engine)
        cls.client = TestClient(app)

    @classmethod
    def tearDownClass(cls):
        Base.metadata.drop_all(bind=engine)
        engine.dispose()
        if os.path.exists(DB_FILE):
            try:
                os.remove(DB_FILE)
            except Exception:
                pass

    def setUp(self):
        # Override the dependency to use the in-memory SQLite database
        def override_get_db():
            db = TestingSessionLocal()
            try:
                yield db
            finally:
                db.close()
        app.dependency_overrides[get_db] = override_get_db
        
        # Clear database records between runs to ensure isolation
        self.db = TestingSessionLocal()
        self.db.query(models.Agent).delete()
        self.db.commit()

    def tearDown(self):
        self.db.close()
        app.dependency_overrides.clear()

    def test_agent_registration_flow(self):
        # 1. Register a new agent
        payload = {
            "hostname": "test-host",
            "username": "test-user",
            "os_version": "Windows 10 Pro",
            "agent_version": "1.0.0",
            "department": "IT",
            "tags": ["test"],
            "group": "default"
        }
        response = self.client.post("/api/v1/agents/register", json=payload)
        self.assertEqual(response.status_code, 201)
        data = response.json()
        self.assertIn("agent_id", data)
        self.assertIn("secret", data)
        self.assertIn("token", data)
        self.assertEqual(data["registration_status"], "registered")
        
        agent_id = data["agent_id"]
        secret = data["secret"]
        token = data["token"]
        
        # 2. Try registering the same agent again (should update and return new secret/token)
        payload["os_version"] = "Windows 11 Pro"
        response2 = self.client.post("/api/v1/agents/register", json=payload)
        self.assertEqual(response2.status_code, 201)
        data2 = response2.json()
        self.assertEqual(data2["agent_id"], agent_id)
        self.assertNotEqual(data2["secret"], secret) # Verify new secret generated
        self.assertEqual(data2["registration_status"], "updated")

    def test_ping_authentication(self):
        # Register agent to get valid credentials
        reg_payload = {
            "hostname": "ping-host",
            "username": "ping-user",
            "os_version": "Windows 10 Pro",
            "agent_version": "1.0.0",
            "tags": [],
            "group": "default"
        }
        reg_data = self.client.post("/api/v1/agents/register", json=reg_payload).json()
        agent_id = reg_data["agent_id"]
        token = reg_data["token"]
        
        ping_payload = {
            "agent_id": agent_id,
            "cpu_usage": 15.5,
            "ram_usage": 45.2,
            "status": "online"
        }
        
        # 1. Ping without authorization header
        response = self.client.post("/api/v1/agents/ping", json=ping_payload)
        self.assertIn(response.status_code, [401, 403]) # HTTPBearer raises 401/403 when no auth header is present
        
        # 2. Ping with invalid authorization header
        response = self.client.post("/api/v1/agents/ping", json=ping_payload, headers={"Authorization": "Bearer invalidtoken"})
        self.assertEqual(response.status_code, 401)
        
        # 3. Ping with valid authorization header
        response = self.client.post("/api/v1/agents/ping", json=ping_payload, headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "success")

    def test_telemetry_submit_authentication(self):
        # Register agent
        reg_payload = {
            "hostname": "telemetry-host",
            "username": "telemetry-user",
            "os_version": "Windows 10 Pro",
            "agent_version": "1.0.0",
            "tags": [],
            "group": "default"
        }
        reg_data = self.client.post("/api/v1/agents/register", json=reg_payload).json()
        agent_id = reg_data["agent_id"]
        token = reg_data["token"]

        telemetry_payload = {
            "agent_id": agent_id,
            "timestamp": "2026-06-18T12:00:00Z",
            "system_info": {
                "hostname": "telemetry-host",
                "username": "telemetry-user",
                "os_version": "Windows 10 Pro",
                "ip_address": "192.168.1.10",
                "mac_address": "AA:BB:CC:DD:EE:FF",
                "cpu_usage": 10.0,
                "ram_usage": 20.0,
                "disk_usage": 50.0,
                "uptime": 3600
            },
            "user_activity": {"recent_audit_events": [], "last_logged_in_user": "telemetry-user"},
            "security_status": {"antivirus_status": "Active", "firewall_status": "On", "privilege_escalation_warnings": []},
            "processes": {"running_processes_count": 0, "sample_processes": [], "suspicious_processes": []},
            "installed_software": {"installed_applications_count": 0, "software_list": []},
            "usb_devices": {"connected_usb_devices": []},
            "network": {"active_connections_count": 0, "listening_ports": [], "connections_sample": [], "vpn_active": False},
            "threats": {"security_alerts": []},
            "exam_integrity": {"violations_found": False, "violations": [], "vpn_enabled": False, "rdp_active": False}
        }

        # 1. Telemetry without auth header
        response = self.client.post("/api/v1/telemetry/submit", json=telemetry_payload)
        self.assertIn(response.status_code, [401, 403])
        
        # 2. Telemetry with valid auth header
        response = self.client.post("/api/v1/telemetry/submit", json=telemetry_payload, headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "success")

    def test_token_retrieval_and_refresh(self):
        # Register agent
        reg_payload = {
            "hostname": "token-host",
            "username": "token-user",
            "os_version": "Windows 10 Pro",
            "agent_version": "1.0.0",
            "tags": [],
            "group": "default"
        }
        reg_data = self.client.post("/api/v1/agents/register", json=reg_payload).json()
        agent_id = reg_data["agent_id"]
        secret = reg_data["secret"]

        # 1. Get token with valid credentials
        token_payload = {"agent_id": agent_id, "secret": secret}
        response = self.client.post("/api/v1/agents/token", json=token_payload)
        self.assertEqual(response.status_code, 200)
        self.assertIn("token", response.json())
        new_token = response.json()["token"]

        # Verify new token works for pinging
        ping_payload = {
            "agent_id": agent_id,
            "cpu_usage": 5.0,
            "ram_usage": 10.0,
            "status": "online"
        }
        response_ping = self.client.post("/api/v1/agents/ping", json=ping_payload, headers={"Authorization": f"Bearer {new_token}"})
        self.assertEqual(response_ping.status_code, 200)

        # 2. Try to get token with invalid secret
        token_payload["secret"] = "wrong_secret"
        response_invalid = self.client.post("/api/v1/agents/token", json=token_payload)
        self.assertEqual(response_invalid.status_code, 401)

    def test_mismatched_agent_id_and_token(self):
        # Register two agents
        reg_payload_a = {
            "hostname": "host-a",
            "username": "user-a",
            "os_version": "Windows 10 Pro",
            "agent_version": "1.0.0",
            "tags": [],
            "group": "default"
        }
        reg_data_a = self.client.post("/api/v1/agents/register", json=reg_payload_a).json()
        agent_id_a = reg_data_a["agent_id"]
        token_a = reg_data_a["token"]

        reg_payload_b = {
            "hostname": "host-b",
            "username": "user-b",
            "os_version": "Windows 10 Pro",
            "agent_version": "1.0.0",
            "tags": [],
            "group": "default"
        }
        reg_data_b = self.client.post("/api/v1/agents/register", json=reg_payload_b).json()
        agent_id_b = reg_data_b["agent_id"]
        
        # Ping with agent_id B but token A (should be rejected with 403 Forbidden)
        ping_payload = {
            "agent_id": agent_id_b,
            "cpu_usage": 10.0,
            "ram_usage": 20.0,
            "status": "online"
        }
        response = self.client.post("/api/v1/agents/ping", json=ping_payload, headers={"Authorization": f"Bearer {token_a}"})
        self.assertEqual(response.status_code, 403)
        self.assertIn("does not match", response.json()["detail"])
    def test_agent_identity_persistence(self):
        # Dynamically import Red-Eye.py
        import importlib.util
        import sys
        spec = importlib.util.spec_from_file_location("red_eye", "agents/windows/Red-Eye.py")
        red_eye = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(red_eye)

        # Mock the config path to use a test-local file
        test_config_file = os.path.abspath("test_agent_config.json")
        red_eye.get_config_path = lambda: test_config_file

        # Ensure no residual config exists
        if os.path.exists(test_config_file):
            os.remove(test_config_file)

        try:
            # 1. Loading when config doesn't exist should return None
            self.assertIsNone(red_eye.load_stored_identity())

            # 2. Save identity
            agent_uuid = str(uuid.uuid4())
            secret = "supersecret123"
            hostname = "test-persist-host"
            save_success = red_eye.save_stored_identity(agent_uuid, secret, hostname)
            self.assertTrue(save_success)

            # Verify file exists
            self.assertTrue(os.path.exists(test_config_file))

            # 3. Load identity and verify values
            identity = red_eye.load_stored_identity()
            self.assertIsNotNone(identity)
            self.assertEqual(identity["agent_uuid"], agent_uuid)
            self.assertEqual(identity["secret"], secret)
            self.assertEqual(identity["hostname"], hostname)

        finally:
            # Clean up the test config file
            if os.path.exists(test_config_file):
                try:
                    os.remove(test_config_file)
                except Exception:
                    pass
    def test_offline_queue_mechanism(self):
        # Dynamically import Red-Eye.py
        import importlib.util
        import shutil
        spec = importlib.util.spec_from_file_location("red_eye", "agents/windows/Red-Eye.py")
        red_eye = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(red_eye)

        # Mock the queue directory to use a test-local folder
        test_queue_dir = os.path.abspath("test_queue")
        red_eye.get_queue_dir = lambda: test_queue_dir

        # Ensure any residual test queue directory is deleted
        if os.path.exists(test_queue_dir):
            shutil.rmtree(test_queue_dir)

        try:
            # 1. Register a test agent to get a valid token/identity
            reg_payload = {
                "hostname": "queue-test-host",
                "username": "queue-test-user",
                "os_version": "Windows 10 Pro",
                "agent_version": "1.0.0",
                "tags": [],
                "group": "default"
            }
            reg_data = self.client.post("/api/v1/agents/register", json=reg_payload).json()
            agent_id = reg_data["agent_id"]
            secret = reg_data["secret"]
            token = reg_data["token"]

            # 2. Simulate submit_telemetry failing due to connection error
            import requests
            def mock_failed_post(*args, **kwargs):
                raise requests.exceptions.ConnectionError("Failed to connect")

            original_post = requests.post
            requests.post = mock_failed_post

            # Try submitting telemetry; it should fail and queue the payload
            success = red_eye.submit_telemetry("http://unreachable-url", agent_id, token)
            self.assertFalse(success)

            # Restore original requests.post
            requests.post = original_post

            # 3. Verify payload was successfully serialized to the local queue folder
            self.assertTrue(os.path.exists(test_queue_dir))
            files = [f for f in os.listdir(test_queue_dir) if f.startswith("telemetry_") and f.endswith(".json")]
            self.assertEqual(len(files), 1)

            # Read the serialized payload
            with open(os.path.join(test_queue_dir, files[0]), "r") as f:
                queued_payload = json.load(f)
            self.assertEqual(queued_payload["agent_id"], agent_id)

            # 4. Now process the queue with a valid API server target URL
            def mock_client_post(url, *args, **kwargs):
                from urllib.parse import urlparse
                parsed = urlparse(url)
                path = parsed.path
                if "data" in kwargs:
                    kwargs["content"] = kwargs.pop("data")
                r = self.client.post(path, *args, **kwargs)
                class MockResponse:
                    def __init__(self, res):
                        self.status_code = res.status_code
                        self.text = res.text
                        self._res = res
                    def json(self):
                        return self._res.json()
                return MockResponse(r)

            requests.post = mock_client_post
            red_eye.NEXT_RETRY_TIME = 0.0

            # Process the queue
            updated_token = red_eye.process_offline_queue("http://localhost:8000", agent_id, token, secret)
            self.assertEqual(updated_token, token)

            # Restore original requests.post
            requests.post = original_post

            # Verify queue file was successfully uploaded and deleted
            files_after = [f for f in os.listdir(test_queue_dir) if f.startswith("telemetry_") and f.endswith(".json")]
            self.assertEqual(len(files_after), 0)

        finally:
            # Clean up the test queue directory
            if os.path.exists(test_queue_dir):
                shutil.rmtree(test_queue_dir)
    def test_scheduling_intervals_and_caching(self):
        # Dynamically import Red-Eye.py
        import importlib.util
        spec = importlib.util.spec_from_file_location("red_eye", "agents/windows/Red-Eye.py")
        red_eye = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(red_eye)

        # Initialize cache globals to None/0
        red_eye.CACHED_SOFTWARE_DATA = None
        red_eye.LAST_SOFTWARE_COLLECTION_TIME = 0.0

        # Spy on collect_installed_software
        original_collect = red_eye.collect_installed_software
        call_count = 0
        def spy_collect():
            nonlocal call_count
            call_count += 1
            return original_collect()
        red_eye.collect_installed_software = spy_collect

        # Register a test agent to get a valid token/identity
        reg_payload = {
            "hostname": "cache-test-host",
            "username": "cache-test-user",
            "os_version": "Windows 10 Pro",
            "agent_version": "1.0.0",
            "tags": [],
            "group": "default"
        }
        reg_data = self.client.post("/api/v1/agents/register", json=reg_payload).json()
        agent_id = reg_data["agent_id"]
        token = reg_data["token"]

        # Mock requests.post to redirect to TestClient
        import requests
        def mock_client_post(url, *args, **kwargs):
            from urllib.parse import urlparse
            parsed = urlparse(url)
            path = parsed.path
            if "data" in kwargs:
                kwargs["content"] = kwargs.pop("data")
            r = self.client.post(path, *args, **kwargs)
            class MockResponse:
                def __init__(self, res):
                    self.status_code = res.status_code
                    self.text = res.text
                    self._res = res
                def json(self):
                    return self._res.json()
            return MockResponse(r)

        original_post = requests.post
        requests.post = mock_client_post

        try:
            # First telemetry submission: should fetch software list (call_count becomes 1)
            red_eye.submit_telemetry("http://localhost:8000", agent_id, token)
            self.assertEqual(call_count, 1)
            self.assertIsNotNone(red_eye.CACHED_SOFTWARE_DATA)

            # Second telemetry submission: should use cached software list (call_count remains 1)
            red_eye.submit_telemetry("http://localhost:8000", agent_id, token)
            self.assertEqual(call_count, 1)

        finally:
            requests.post = original_post
            red_eye.collect_installed_software = original_collect

    def test_incremental_telemetry_payloads(self):
        """Verifies that the agent sends only changes/diffs after establishing the baseline."""
        import importlib.util
        spec = importlib.util.spec_from_file_location("red_eye", "agents/windows/Red-Eye.py")
        red_eye = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(red_eye)

        import requests
        
        # Reset telemetry states
        red_eye.reset_telemetry_state()
        
        # Register a test agent to get a valid token/identity
        reg_payload = {
            "hostname": "diff-test-host",
            "username": "diff-test-user",
            "os_version": "Windows 10 Pro",
            "agent_version": "1.0.0",
            "tags": [],
            "group": "default"
        }
        reg_data = self.client.post("/api/v1/agents/register", json=reg_payload).json()
        agent_id = reg_data["agent_id"]
        token = reg_data["token"]

        sent_payloads = []
        def mock_client_post(url, *args, **kwargs):
            from urllib.parse import urlparse
            import gzip
            parsed = urlparse(url)
            path = parsed.path
            if "json" in kwargs:
                sent_payloads.append(kwargs["json"])
            elif "data" in kwargs:
                data = kwargs["data"]
                if kwargs.get("headers", {}).get("Content-Encoding") == "gzip":
                    data = gzip.decompress(data)
                sent_payloads.append(json.loads(data.decode('utf-8')))
                
            if "data" in kwargs:
                kwargs["content"] = kwargs.pop("data")
            r = self.client.post(path, *args, **kwargs)
            class MockResponse:
                def __init__(self, res):
                    self.status_code = res.status_code
                    self.text = res.text
                    self._res = res
                def json(self):
                    return self._res.json()
            return MockResponse(r)

        original_post = requests.post
        requests.post = mock_client_post

        # Mock collection functions to control returned lists
        original_processes = red_eye.collect_processes
        original_software = red_eye.collect_installed_software
        original_usb = red_eye.collect_usb_devices
        original_network = red_eye.collect_network_info

        mock_proc_list = [
            {"pid": 100, "name": "system.exe", "parent_pid": 0, "parent_process": "init", "user": "SYSTEM"},
            {"pid": 200, "name": "explorer.exe", "parent_pid": 100, "parent_process": "system.exe", "user": "user1"}
        ]
        red_eye.collect_processes = lambda: {
            "running_processes_count": len(mock_proc_list),
            "sample_processes": mock_proc_list,
            "suspicious_processes": []
        }

        mock_sw_list = [
            {"name": "Python 3.10", "version": "3.10.5"},
            {"name": "Git", "version": "2.37.0"}
        ]
        red_eye.collect_installed_software = lambda: {
            "installed_applications_count": len(mock_sw_list),
            "software_list": mock_sw_list,
            "alerts": []
        }

        mock_usb_list = [
            {"device_name": "Kingston DataTraveler", "serial_number": "12345XYZ"}
        ]
        red_eye.collect_usb_devices = lambda: {
            "connected_usb_devices": mock_usb_list,
            "alerts": []
        }

        mock_net_list = [
            {"protocol": "TCP", "local_address": "127.0.0.1:443", "foreign_address": "127.0.0.1:54321", "state": "ESTABLISHED", "vpn_active": False}
        ]
        red_eye.collect_network_info = lambda: {
            "active_connections_count": len(mock_net_list),
            "listening_ports": [443],
            "connections_sample": mock_net_list,
            "vpn_active": False,
            "alerts": []
        }

        try:
            # 1. First submission (baseline)
            red_eye.submit_telemetry("http://localhost:8000", agent_id, token)
            self.assertEqual(len(sent_payloads), 1)
            p1 = sent_payloads[-1]
            
            # Assert all items have action: baseline
            for item in p1["processes"]["sample_processes"]:
                self.assertEqual(item["action"], "baseline")
            for item in p1["installed_software"]["software_list"]:
                self.assertEqual(item["action"], "baseline")
            for item in p1["usb_devices"]["connected_usb_devices"]:
                self.assertEqual(item["action"], "baseline")
            for item in p1["network"]["connections_sample"]:
                self.assertEqual(item["action"], "baseline")

            # 2. Second submission (no changes)
            red_eye.submit_telemetry("http://localhost:8000", agent_id, token)
            self.assertEqual(len(sent_payloads), 2)
            p2 = sent_payloads[-1]

            # Lists should be completely empty since there are no changes
            self.assertEqual(len(p2["processes"]["sample_processes"]), 0)
            self.assertEqual(len(p2["installed_software"]["software_list"]), 0)
            self.assertEqual(len(p2["usb_devices"]["connected_usb_devices"]), 0)
            self.assertEqual(len(p2["network"]["connections_sample"]), 0)

            # 3. Third submission (with changes)
            # - Start pid 300, stop pid 200
            # - Install "VS Code", uninstall "Git"
            # - Unplug USB
            # - Add network connection
            mock_proc_list = [
                {"pid": 100, "name": "system.exe", "parent_pid": 0, "parent_process": "init", "user": "SYSTEM"},
                {"pid": 300, "name": "vscode.exe", "parent_pid": 100, "parent_process": "system.exe", "user": "user1"}
            ]
            mock_sw_list = [
                {"name": "Python 3.10", "version": "3.10.5"},
                {"name": "VS Code", "version": "1.70.0"}
            ]
            mock_usb_list = []
            mock_net_list = [
                {"protocol": "TCP", "local_address": "127.0.0.1:443", "foreign_address": "127.0.0.1:54321", "state": "ESTABLISHED", "vpn_active": False},
                {"protocol": "TCP", "local_address": "127.0.0.1:80", "foreign_address": "127.0.0.1:61234", "state": "ESTABLISHED", "vpn_active": False}
            ]

            red_eye.CACHED_SOFTWARE_DATA = None
            red_eye.submit_telemetry("http://localhost:8000", agent_id, token)
            self.assertEqual(len(sent_payloads), 3)
            p3 = sent_payloads[-1]

            # Processes check: explorer (200) terminated, vscode (300) started
            proc_changes = p3["processes"]["sample_processes"]
            self.assertEqual(len(proc_changes), 2)
            started_pids = [pr["pid"] for pr in proc_changes if pr["action"] == "started"]
            terminated_pids = [pr["pid"] for pr in proc_changes if pr["action"] == "terminated"]
            self.assertIn(300, started_pids)
            self.assertIn(200, terminated_pids)

            # Software check: VS Code added, Git removed
            sw_changes = p3["installed_software"]["software_list"]
            self.assertEqual(len(sw_changes), 2)
            added_sw = [s["name"] for s in sw_changes if s["action"] == "added"]
            removed_sw = [s["name"] for s in sw_changes if s["action"] == "removed"]
            self.assertIn("VS Code", added_sw)
            self.assertIn("Git", removed_sw)

            # USB check: Kingston removed
            usb_changes = p3["usb_devices"]["connected_usb_devices"]
            self.assertEqual(len(usb_changes), 1)
            self.assertEqual(usb_changes[0]["action"], "removed")
            self.assertEqual(usb_changes[0]["serial_number"], "12345XYZ")

            # Network check: Port 80 connection opened
            net_changes = p3["network"]["connections_sample"]
            self.assertEqual(len(net_changes), 1)
            self.assertEqual(net_changes[0]["action"], "opened")
            self.assertIn(":80", net_changes[0]["local_address"])

        finally:
            requests.post = original_post
            red_eye.collect_processes = original_processes
            red_eye.collect_installed_software = original_software
            red_eye.collect_usb_devices = original_usb
            red_eye.collect_network_info = original_network
            red_eye.reset_telemetry_state()

    def test_exponential_backoff_retry(self):
        """Verifies that network failures cause exponential backoff: 60s, 120s, 240s, 480s, 960s."""
        import importlib.util
        spec = importlib.util.spec_from_file_location("red_eye", "agents/windows/Red-Eye.py")
        red_eye = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(red_eye)
        
        red_eye.reset_telemetry_state()
        
        self.assertEqual(red_eye.CURRENT_BACKOFF, 0)
        self.assertEqual(red_eye.NEXT_RETRY_TIME, 0.0)
        
        # 1. First failure -> 60s (1 min)
        red_eye.handle_network_failure()
        self.assertEqual(red_eye.CURRENT_BACKOFF, 60)
        self.assertGreater(red_eye.NEXT_RETRY_TIME, 0.0)
        
        # 2. Second failure -> 120s (2 min)
        red_eye.handle_network_failure()
        self.assertEqual(red_eye.CURRENT_BACKOFF, 120)
        
        # 3. Third failure -> 240s (4 min)
        red_eye.handle_network_failure()
        self.assertEqual(red_eye.CURRENT_BACKOFF, 240)
        
        # 4. Fourth failure -> 480s (8 min)
        red_eye.handle_network_failure()
        self.assertEqual(red_eye.CURRENT_BACKOFF, 480)
        
        # 5. Fifth failure -> 960s (16 min)
        red_eye.handle_network_failure()
        self.assertEqual(red_eye.CURRENT_BACKOFF, 960)
        
        # 6. Sixth failure -> capped at 960s (16 min)
        red_eye.handle_network_failure()
        self.assertEqual(red_eye.CURRENT_BACKOFF, 960)
        
        # 7. Success -> Reset to 0
        red_eye.handle_network_success()
        self.assertEqual(red_eye.CURRENT_BACKOFF, 0)
        self.assertEqual(red_eye.NEXT_RETRY_TIME, 0.0)

    def test_policy_api(self):
        """Verifies EDR Policy API authentication, response format, and agent synchronization."""
        # 1. Register agent
        reg_payload = {
            "hostname": "policy-host",
            "username": "policy-user",
            "os_version": "Windows 10 Pro",
            "agent_version": "1.0.0",
            "tags": [],
            "group": "default"
        }
        reg_data = self.client.post("/api/v1/agents/register", json=reg_payload).json()
        agent_id = reg_data["agent_id"]
        token = reg_data["token"]

        # 2. Get policy without token
        response = self.client.get("/api/v1/policies")
        self.assertIn(response.status_code, [401, 403])

        # 3. Get policy with token
        response = self.client.get("/api/v1/policies", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("suspicious_keywords", data)
        self.assertIn("steam", data["suspicious_keywords"])

        # 4. Verify agent's fetch_policy updates global SUSPICIOUS_KEYWORDS
        import importlib.util
        spec = importlib.util.spec_from_file_location("red_eye", "agents/windows/Red-Eye.py")
        red_eye = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(red_eye)
        
        red_eye.reset_telemetry_state()
        
        # Verify default list has steam, discord, etc.
        self.assertIn("steam", red_eye.SUSPICIOUS_KEYWORDS)
        
        # Mock requests.get inside Red-Eye to return custom list of keywords
        import requests
        original_get = requests.get
        class MockResponse:
            def __init__(self, json_data, status_code):
                self.json_data = json_data
                self.status_code = status_code
            def json(self):
                return self.json_data
                
        def mock_get(url, headers=None, timeout=None):
            return MockResponse({"suspicious_keywords": ["malware.exe", "mimikatz"]}, 200)
            
        requests.get = mock_get
        try:
            red_eye.fetch_policy("http://localhost:8000", "mocktoken")
            self.assertEqual(red_eye.SUSPICIOUS_KEYWORDS, {"malware.exe", "mimikatz"})
        finally:
            requests.get = original_get

    def test_config_json_management(self):
        """Verifies loading, saving, fallback defaults and registration tenant processing."""
        import importlib.util
        spec = importlib.util.spec_from_file_location("red_eye", "agents/windows/Red-Eye.py")
        red_eye = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(red_eye)
        
        red_eye.reset_telemetry_state()
        
        # 1. Verify load_config produces defaults and saves config.json
        config = red_eye.load_config()
        self.assertEqual(config["server_url"], "http://192.168.1.63:8000")
        self.assertEqual(config["tenant"], "default")
        self.assertIsNone(config["agent_uuid"])
        
        # 2. Modify and save config
        config["tenant"] = "custom-tenant"
        config["server_url"] = "http://custom-soc:9000"
        red_eye.save_config(config)
        
        # 3. Reload config and verify changes
        reloaded = red_eye.load_config()
        self.assertEqual(reloaded["tenant"], "custom-tenant")
        self.assertEqual(reloaded["server_url"], "http://custom-soc:9000")
        
        # 4. Verify backend registration maps tenant payload parameter onto the DB group_name
        reg_payload = {
            "hostname": "config-host",
            "username": "config-user",
            "os_version": "Windows 10 Pro",
            "agent_version": "1.0.0",
            "tags": [],
            "group": "default",
            "tenant": "enterprise-ops-group"
        }
        response = self.client.post("/api/v1/agents/register", json=reg_payload)
        self.assertEqual(response.status_code, 201)
        
        # Query DB directly to verify mapping
        agent = self.db.query(models.Agent).filter(models.Agent.hostname == "config-host").first()
        self.assertIsNotNone(agent)
        self.assertEqual(agent.group_name, "enterprise-ops-group")

    def test_agent_auto_update(self):
        """Verifies auto-update detection on version mismatch, file download, and reload trigger."""
        import importlib.util
        spec = importlib.util.spec_from_file_location("red_eye", "agents/windows/Red-Eye.py")
        red_eye = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(red_eye)
        
        red_eye.reset_telemetry_state()
        
        # 1. Register agent
        reg_payload = {
            "hostname": "update-host",
            "username": "update-user",
            "os_version": "Windows 11 Enterprise",
            "agent_version": "1.0.0",
            "tags": [],
            "group": "Monitoring"
        }
        reg_res = self.client.post("/api/v1/agents/register", json=reg_payload)
        self.assertEqual(reg_res.status_code, 201)
        data = reg_res.json()
        agent_id = data["agent_id"]
        token = data["token"]
        
        # 2. Ping agent with version mismatch ("1.0.0" vs server default "2.0.0")
        ping_payload = {
            "agent_id": agent_id,
            "cpu_usage": 15.5,
            "ram_usage": 45.2,
            "status": "online",
            "agent_version": "1.0.0"
        }
        headers = {"Authorization": f"Bearer {token}"}
        
        # Override the latest agent version in environment to be sure it matches "2.0.0"
        os.environ["LATEST_AGENT_VERSION"] = "2.0.0"
        
        ping_res = self.client.post("/api/v1/agents/ping", json=ping_payload, headers=headers)
        self.assertEqual(ping_res.status_code, 200)
        ping_data = ping_res.json()
        self.assertTrue(ping_data["update_available"])
        self.assertEqual(ping_data["update_url"], "/api/v1/agents/download")
        
        # 3. Ping agent with matching version ("2.0.0")
        ping_payload["agent_version"] = "2.0.0"
        ping_res2 = self.client.post("/api/v1/agents/ping", json=ping_payload, headers=headers)
        self.assertEqual(ping_res2.status_code, 200)
        ping_data2 = ping_res2.json()
        self.assertFalse(ping_data2["update_available"])
        
        # 4. Download update file
        download_res = self.client.get("/api/v1/agents/download", headers=headers)
        self.assertEqual(download_res.status_code, 200)
        self.assertGreater(len(download_res.content), 0)
        
        # 5. Mock requests and check client-side send_heartbeat auto-update trigger
        import requests
        original_post = requests.post
        original_get = requests.get
        
        class MockResponse:
            def __init__(self, json_data, status_code, content=b""):
                self._json = json_data
                self.status_code = status_code
                self.content = content
                self.text = "Mocked text"
            def json(self):
                return self._json
                
        def mock_post(url, json=None, headers=None, timeout=None):
            if "/api/v1/agents/ping" in url or "/api/v1/windows/ping" in url:
                return MockResponse({
                    "status": "success",
                    "timestamp": "2026-06-18T10:00:00Z",
                    "latest_version": "2.0.0",
                    "update_available": True,
                    "update_url": "/api/v1/agents/download"
                }, 200)
            return original_post(url, json, headers, timeout)
            
        def mock_get(url, headers=None, timeout=None):
            if "/api/v1/agents/download" in url or "/api/v1/operator/agent/download" in url:
                return MockResponse({}, 200, content=b"# Updated Red-Eye Script")
            return original_get(url, headers, timeout)
            
        requests.post = mock_post
        requests.get = mock_get
        
        # Mock sys.argv[0] and os.execv to prevent actual file overwrite and restart
        import sys
        original_argv0 = sys.argv[0]
        dummy_file = "test_dummy_agent.py"
        with open(dummy_file, "w") as f:
            f.write("# Dummy agent script")
            
        sys.argv[0] = dummy_file
        
        execv_called = []
        original_execv = os.execv
        def mock_execv(executable, args):
            execv_called.append((executable, args))
            
        os.execv = mock_execv
        
        try:
            info = {
                "cpu_usage": 10.0,
                "ram_usage": 20.0
            }
            res = red_eye.send_heartbeat("http://localhost:8000", agent_id, token, info, "1.0.0")
            self.assertTrue(res)
            self.assertEqual(len(execv_called), 1)
            self.assertEqual(execv_called[0][0], sys.executable)
            
            with open(dummy_file, "r") as f:
                content = f.read()
            self.assertEqual(content, "# Updated Red-Eye Script")
        finally:
            requests.post = original_post
            requests.get = original_get
            sys.argv[0] = original_argv0
            os.execv = original_execv
            if os.path.exists(dummy_file):
                os.remove(dummy_file)

    def test_service_commands(self):
        """Verifies CLI argument routes for Windows Service installation configuration."""
        import importlib.util
        spec = importlib.util.spec_from_file_location("red_eye", "agents/windows/Red-Eye.py")
        red_eye = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(red_eye)
        
        # Mock run_win_service_installer to trace action routing
        actions_called = []
        original_installer = red_eye.run_win_service_installer
        
        def mock_installer(action):
            actions_called.append(action)
            return True
            
        red_eye.run_win_service_installer = mock_installer
        
        # Force platform.system to Linux to avoid Windows UAC self-elevation check triggering exit(0)
        import platform as plat
        original_system = red_eye.platform.system
        red_eye.platform.system = lambda: "Linux"
        original_plat_system = plat.system
        plat.system = lambda: "Linux"
        
        # Test CLI routes
        import sys
        original_argv = sys.argv
        try:
            sys.argv = ["Red-Eye.py", "--install"]
            red_eye.main()
            self.assertIn("install", actions_called)
            
            sys.argv = ["Red-Eye.py", "--start"]
            red_eye.main()
            self.assertIn("start", actions_called)
            
            sys.argv = ["Red-Eye.py", "--stop"]
            red_eye.main()
            self.assertIn("stop", actions_called)
            
            sys.argv = ["Red-Eye.py", "--remove"]
            red_eye.main()
            self.assertIn("remove", actions_called)
        finally:
            sys.argv = original_argv
            red_eye.run_win_service_installer = original_installer
            red_eye.platform.system = original_system
            plat.system = original_plat_system

    def test_dynamic_policy_admin(self):
        """Verifies policy rule addition, deletion, dynamic persistence, and synchronization."""
        # 1. Check initial empty policies auto seeding
        reg_payload = {
            "hostname": "policy-host",
            "username": "policy-user",
            "os_version": "Windows 11 Pro",
            "agent_version": "1.0.0",
            "tags": [],
            "group": "Monitoring"
        }
        reg_res = self.client.post("/api/v1/agents/register", json=reg_payload)
        self.assertEqual(reg_res.status_code, 201)
        data = reg_res.json()
        agent_id = data["agent_id"]
        token = data["token"]
        
        headers = {"Authorization": f"Bearer {token}"}
        get_res = self.client.get("/api/v1/policies", headers=headers)
        self.assertEqual(get_res.status_code, 200)
        policy_data = get_res.json()
        self.assertIn("steam", policy_data["suspicious_keywords"])
        
        # 2. Add a new policy keyword
        add_payload = {"keyword": "miner"}
        add_res = self.client.post("/api/v1/policies", json=add_payload)
        self.assertEqual(add_res.status_code, 201)
        add_data = add_res.json()
        self.assertEqual(add_data["keyword"], "miner")
        self.assertEqual(add_data["status"], "created")
        
        # 3. Verify added keyword in list
        get_res2 = self.client.get("/api/v1/policies", headers=headers)
        self.assertEqual(get_res2.status_code, 200)
        self.assertIn("miner", get_res2.json()["suspicious_keywords"])
        
        # 4. Try adding duplicate keyword
        add_res2 = self.client.post("/api/v1/policies", json=add_payload)
        self.assertEqual(add_res2.status_code, 201)
        self.assertEqual(add_res2.json()["status"], "exists")
        
        # 5. Delete keyword
        del_res = self.client.delete("/api/v1/policies/miner")
        self.assertEqual(del_res.status_code, 204)
        
        # 6. Verify deletion from list
        get_res3 = self.client.get("/api/v1/policies", headers=headers)
        self.assertEqual(get_res3.status_code, 200)
        self.assertNotIn("miner", get_res3.json()["suspicious_keywords"])

    def test_local_logging(self):
        """Verifies local rotating logging outputs correct formatting and level constraints."""
        import importlib.util
        spec = importlib.util.spec_from_file_location("red_eye", "agents/windows/Red-Eye.py")
        red_eye = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(red_eye)
        
        import tempfile
        import shutil
        temp_log_dir = tempfile.mkdtemp()
        
        # Mock platform.system to Windows to test logger path resolution logic
        original_system = red_eye.platform.system
        red_eye.platform.system = lambda: "Windows"
        
        # Also mock locally-imported plat system inside function scope
        import platform as plat
        original_plat_system = plat.system
        plat.system = lambda: "Windows"
        
        original_environ = red_eye.os.environ
        red_eye.os.environ = dict(original_environ)
        red_eye.os.environ["ProgramData"] = temp_log_dir
        
        try:
            import logging
            for h in list(logging.getLogger("RedEyeAgent").handlers):
                h.close()
            logging.getLogger("RedEyeAgent").handlers.clear()
            red_eye.LOGGER = None  # Reset singleton
            red_eye.setup_local_logging()
            
            # Log messages
            red_eye.log_info("Testing local info log entry")
            red_eye.log_warning("Testing local warning log entry")
            red_eye.log_error("Testing local error log entry")
            
            # Verify file exists and logs were written
            expected_log_path = os.path.join(temp_log_dir, "RedEye", "logs", "redeye_agent.log")
            self.assertTrue(os.path.exists(expected_log_path))
            
            with open(expected_log_path, "r") as f:
                content = f.read()
                
            self.assertIn("[INFO] Testing local info log entry", content)
            self.assertIn("[WARNING] Testing local warning log entry", content)
            self.assertIn("[ERROR] Testing local error log entry", content)
        finally:
            import logging
            for h in list(logging.getLogger("RedEyeAgent").handlers):
                h.close()
            logging.getLogger("RedEyeAgent").handlers.clear()
            red_eye.platform.system = original_system
            plat.system = original_plat_system
            red_eye.os.environ = original_environ
            shutil.rmtree(temp_log_dir)

    def test_integrity_validation(self):
        """Verifies server side integrity validation and auto-update verification."""
        reg_payload = {
            "hostname": "integrity-host",
            "username": "integrity-user",
            "os_version": "Windows 11",
            "agent_version": "2.0.0",
            "tags": [],
            "group": "default"
        }
        reg_res = self.client.post("/api/v1/agents/register", json=reg_payload)
        self.assertEqual(reg_res.status_code, 201)
        reg_data = reg_res.json()
        agent_id = reg_data["agent_id"]
        token = reg_data["token"]
        
        import hashlib
        file_path = "agents/windows/Red-Eye.py"
        if not os.path.exists(file_path):
            file_path = os.path.join(os.path.dirname(__file__), "..", "agents", "windows", "Red-Eye.py")
        expected_checksum = ""
        if os.path.exists(file_path):
            with open(file_path, "rb") as f:
                expected_checksum = hashlib.sha256(f.read()).hexdigest()
                
        ping_payload = {
            "agent_id": agent_id,
            "cpu_usage": 10.5,
            "ram_usage": 45.2,
            "status": "online",
            "agent_version": "2.0.0",
            "checksum": expected_checksum
        }
        
        headers = {"Authorization": f"Bearer {token}"}
        ping_res = self.client.post("/api/v1/agents/ping", json=ping_payload, headers=headers)
        self.assertEqual(ping_res.status_code, 200)
        self.assertFalse(ping_res.json()["update_available"])
        
        ping_payload["checksum"] = "mismatched-tampered-checksum"
        ping_res_mismatch = self.client.post("/api/v1/agents/ping", json=ping_payload, headers=headers)
        self.assertEqual(ping_res_mismatch.status_code, 200)
        mismatch_data = ping_res_mismatch.json()
        self.assertTrue(mismatch_data["update_available"])
        self.assertEqual(mismatch_data["expected_checksum"], expected_checksum)
        
        db = TestingSessionLocal()
        try:
            violation = db.query(models.ExamViolation).filter(
                models.ExamViolation.agent_id == uuid.UUID(agent_id),
                models.ExamViolation.violation_type == "Host Agent Modification Detected"
            ).first()
            self.assertIsNotNone(violation)
            self.assertEqual(violation.severity, "HIGH")
        finally:
            db.close()

    def test_gzip_middleware(self):
        """Verifies GzipRequestMiddleware decompresses incoming payloads successfully."""
        reg_payload = {
            "hostname": "gzip-host",
            "username": "gzip-user",
            "os_version": "Windows 11",
            "agent_version": "2.0.0",
            "tags": [],
            "group": "default"
        }
        reg_res = self.client.post("/api/v1/agents/register", json=reg_payload)
        self.assertEqual(reg_res.status_code, 201)
        reg_data = reg_res.json()
        agent_id = reg_data["agent_id"]
        token = reg_data["token"]
        
        telemetry_payload = {
            "agent_id": agent_id,
            "timestamp": "2026-06-18T12:00:00Z",
            "system_info": {
                "hostname": "gzip-host",
                "username": "gzip-user",
                "os_version": "Windows 10 Pro",
                "ip_address": "192.168.1.10",
                "mac_address": "AA:BB:CC:DD:EE:FF",
                "cpu_usage": 10.0,
                "ram_usage": 20.0,
                "disk_usage": 50.0,
                "uptime": 3600
            },
            "user_activity": {"recent_audit_events": [], "last_logged_in_user": "gzip-user"},
            "security_status": {"antivirus_status": "Active", "firewall_status": "On", "privilege_escalation_warnings": []},
            "processes": {"running_processes_count": 0, "sample_processes": [], "suspicious_processes": []},
            "installed_software": {"installed_applications_count": 0, "software_list": []},
            "usb_devices": {"connected_usb_devices": []},
            "network": {"active_connections_count": 0, "listening_ports": [], "connections_sample": [], "vpn_active": False},
            "threats": {"security_alerts": []},
            "exam_integrity": {"violations_found": False, "violations": [], "vpn_enabled": False, "rdp_active": False}
        }
        
        import gzip
        import json
        compressed = gzip.compress(json.dumps(telemetry_payload).encode('utf-8'))
        
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Encoding": "gzip",
            "Content-Type": "application/json"
        }
        
        response = self.client.post("/api/v1/telemetry/submit", content=compressed, headers=headers)
        self.assertEqual(response.status_code, 200)
        self.assertIn("processed_records", response.json())

    def test_rate_limiting(self):
        """Verifies rate-limiting rejects requests after exceeding limits."""
        from backend.main import RATE_LIMIT_RECORD
        RATE_LIMIT_RECORD.clear()
        
        original_testing = os.environ.get("TESTING")
        if "TESTING" in os.environ:
            del os.environ["TESTING"]
            
        try:
            from backend.main import rate_limiter
            from fastapi import Request, HTTPException
            
            class MockClient:
                def __init__(self, host):
                    self.host = host
            class MockRequest:
                def __init__(self, host):
                    self.client = MockClient(host)
                    
            limiter_dep = rate_limiter(max_requests=3, window=10.0)
            req = MockRequest("192.168.1.63")
            
            limiter_dep(req)
            limiter_dep(req)
            limiter_dep(req)
            
            with self.assertRaises(HTTPException) as ctx:
                limiter_dep(req)
            self.assertEqual(ctx.exception.status_code, 429)
            self.assertEqual(ctx.exception.detail, "Rate limit exceeded. Too many requests.")
            
        finally:
            if original_testing is not None:
                os.environ["TESTING"] = original_testing

    def test_operator_endpoints_and_commands(self):
        """Tests custom operator endpoints and client command polling loop."""
        # 1. Register agent
        reg_payload = {
            "hostname": "operator-test-host",
            "username": "op-user",
            "platform": "Windows",
            "os_version": "10.0.19045",
            "agent_version": "1.0.0",
            "department": "IT Security",
            "tags": ["critical", "active"],
            "group_name": "servers",
            "tenant": "default"
        }
        res = self.client.post("/api/v1/agents/register", json=reg_payload)
        self.assertEqual(res.status_code, 201)
        data = res.json()
        agent_id = data["agent_id"]
        secret = data["secret"]
        
        # Authenticate and get token
        auth_payload = {"agent_id": agent_id, "secret": secret}
        res = self.client.post("/api/v1/agents/token", json=auth_payload)
        self.assertEqual(res.status_code, 200)
        token = res.json()["token"]
        headers = {"Authorization": f"Bearer {token}"}
        
        # 2. Verify Operator get agents list
        res = self.client.get("/api/v1/operator/agents")
        self.assertEqual(res.status_code, 200)
        agents = res.json()
        self.assertTrue(any(a["id"] == agent_id for a in agents))
        
        # 3. Verify Operator get agent detail
        res = self.client.get(f"/api/v1/operator/agents/{agent_id}")
        self.assertEqual(res.status_code, 200)
        detail = res.json()
        self.assertEqual(detail["agent"]["hostname"], "operator-test-host")
        
        # 4. Operator queue a command for the agent
        cmd_payload = {"command_text": "dir C:\\"}
        res = self.client.post(f"/api/v1/operator/agents/{agent_id}/command", json=cmd_payload)
        self.assertEqual(res.status_code, 201)
        cmd_data = res.json()
        command_id = cmd_data["id"]
        self.assertEqual(cmd_data["command_text"], "dir C:\\")
        self.assertEqual(cmd_data["status"], "pending")
        
        # 5. Agent polls for pending commands
        res = self.client.get(f"/api/v1/agents/{agent_id}/commands/pending", headers=headers)
        self.assertEqual(res.status_code, 200)
        pending_cmds = res.json()
        self.assertEqual(len(pending_cmds), 1)
        self.assertEqual(pending_cmds[0]["id"], command_id)
        
        # Verify status became 'sent' on operator side
        res = self.client.get(f"/api/v1/operator/agents/{agent_id}/commands")
        self.assertEqual(res.status_code, 200)
        cmds_history = res.json()
        self.assertEqual(cmds_history[0]["status"], "sent")
        
        # 6. Agent responds to command execution
        resp_payload = {
            "response_text": "Directory of C:\\\nWindows\nProgram Files",
            "status": "completed"
        }
        res = self.client.post(f"/api/v1/commands/{command_id}/respond", json=resp_payload, headers=headers)
        self.assertEqual(res.status_code, 200)
        
        # Verify command updated in operator history
        res = self.client.get(f"/api/v1/operator/agents/{agent_id}/commands")
        self.assertEqual(res.status_code, 200)
        cmds_history = res.json()
        self.assertEqual(cmds_history[0]["status"], "completed")
        self.assertEqual(cmds_history[0]["response_text"], "Directory of C:\\\nWindows\nProgram Files")

        # 7. Operator deletes/removes the agent
        res = self.client.delete(f"/api/v1/operator/agents/{agent_id}")
        self.assertEqual(res.status_code, 204)

        # Verify agent is gone from DB
        res = self.client.get(f"/api/v1/operator/agents/{agent_id}")
        self.assertEqual(res.status_code, 404)

        # Verify heartbeat from deleted agent returns 404
        ping_payload = {
            "agent_id": agent_id,
            "cpu_usage": 5.5,
            "ram_usage": 32.2,
            "status": "online",
            "agent_version": "1.0.0"
        }
        res = self.client.post("/api/v1/agents/ping", json=ping_payload, headers=headers)
        self.assertEqual(res.status_code, 404)

    def test_android_apps_sync_and_heuristics(self):
        """Verifies Android apps sync payload ingestion, risk heuristics, and serialization."""
        # 1. Sync Android apps payload
        sync_payload = {
            "device_id": "test-android-device-123",
            "apps": [
                {
                    "app_name": "System Update",
                    "package_name": "com.android.system.update",
                    "version_name": "2.4.1",
                    "version_code": 25,
                    "install_time": "1710000000000",
                    "update_time": "1710000010000",
                    "system_app": False,
                    "enabled": True,
                    "installer": "Unknown",
                    "target_sdk": 33,
                    "certificate": "SHA256:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF",
                    "requested_permissions": ["android.permission.READ_SMS", "android.permission.BIND_ACCESSIBILITY_SERVICE"],
                    "services": ["com.android.system.update.MainService"],
                    "receivers": ["com.android.system.update.BootReceiver"],
                    "exported_components_count": 2,
                    "has_accessibility": True,
                    "has_device_admin": False,
                    "has_foreground_service": True,
                    "has_overlay": True,
                    "has_boot_receiver": True,
                    "read_sms_granted": True,
                    "read_contacts_granted": False,
                    "camera_granted": True,
                    "record_audio_granted": False,
                    "keylogger_detected": True,
                    "has_battery_exemption": True,
                    "persistence_score": 3,
                    "accessibility_service_name": "com.android.system.update.MyAccessibilityService",
                    "accessibility_service_enabled": True,
                    "accessibility_capabilities": ["retrieve_window_content", "touch_exploration"],
                    "overlay_granted": True,
                    "device_admin_active": True,
                    "is_device_owner": False,
                    "is_profile_owner": False
                },
                {
                    "app_name": "Trusted Tool",
                    "package_name": "com.trusted.tool",
                    "version_name": "1.0.0",
                    "version_code": 1,
                    "install_time": "1710000000000",
                    "update_time": "1710000000000",
                    "system_app": False,
                    "enabled": True,
                    "installer": "Unknown",
                    "target_sdk": 33,
                    "certificate": "SHA256:3B:8D:1F:6A:B2:A1:C9:D0:5E:F6:71:02:83:94:A5:B6:C7:D8:E9:F0:A1:B2:C3:D4:E5:F6:07:08:09:0A:0B:C0",
                    "requested_permissions": [],
                    "services": [],
                    "receivers": [],
                    "exported_components_count": 0,
                    "has_accessibility": True,
                    "has_device_admin": False,
                    "has_foreground_service": False,
                    "has_overlay": True,
                    "has_boot_receiver": False,
                    "read_sms_granted": False,
                    "read_contacts_granted": False,
                    "camera_granted": False,
                    "record_audio_granted": False,
                    "keylogger_detected": False,
                    "has_battery_exemption": False,
                    "persistence_score": 0,
                    "accessibility_service_name": "com.trusted.tool.Service",
                    "accessibility_service_enabled": True,
                    "accessibility_capabilities": [],
                    "overlay_granted": True,
                    "device_admin_active": False,
                    "is_device_owner": False,
                    "is_profile_owner": False
                }
            ]
        }
        
        response = self.client.post("/api/android/apps/sync", json=sync_payload)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "success")
        
        # 2. Retrieve Android apps using general get endpoint
        response = self.client.get("/api/android/apps")
        self.assertEqual(response.status_code, 200)
        apps = response.json()["apps"]
        self.assertTrue(len(apps) >= 2)
        test_app = [a for a in apps if a["package_name"] == "com.android.system.update"][0]
        test_app2 = [a for a in apps if a["package_name"] == "com.trusted.tool"][0]
        
        # Verify persistence scoring, risk heuristics, and permission statuses
        self.assertEqual(test_app["risk_level"], "red") # Accessibility + Overlay
        self.assertEqual(test_app["read_sms_granted"], True)
        self.assertEqual(test_app["read_contacts_granted"], False)
        self.assertEqual(test_app["camera_granted"], True)
        self.assertEqual(test_app["record_audio_granted"], False)
        self.assertEqual(test_app["keylogger_detected"], True)
        self.assertEqual(test_app["has_battery_exemption"], True)
        self.assertEqual(test_app["persistence_score"], 3)
        self.assertEqual(test_app["certificate"], "SHA256:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF")
        self.assertEqual(test_app["accessibility_service_name"], "com.android.system.update.MyAccessibilityService")
        self.assertEqual(test_app["accessibility_service_enabled"], True)
        self.assertEqual(test_app["accessibility_capabilities"], ["retrieve_window_content", "touch_exploration"])
        self.assertEqual(test_app["overlay_granted"], True)
        self.assertEqual(test_app["device_admin_active"], True)
        self.assertEqual(test_app["is_device_owner"], False)
        self.assertEqual(test_app["is_profile_owner"], False)
        self.assertEqual(test_app["certificate_reputation"], "malicious")

        # Verify Trusted publisher risk level downgrading (red -> yellow)
        self.assertEqual(test_app2["risk_level"], "yellow") # Normally red due to both accessibility & overlay, but signature is trusted
        self.assertEqual(test_app2["certificate_reputation"], "trusted")
        self.assertEqual(test_app2["device_admin_active"], False)
        self.assertEqual(test_app2["is_device_owner"], False)
        self.assertEqual(test_app2["is_profile_owner"], False)

        # 3. Retrieve Android apps by device ID
        response = self.client.get("/api/android/apps/test-android-device-123")
        self.assertEqual(response.status_code, 200)
        device_apps = response.json()["apps"]
        self.assertEqual(len(device_apps), 2)

    def test_whitelisting_and_auto_whitelisting(self):
        """Verifies local whitelisting file cache and automated VirusTotal clean-result whitelisting."""
        import os
        import json
        backend_dir = os.path.dirname(os.path.abspath(__file__))
        redeye_root = os.path.dirname(backend_dir)
        whitelist_file = os.path.join(redeye_root, "malware_free.json")
        
        # Backup original if exists
        original_content = None
        if os.path.exists(whitelist_file):
            try:
                with open(whitelist_file, "r") as f:
                    original_content = f.read()
            except Exception:
                pass
                
        # Write test whitelist content
        test_hash = "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff"
        with open(whitelist_file, "w") as f:
            json.dump([test_hash], f)
            
        try:
            # Sync an app that matches the whitelist hash
            sync_payload = {
                "device_id": "test-device-whitelist",
                "apps": [
                    {
                        "app_name": "Government App",
                        "package_name": "gov.in.app",
                        "version_name": "1.0",
                        "version_code": 1,
                        "install_time": "1710000000000",
                        "update_time": "1710000000000",
                        "system_app": False,
                        "enabled": True,
                        "installer": "Unknown",
                        "target_sdk": 33,
                        "certificate": "SHA256:11:22",
                        "apk_sha256": test_hash,
                        "requested_permissions": [],
                        "services": [],
                        "receivers": [],
                        "exported_components_count": 0,
                        "has_accessibility": True,  # Would normally score high
                        "has_device_admin": True,
                        "has_foreground_service": False,
                        "has_overlay": True,
                        "has_boot_receiver": False,
                        "read_sms_granted": False,
                        "read_contacts_granted": False,
                        "camera_granted": False,
                        "record_audio_granted": False,
                        "keylogger_detected": False,
                        "has_battery_exemption": False,
                        "persistence_score": 0,
                        "accessibility_service_name": "",
                        "accessibility_service_enabled": False,
                        "accessibility_capabilities": [],
                        "overlay_granted": False,
                        "device_admin_active": False,
                        "is_device_owner": False,
                        "is_profile_owner": False
                    }
                ]
            }
            
            response = self.client.post("/api/android/apps/sync", json=sync_payload)
            self.assertEqual(response.status_code, 200)
            
            # Retrieve and assert threat score is 0 and category is whitelisted
            response = self.client.get("/api/android/apps/test-device-whitelist")
            self.assertEqual(response.status_code, 200)
            apps = response.json()["apps"]
            self.assertEqual(len(apps), 1)
            self.assertEqual(apps[0]["threat_score"], 0)
            self.assertEqual(apps[0]["threat_category"], "Safe / Trusted App (Local Whitelist)")
            self.assertEqual(apps[0]["risk_level"], "green")
            
        finally:
            # Restore original whitelist
            if original_content is not None:
                with open(whitelist_file, "w") as f:
                    f.write(original_content)
            elif os.path.exists(whitelist_file):
                os.remove(whitelist_file)

    def test_windows_telemetry_ingestion(self):
        """Verifies ingestion of Windows telemetry payloads with threat score, reasons, and classification."""
        # 1. Register a Windows agent
        reg_payload = {
            "hostname": "win-agent-test",
            "username": "win-user",
            "os_version": "Windows 11 Enterprise",
            "agent_version": "1.0.0",
            "tags": ["windows", "test"],
            "group": "Monitoring"
        }
        reg_res = self.client.post("/api/v1/agents/register", json=reg_payload)
        self.assertEqual(reg_res.status_code, 201)
        data = reg_res.json()
        agent_id = data["agent_id"]
        token = data["token"]
        
        headers = {"Authorization": f"Bearer {token}"}
        
        # 2. Submit telemetry payload with Windows processes
        telemetry_payload = {
            "agent_id": agent_id,
            "timestamp": "2026-06-18T12:00:00Z",
            "system_info": {
                "hostname": "win-agent-test",
                "username": "win-user",
                "os_version": "Windows 11 Enterprise",
                "ip_address": "192.168.1.15",
                "mac_address": "BB:CC:DD:EE:FF:00",
                "cpu_usage": 15.0,
                "ram_usage": 35.0,
                "disk_usage": 60.0,
                "uptime": 7200
            },
            "user_activity": {"recent_audit_events": [], "last_logged_in_user": "win-user"},
            "security_status": {"antivirus_status": "Active", "firewall_status": "On", "privilege_escalation_warnings": []},
            "processes": {
                "running_processes_count": 2,
                "sample_processes": [
                    {
                        "pid": 4124,
                        "name": "malicious.exe",
                        "parent_pid": 1000,
                        "parent_process": "explorer.exe",
                        "user": "win-user",
                        "cpu": 2.5,
                        "mem": 1.2,
                        "executable_path": "C:\\Users\\win-user\\AppData\\Local\\Temp\\malicious.exe",
                        "command_line": "malicious.exe --payload",
                        "sha256_hash": "223344556677889900aabbccddeeff11223344556677889900aabbccddeeff",
                        "threat_score": 75,
                        "threat_reasons": ["Unsigned EXE in AppData/Temp", "Disables UAC/Firewall/Updates"],
                        "threat_classification": "High Risk"
                    },
                    {
                        "pid": 500,
                        "name": "svchost.exe",
                        "parent_pid": 400,
                        "parent_process": "services.exe",
                        "user": "SYSTEM",
                        "cpu": 0.1,
                        "mem": 0.5,
                        "executable_path": "C:\\Windows\\System32\\svchost.exe",
                        "command_line": "C:\\Windows\\system32\\svchost.exe -k netsvcs",
                        "sha256_hash": "3344556677889900aabbccddeeff11223344556677889900aabbccddeeff",
                        "threat_score": 10,
                        "threat_reasons": [],
                        "threat_classification": "Clean"
                    }
                ],
                "suspicious_processes": []
            },
            "installed_software": {"installed_applications_count": 0, "software_list": []},
            "usb_devices": {"connected_usb_devices": []},
            "network": {"active_connections_count": 0, "listening_ports": [], "connections_sample": [], "vpn_active": False},
            "threats": {"security_alerts": []},
            "exam_integrity": {"violations_found": False, "violations": [], "vpn_enabled": False, "rdp_active": False}
        }
        
        response = self.client.post("/api/v1/telemetry/submit", json=telemetry_payload, headers=headers)
        self.assertEqual(response.status_code, 200)
        
        # 3. Query DB to verify processes and threat fields
        db = TestingSessionLocal()
        try:
            # Check malicious process
            proc_mal = db.query(models.ProcessEvent).filter(
                models.ProcessEvent.agent_id == uuid.UUID(agent_id),
                models.ProcessEvent.process_name == "malicious.exe"
            ).first()
            self.assertIsNotNone(proc_mal)
            self.assertEqual(proc_mal.threat_score, 75)
            self.assertEqual(proc_mal.threat_classification, "High Risk")
            reasons = json.loads(proc_mal.threat_reasons)
            self.assertIn("Unsigned EXE in AppData/Temp", reasons)
            
            # Check svchost clean process
            proc_clean = db.query(models.ProcessEvent).filter(
                models.ProcessEvent.agent_id == uuid.UUID(agent_id),
                models.ProcessEvent.process_name == "svchost.exe"
            ).first()
            self.assertIsNotNone(proc_clean)
            self.assertEqual(proc_clean.threat_score, 10)
            self.assertEqual(proc_clean.threat_classification, "Clean")
            
            # Verify backend alert is generated for the process with threat score >= 60
            alert = db.query(models.Alert).filter(
                models.Alert.agent_id == uuid.UUID(agent_id),
                models.Alert.category == "Threat Detection"
            ).first()
            self.assertIsNotNone(alert)
            self.assertEqual(alert.severity, "HIGH")
            self.assertIn("Windows Threat Detected: malicious.exe", alert.message)
            self.assertIn("Unsigned EXE in AppData/Temp", alert.evidence)
            
        finally:
            db.close()

    @patch("requests.post")
    @patch("backend.main.query_threat_intel")
    def test_file_reputation_upload_flow(self, mock_query, mock_post):
        # 1. Register a Windows agent
        reg_payload = {
            "hostname": "win-reputation-test",
            "username": "win-user",
            "os_version": "Windows 11 Enterprise",
            "agent_version": "1.0.0",
            "tags": ["windows", "test"],
            "group": "Monitoring"
        }
        reg_res = self.client.post("/api/v1/agents/register", json=reg_payload)
        self.assertEqual(reg_res.status_code, 201)
        data = reg_res.json()
        agent_id = data["agent_id"]
        token = data["token"]
        
        headers = {"Authorization": f"Bearer {token}"}
        
        # 2. Check reputation of an unknown file hash
        unknown_sha256 = "1234567890123456789012345678901234567890123456789012345678901234"
        check_payload = {
            "agent_id": agent_id,
            "file_path": "C:\\temp\\unknown.exe",
            "file_name": "unknown.exe",
            "sha1": "1234567890123456789012345678901234567890",
            "sha256": unknown_sha256,
            "file_size": 100
        }
        
        # Mock query_threat_intel to return 0/0 and False for unknown file
        mock_query.return_value = ("0/0", False)
        
        res = self.client.post("/api/v1/windows/file-reputation/check", json=check_payload, headers=headers)
        self.assertEqual(res.status_code, 200)
        res_data = res.json()
        self.assertEqual(res_data["verdict"], "unknown")
        self.assertTrue(res_data["upload_required"])
        
        # 3. Perform file upload proxying to VirusTotal
        import io
        file_content = b"MZ\x90\x00\x03\x00\x00\x00"  # mock PE header
        import hashlib
        real_sha256 = hashlib.sha256(file_content).hexdigest()
        
        # Setup VT mock response
        mock_vt_response = MagicMock()
        mock_vt_response.status_code = 200
        mock_vt_response.json.return_value = {"data": {"id": "mock_analysis_id"}}
        mock_post.return_value = mock_vt_response
        
        # Setup mock_query to return malicious verdict on the second call (after upload)
        mock_query.return_value = ("5/70", False)
        
        upload_data = {
            "agent_id": agent_id,
            "sha256": real_sha256
        }
        upload_files = {
            "file": ("unknown.exe", io.BytesIO(file_content), "application/octet-stream")
        }
        
        up_res = self.client.post(
            "/api/v1/windows/file-reputation/upload",
            data=upload_data,
            files=upload_files,
            headers=headers
        )
        self.assertEqual(up_res.status_code, 200)
        up_res_data = up_res.json()
        self.assertEqual(up_res_data["status"], "success")
        self.assertEqual(up_res_data["verdict"], "malicious")
        self.assertEqual(up_res_data["vt_rate"], "5/70")

if __name__ == "__main__":
    unittest.main()
