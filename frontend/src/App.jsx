import React, { useState, useEffect, useRef } from 'react';
import {
  Server, Terminal, RefreshCw, Laptop, Cpu, Smartphone,
  Database, Send, Clock, Activity, Code, Trash2, CheckCircle2, AlertTriangle,
  Menu, ChevronLeft, ChevronRight, Info, Mail, DollarSign, LogIn, LogOut,
  AlertCircle, FileText, Check, Lock, User, Map, Settings,
  ShieldAlert, ShieldCheck, Zap, Globe, Search, Play, Pause, ChevronUp, Eye, Command, Plus
} from 'lucide-react';
import './App.css';

// Formats timestamp strings to YY-MM-DD HH:MM in local time
const formatLocalTime = (isoString) => {
  if (!isoString) return '';
  try {
    const d = new Date(isoString);
    if (isNaN(d.getTime())) return isoString;
    const pad = (num) => String(num).padStart(2, '0');
    const yyyy = d.getFullYear();
    const mm = pad(d.getMonth() + 1);
    const dd = pad(d.getDate());
    const hh = pad(d.getHours());
    const min = pad(d.getMinutes());
    const ss = pad(d.getSeconds());
    return `${dd}-${mm}-${yyyy} ${hh}:${min}:${ss}`;
  } catch (e) {
    return isoString;
  }
};

// Pre-defined system command outputs for high fidelity simulation
const MOCK_COMMAND_OUTPUTS = {
  Windows: {
    'whoami': 'redeye-client\\admin',
    'sysinfo': 'Host Name:           RE-WIN-MAIN\nOS Name:             Microsoft Windows 11 Enterprise\nOS Version:          10.0.22621 N/A Build 22621\nOS Manufacturer:     Microsoft Corporation\nSystem Type:         x64-based PC\nProcessor(s):        1 Processor(s) Installed. [01]: Intel64 Family 6 Model 158 Stepping 13 GenuineIntel ~3600 Mhz\nPhysical Memory:     16,244 MB',
    'get-process': 'Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName\n-------  ------    -----      -----     ------     --  -- ----------\n    412      24    45120      51200       1.24   1842   1  agent.exe\n   1104      48   112044     143020      12.48    840   1  explorer.exe\n    284      12     5412       9820       0.04   2904   0  lsass.exe\n    501      31    18420      24108       0.56   4120   1  svchost.exe',
    'netstat': 'Active Connections\n\n  Proto  Local Address          Foreign Address        State\n  TCP    192.168.1.104:49811    192.168.1.1:80         ESTABLISHED\n  TCP    192.168.1.104:50041    192.168.1.5:5432       ESTABLISHED\n  TCP    192.168.1.104:50112    10.0.0.12:443          ESTABLISHED',
    'shutdown': '[-] Shutdown sequence initiated: agent shutdown aborted by client rules.'
  },
  Linux: {
    'whoami': 'root',
    'uname -a': 'Linux RE-LNX-WEB 6.1.0-18-amd64 #1 SMP Debian 6.1.76-1 (2024-02-01) x86_64 GNU/Linux',
    'ps aux': 'USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\nroot           1  0.0  0.1 168244 11204 ?        Ss   Jun14   0:04 /sbin/init\nroot         842  0.1  0.8 450412 64120 ?        S    Jun14   1:12 python3 agent.py\nroot        1004  0.0  0.2  89040 18400 pts/0    Ss+  09:12   0:00 bash\nroot        1124  0.0  0.0  45120  4104 pts/0    R+   10:46   0:00 ps aux',
    'ifconfig': 'eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n        inet 192.168.1.18  netmask 255.255.255.0  broadcast 192.168.1.255\n        inet6 fe80::a00:27ff:fe8f:b512  prefixlen 64  scopeid 0x20<link>\n        ether 08:00:27:8f:b5:12  txqueuelen 1000  (Ethernet)\n        RX packets 24128  bytes 18420104 (18.4 MB)\n        TX packets 19204  bytes 2404104 (2.4 MB)\n\nlo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\n        inet 127.0.0.1  netmask 255.0.0.0',
    'shutdown': '[-] Shutdown: Shutdown is restricted to physical console access.'
  },
  Android: {
    'whoami': 'u0_a244',
    'getprop ro.product.model': 'Pixel 8 Pro',
    'pm list packages': 'package:com.android.chrome\npackage:com.google.android.youtube\npackage:com.redeye.agent\npackage:com.android.settings\npackage:com.google.android.gms',
    'sysinfo': 'Brand: Google\nModel: Pixel 8 Pro\nAndroid SDK: 34\nRelease: 14\nKernel: 6.1.25-android14-11',
    'shutdown': '[-] Operation not permitted: Superuser access required.'
  }
};

const INITIAL_AGENTS = [];

const MOCK_SYSTEM_LOGS = [];

const MOCK_ALERTS = [];

const INITIAL_EVENTS = [];

const EVENT_TEMPLATES = [
  { type: 'User Login', message: 'User admin logged in to Server PC (Web console)', source: 'Server PC', severity: 'info' },
  { type: 'User Login', message: 'User auditor logged out of Server PC', source: 'Server PC', severity: 'info' },
  { type: 'Failed Login', message: 'Failed SSH login attempt from 192.168.1.205 (user: root)', source: 'Server PC', severity: 'warning' },
  { type: 'Failed Login', message: 'Failed console authentication on Agent RE-WIN-MAIN (user: operator)', source: 'RE-WIN-MAIN', severity: 'warning' },
  { type: 'Software Install', message: 'Software installed on Agent RE-LNX-WEB: nmap-security-suite (v7.94)', source: 'RE-LNX-WEB', severity: 'info' },
  { type: 'Software Install', message: 'Software installed on Agent RE-WIN-MAIN: wireshark.msi', source: 'RE-WIN-MAIN', severity: 'warning' },
  { type: 'USB Activity', message: 'USB storage device SanDisk Ultra inserted on Agent RE-WIN-MAIN', source: 'RE-WIN-MAIN', severity: 'warning' },
  { type: 'USB Activity', message: 'USB interface disconnected on Agent RE-AND-USR', source: 'RE-AND-USR', severity: 'info' },
  { type: 'Agent Status', message: 'Agent RE-WIN-DB heartbeats timed out. Node marked OFFLINE.', source: 'RE-WIN-DB', severity: 'critical' },
  { type: 'Agent Status', message: 'Agent RE-LNX-WEB established connection link. Node marked ONLINE.', source: 'RE-LNX-WEB', severity: 'info' },
  { type: 'Firewall Change', message: 'Router Edge-RT-01 ruleset updated: Block inbound traffic on port 21', source: 'Router-01', severity: 'warning' },
  { type: 'Firewall Change', message: 'Switch Switch-02 VLAN policy changed: Restricted port access', source: 'Switch-02', severity: 'warning' },
  { type: 'Port Change', message: 'Open port change detected on Agent RE-LNX-WEB: Port 22 (SSH) opened', source: 'RE-LNX-WEB', severity: 'warning' },
  { type: 'Port Change', message: 'Port scan audit on Server PC: Port 5432 (PostgreSQL) declared secure', source: 'Server PC', severity: 'info' },
  { type: 'Suspicious Network', message: 'Suspicious outbound connection detected to IP 185.220.101.5 on Agent RE-WIN-MAIN', source: 'RE-WIN-MAIN', severity: 'critical' },
  { type: 'Suspicious Network', message: 'Port sweep scan activity originating from Agent RE-LNX-WEB targeted at 10.0.0.1/24', source: 'RE-LNX-WEB', severity: 'critical' },
  { type: 'New Alert', message: 'New Alert: Alert threshold triggered - RAM pagination exceeded 90% on Server PC', source: 'Server PC', severity: 'critical' },
  { type: 'New Alert', message: 'New Alert: System integrity validation failed for agent daemon on Agent RE-AND-USR', source: 'RE-AND-USR', severity: 'critical' }
];

const getSvgPath = (data) => {
  const width = 500;
  const height = 150;
  const step = width / (data.length - 1);
  const points = data.map((val, idx) => {
    const x = idx * step;
    const y = height - (val / 100) * height;
    return `${x},${y}`;
  });
  return `M ${points.join(' L ')}`;
};

const getSvgAreaPath = (data) => {
  const width = 500;
  const height = 150;
  const step = width / (data.length - 1);
  const points = data.map((val, idx) => {
    const x = idx * step;
    const y = height - (val / 100) * height;
    return `${x},${y}`;
  });
  return `M 0,${height} L ${points.join(' L ')} L ${width},${height} Z`;
};

const getPlatformIcon = (platform) => {
  const p = (platform || '').toLowerCase();
  if (p === 'windows') {
    return <Laptop size={14} style={{ color: '#00adef' }} title="Windows" />;
  } else if (p === 'android') {
    return <Smartphone size={14} style={{ color: '#3ddc84' }} title="Android" />;
  } else if (p === 'linux') {
    return <Cpu size={14} style={{ color: '#f8b739' }} title="Linux" />;
  }
  return <Server size={14} style={{ color: 'var(--text-muted)' }} title="Unknown" />;
};

export default function App() {
  // Navigation Routing States
  const [isLoggedIn, setIsLoggedIn] = useState(true);
  const [operatorToken, setOperatorToken] = useState(localStorage.getItem('redeye_operator_token') || '');
  const [platformFilter, setPlatformFilter] = useState('ALL');
  const [activePage, setActivePage] = useState('dashboard');
  const [activeSidebarTab, setActiveSidebarTab] = useState('nodes');
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [nodesSubView, setNodesSubView] = useState('overview');
  const [isLocked, setIsLocked] = useState(false);
  const [lockPassword, setLockPassword] = useState('');
  const [lockError, setLockError] = useState(false);

  // Dynamic C2 Gateway IP Configuration State
  const [c2GatewayIp, setC2GatewayIp] = useState(localStorage.getItem('redeye_c2_ip') || 'api.desaivraj.site');
  const c2BaseUrl = `http://${c2GatewayIp}:8000`;

  const handleUpdateC2Ip = (newIp) => {
    setC2GatewayIp(newIp);
    localStorage.setItem('redeye_c2_ip', newIp);
  };

  // Authenticated Console / Core States
  const [agents, setAgents] = useState(INITIAL_AGENTS);
  const [selectedAgentId, setSelectedAgentId] = useState(null);
  const [detailAgentId, setDetailAgentId] = useState(null);
  const [detailSubTab, setDetailSubTab] = useState('logins');
  const [appSearchQuery, setAppSearchQuery] = useState('');
  const [expandedAppPkg, setExpandedAppPkg] = useState(null);
  const [expandedProcessId, setExpandedProcessId] = useState(null);
  const [processSortConfig, setProcessSortConfig] = useState({ key: null, direction: 'asc' });
  const [processSearchQuery, setProcessSearchQuery] = useState('');
  const [inspectedApp, setInspectedApp] = useState(null);

  // VT Batch Scan states
  const [isVtScanning, setIsVtScanning] = useState(false);
  const [vtScanProgress, setVtScanProgress] = useState({ current: 0, total: 0 });

  // Agent Generator Form States
  const [formAgentName, setFormAgentName] = useState('HR-PC-01');
  const [formOS, setFormOS] = useState('Windows');
  const [formGroup, setFormGroup] = useState('Workstations');
  const [formDesc, setFormDesc] = useState('');
  const [formDept, setFormDept] = useState('HR');
  const [formTags, setFormTags] = useState(['Critical', 'Office']);
  const [formLocation, setFormLocation] = useState('Ahmedabad Office');
  const [formHeartbeat, setFormHeartbeat] = useState('60s');

  // Features:
  const [formFeatureProcess, setFormFeatureProcess] = useState(true);
  const [formFeatureLogin, setFormFeatureLogin] = useState(true);
  const [formFeatureUSB, setFormFeatureUSB] = useState(true);
  const [formFeatureNetwork, setFormFeatureNetwork] = useState(true);
  const [formFeatureVPN, setFormFeatureVPN] = useState(true);

  // Generation status states
  const [isGenerating, setIsGenerating] = useState(false);
  const [generateProgress, setGenerateProgress] = useState(0);
  const [generatedPath, setGeneratedPath] = useState('');
  const [downloadedAgentInfo, setDownloadedAgentInfo] = useState(null);

  const [consoleHistory, setConsoleHistory] = useState({});
  const [agentPaths, setAgentPaths] = useState({});
  const [inputValue, setInputValue] = useState('');
  const [sqlLogs, setSqlLogs] = useState([]);
  const [agentsTab, setAgentsTab] = useState('list');
  const [bandwidthStats, setBandwidthStats] = useState([]);
  const canvasRef = useRef(null);
  const [isScanning, setIsScanning] = useState(false);
  const [systemLogs, setSystemLogs] = useState(MOCK_SYSTEM_LOGS);
  const [alerts, setAlerts] = useState(MOCK_ALERTS);
  const [logFilterLevel, setLogFilterLevel] = useState('ALL');
  const [logFilterSource, setLogFilterSource] = useState('ALL');
  const [selectedCategory, setSelectedCategory] = useState(null);
  const [selectedSubcategory, setSelectedSubcategory] = useState(null);
  const [logSearchTerm, setLogSearchTerm] = useState('');
  const [sqlPlaygroundQuery, setSqlPlaygroundQuery] = useState("SELECT * FROM agents WHERE status = 'online';");
  const [sqlPlaygroundResult, setSqlPlaygroundResult] = useState(null);

  // Live Telemetry & Event States
  const [recentEvents, setRecentEvents] = useState(INITIAL_EVENTS);
  const [apiTraffic, setApiTraffic] = useState([]);
  const [telemetryData, setTelemetryData] = useState({
    cpu: [28, 32, 35, 30, 28, 42, 50, 48, 45, 40, 38, 42, 45, 48, 55, 60, 58, 52, 48, 45],
    ram: [64, 64, 65, 65, 65, 66, 66, 66, 67, 67, 68, 68, 68, 67, 67, 66, 66, 65, 65, 65]
  });

  const sendDesktopNotification = (title, message) => {
    if (typeof window !== "undefined" && "Notification" in window) {
      if (Notification.permission === "granted") {
        new Notification(title, {
          body: message
        });
      }
    }
  };

  const logApiTraffic = (method, url, status, payloadSize, statusText) => {
    const timestamp = new Date().toLocaleTimeString();
    setApiTraffic(prev => [
      { timestamp, method, url, status, payloadSize, statusText },
      ...prev.slice(0, 99)
    ]);
  };

  // Request notifications permission on startup
  useEffect(() => {
    if (typeof window !== "undefined" && "Notification" in window) {
      if (Notification.permission === "default") {
        Notification.requestPermission();
      }
    }
  }, []);

  // Silent authentication to retrieve token for default session if needed
  useEffect(() => {
    const fetchSilentToken = async () => {
      try {
        const res = await fetch(`http://${c2GatewayIp}:8000/api/v1/operator/login`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username: 'admin', password: 'redeye-secret' })
        });
        if (res.ok) {
          const data = await res.json();
          setOperatorToken(data.token);
          localStorage.setItem('redeye_operator_token', data.token);
        }
      } catch (e) {
        console.error("Silent operator login failed:", e);
      }
    };
    if (!operatorToken) {
      fetchSilentToken();
    }
  }, [operatorToken, c2GatewayIp]);

  // Live sync from FastAPI C2 backend
  useEffect(() => {
    if (!operatorToken) return;
    let active = true;
    const fetchGlobalData = async () => {
      try {
        // Fetch global agent list
        const urlAgents = `http://${c2GatewayIp}:8000/api/v1/operator/agents`;
        try {
          const resAgents = await fetch(urlAgents, {
            headers: { 'Authorization': `Bearer ${operatorToken}` }
          });
          if (resAgents.ok && active) {
            const dataAgents = await resAgents.json();
            setAgents(prev => {
              return dataAgents.map(newA => {
                const existingA = prev.find(a => a.id === newA.id);
                if (existingA) {
                  return {
                    ...existingA,
                    ...newA
                  };
                }
                return newA;
              });
            });
            logApiTraffic('GET', '/api/v1/operator/agents', resAgents.status, JSON.stringify(dataAgents).length, resAgents.statusText);
          } else {
            logApiTraffic('GET', '/api/v1/operator/agents', resAgents.status, 0, resAgents.statusText);
          }
        } catch (e) {
          logApiTraffic('GET', '/api/v1/operator/agents', 'FAIL', 0, e.message);
        }

        // Fetch global logs
        const urlLogs = `http://${c2GatewayIp}:8000/api/v1/operator/logs`;
        try {
          const resLogs = await fetch(urlLogs, {
            headers: { 'Authorization': `Bearer ${operatorToken}` }
          });
          if (resLogs.ok && active) {
            const dataLogs = await resLogs.json();
            if (dataLogs.length > 0) {
              setSystemLogs(dataLogs);
            }
            logApiTraffic('GET', '/api/v1/operator/logs', resLogs.status, JSON.stringify(dataLogs).length, resLogs.statusText);
          } else {
            logApiTraffic('GET', '/api/v1/operator/logs', resLogs.status, 0, resLogs.statusText);
          }
        } catch (e) {
          logApiTraffic('GET', '/api/v1/operator/logs', 'FAIL', 0, e.message);
        }

        // Fetch global alerts
        const urlAlerts = `http://${c2GatewayIp}:8000/api/v1/operator/alerts`;
        try {
          const resAlerts = await fetch(urlAlerts, {
            headers: { 'Authorization': `Bearer ${operatorToken}` }
          });
          if (resAlerts.ok && active) {
            const dataAlerts = await resAlerts.json();
            if (dataAlerts.length > 0) {
              setAlerts(dataAlerts);
            }
            logApiTraffic('GET', '/api/v1/operator/alerts', resAlerts.status, JSON.stringify(dataAlerts).length, resAlerts.statusText);
          } else {
            logApiTraffic('GET', '/api/v1/operator/alerts', resAlerts.status, 0, resAlerts.statusText);
          }
        } catch (e) {
          logApiTraffic('GET', '/api/v1/operator/alerts', 'FAIL', 0, e.message);
        }

        // Fetch recent events
        const urlEvents = `http://${c2GatewayIp}:8000/api/v1/operator/events`;
        try {
          const resEvents = await fetch(urlEvents, {
            headers: { 'Authorization': `Bearer ${operatorToken}` }
          });
          if (resEvents.ok && active) {
            const dataEvents = await resEvents.json();
            setRecentEvents(prevEvents => {
              if (prevEvents && prevEvents.length > 0 && dataEvents) {
                const prevIds = new Set(prevEvents.map(e => e.id));
                const newEvents = dataEvents.filter(e => !prevIds.has(e.id));
                newEvents.forEach(evt => {
                  const isUsb = evt.message?.toLowerCase().includes("usb") || evt.type?.toLowerCase().includes("usb");
                  if (isUsb) {
                    const title = `RedEye USB Detection [${evt.source}]`;
                    sendDesktopNotification(title, evt.message);
                  }
                });
              }
              return dataEvents;
            });
            logApiTraffic('GET', '/api/v1/operator/events', resEvents.status, JSON.stringify(dataEvents).length, resEvents.statusText);
          } else {
            logApiTraffic('GET', '/api/v1/operator/events', resEvents.status, 0, resEvents.statusText);
          }
        } catch (e) {
          logApiTraffic('GET', '/api/v1/operator/events', 'FAIL', 0, e.message);
        }
      } catch (err) {
        console.error("Failed to fetch global SOC metrics from C2 server:", err);
      }
    };

    fetchGlobalData();
    const interval = setInterval(fetchGlobalData, 4000);
    return () => {
      active = false;
      clearInterval(interval);
    };
  }, [operatorToken]);

  // Bandwidth statistics updater
  useEffect(() => {
    const updateStats = () => {
      const activeAgents = agents.length > 0 ? agents : [
        { id: '1', hostname: 'PC-001', ip_address: '192.168.1.10', status: 'online' },
        { id: '2', hostname: 'SERVER-01', ip_address: '192.168.1.1', status: 'online' },
        { id: '3', hostname: 'HR-PC-02', ip_address: '192.168.1.22', status: 'online' },
        { id: '4', hostname: 'Finance-01', ip_address: '192.168.1.40', status: 'online' },
      ];

      const stats = activeAgents.slice(0, 4).map((agent, index) => {
        const upBase = index === 0 ? 3.5 : index === 1 ? 2.0 : index === 2 ? 1.0 : 0.5;
        const downBase = index === 0 ? 2.8 : index === 1 ? 1.5 : index === 2 ? 3.0 : 0.6;

        const upload = Math.max(0.1, upBase + (Math.random() - 0.5) * 0.4);
        const download = Math.max(0.1, downBase + (Math.random() - 0.5) * 0.5);

        return {
          rank: index + 1,
          hostname: agent.hostname,
          ip: agent.ip_address,
          upload: parseFloat(upload.toFixed(1)),
          download: parseFloat(download.toFixed(1)),
          upPct: Math.min(100, Math.round((upload / 5) * 100)),
          downPct: Math.min(100, Math.round((download / 5) * 100))
        };
      });
      setBandwidthStats(stats);
    };

    updateStats();
    const interval = setInterval(updateStats, 2000);
    return () => clearInterval(interval);
  }, [agents]);

  // Topology Canvas animation
  useEffect(() => {
    if (activeSidebarTab !== 'network') return;
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    let animationFrameId;
    let t = 0;

    const handleResize = () => {
      const parent = canvas.parentElement;
      canvas.width = parent.clientWidth;
      canvas.height = parent.clientHeight || 380;
    };

    handleResize();
    window.addEventListener('resize', handleResize);

    const draw = () => {
      if (!canvas) return;
      const W = canvas.width;
      const H = canvas.height;
      ctx.clearRect(0, 0, W, H);

      const displayAgents = agents.length > 0 ? agents : [
        { hostname: "PC-001", platform: "Windows", status: "online", risk_score: 25, ip_address: "192.168.1.10" },
        { hostname: "SERVER-01", platform: "Linux", status: "online", risk_score: 55, ip_address: "192.168.1.1" },
        { hostname: "Android-01", platform: "Android", status: "offline", risk_score: 30, ip_address: "192.168.1.91" }
      ];

      const nodes = [
        { id: 'inet', x: W / 2, y: 50, label: 'Internet', icon: '🌐', color: '#ff4757' },
        { id: 'fw', x: W / 2, y: 130, label: 'Firewall', icon: '🛡️', color: '#e63946' },
        { id: 'sw', x: W / 2, y: 215, label: 'Core Switch', icon: '🔀', color: '#9b59b6' },
      ];

      const startX = 60;
      const endX = W - 60;
      const stepX = displayAgents.length > 1 ? (endX - startX) / (displayAgents.length - 1) : 0;

      displayAgents.forEach((agent, index) => {
        const x = displayAgents.length > 1 ? startX + stepX * index : W / 2;
        const color = agent.status === 'online' ? (agent.risk_score > 70 ? '#e63946' : agent.risk_score > 30 ? '#f39c12' : '#2ecc71') : '#606070';
        const icon = agent.platform === 'Windows' ? '💻' : (agent.platform === 'Linux' ? '🖥️' : '📱');
        nodes.push({
          id: `agent_${agent.id || index}`,
          x,
          y: 310,
          label: agent.hostname,
          icon,
          color,
          status: agent.status,
          ip: agent.ip_address
        });
      });

      const edges = [
        ['inet', 'fw'],
        ['fw', 'sw']
      ];

      displayAgents.forEach((agent, index) => {
        edges.push(['sw', `agent_${agent.id || index}`]);
      });

      edges.forEach(([a, b], ei) => {
        const na = nodes.find(n => n.id === a);
        const nb = nodes.find(n => n.id === b);
        if (!na || !nb) return;

        ctx.beginPath();
        ctx.moveTo(na.x, na.y);
        ctx.lineTo(nb.x, nb.y);
        ctx.setLineDash([5, 6]);
        ctx.strokeStyle = 'rgba(70, 70, 90, 0.6)';
        ctx.lineWidth = 1.5;
        ctx.stroke();
        ctx.setLineDash([]);

        const isStaticEdge = (a === 'inet' && b === 'fw') || (a === 'fw' && b === 'sw');
        const isTargetOnline = nb.status === 'online';

        if (isStaticEdge || isTargetOnline) {
          const prog = ((t * 0.015) + ei * 0.22) % 1;
          const px = na.x + (nb.x - na.x) * prog;
          const py = na.y + (nb.y - na.y) * prog;
          ctx.beginPath();
          ctx.arc(px, py, 3.5, 0, Math.PI * 2);
          ctx.fillStyle = nb.color || '#3498db';
          ctx.fill();
        }
      });

      nodes.forEach((n, i) => {
        const isAgent = n.id.startsWith('agent_');
        const pulse = 1 + Math.sin(t * 0.04 + i * 0.8) * 0.04;
        ctx.save();
        ctx.translate(n.x, n.y);
        ctx.scale(pulse, pulse);

        ctx.beginPath();
        ctx.arc(0, 0, 24, 0, Math.PI * 2);
        ctx.fillStyle = (n.color || '#e63946') + '15';
        ctx.fill();
        ctx.strokeStyle = n.color || '#e63946';
        ctx.lineWidth = 2;
        ctx.stroke();

        ctx.font = '16px serif';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText(n.icon, 0, 0);
        ctx.restore();

        ctx.font = '500 11px Inter, sans-serif';
        ctx.fillStyle = '#a0a0b0';
        ctx.textAlign = 'center';
        ctx.fillText(n.label, n.x, n.y + 36);

        if (isAgent && n.ip) {
          ctx.font = '400 9px monospace';
          ctx.fillStyle = '#606070';
          ctx.textAlign = 'center';
          ctx.fillText(n.ip, n.x, n.y + 47);
        }
      });

      t++;
      animationFrameId = requestAnimationFrame(draw);
    };

    draw();

    return () => {
      window.removeEventListener('resize', handleResize);
      cancelAnimationFrame(animationFrameId);
    };
  }, [activeSidebarTab, agents]);

  // Poll details of selected agent
  useEffect(() => {
    if (!selectedAgentId || !operatorToken) return;
    let active = true;

    const fetchAgentDetails = async () => {
      try {
        const res = await fetch(`https://api.desaivraj.site/api/v1/operator/agents/${selectedAgentId}`, {
          headers: { 'Authorization': `Bearer ${operatorToken}` }
        });
        if (res.ok && active) {
          const details = await res.json();

          // Update the specific agent's stats inside agents array
          setAgents(prev => prev.map(a => {
            if (a.id === selectedAgentId) {
              const tags = details.agent.tags || [];
              const ipTag = tags.find(t => t.startsWith("public_ip:"));
              const countryTag = tags.find(t => t.startsWith("country:"));
              const cityTag = tags.find(t => t.startsWith("city:"));
              const parsedPublicIp = ipTag ? ipTag.substring("public_ip:".length) : details.agent.ip_address;
              const parsedCountry = countryTag ? countryTag.substring("country:".length) : "India";
              const parsedCity = cityTag ? cityTag.substring("city:".length) : "Mumbai";

              return {
                ...a,
                ...details.agent,
                android_apps: details.android_apps || [],
                device_id: details.agent.id,
                os_release: details.agent.os_version,
                internal_ip: details.agent.ip_address,
                public_ip: parsedPublicIp,
                country: parsedCountry,
                city: parsedCity,
                mac_address: details.agent.mac_address || "00:15:5D:01:AF:2C",
                uptime: details.system_info?.uptime ? `${Math.floor(details.system_info.uptime / 60)}m` : "1h 12m",
                health: {
                  cpu: details.system_info?.cpu_usage || 0,
                  ram: details.system_info?.ram_usage || 0,
                  disk: 35,
                  network: "Active"
                },
                security: {
                  antivirus: details.agent.platform === "Windows" ? "Windows Defender (Running)" : "ClamAV (Running)",
                  firewall: "Enabled",
                  vpn: details.network_connections?.some(conn => conn.vpn_active) ? "Connected" : "Disconnected",
                  alerts: details.alerts?.length || 0
                },
                activity: {
                  logins: (details.login_history || []).map(l => ({
                    time: l.timestamp ? new Date(l.timestamp).toLocaleTimeString() : '',
                    user: l.user || 'Unknown',
                    status: l.type || 'Success'
                  })),
                  usb: (details.usb_devices || []).map(u => ({
                    time: u.timestamp ? new Date(u.timestamp).toLocaleTimeString() : '',
                    device: u.name || 'Unknown Device',
                    action: (u.action === 'inserted' || u.action === 'insertion' || u.action === 'connected' || u.action === 'added') ? 'inserted' : 'removed'
                  })),
                  processes: (details.processes || []).map(p => ({
                    pid: p.pid,
                    name: p.name,
                    cpu: "0.2%",
                    mem: "1.4%"
                  })),
                  network: (details.network_connections || []).map(n => ({
                    proto: n.protocol || 'TCP',
                    local: n.local_address,
                    foreign: n.foreign_address,
                    state: n.state
                  })),
                  software: (details.alerts || [])
                    .filter(a => a.category === "Software Installed" || a.category === "Software Removed" || a.category === "Software Activity")
                    .map(s => ({
                      time: s.timestamp ? new Date(s.timestamp).toLocaleTimeString() : '',
                      name: s.message || '',
                      action: s.category === "Software Installed" ? "Installed" : "Removed"
                    }))
                }
              };
            }
            return a;
          }));

          // Rebuild console history from database commands
          if (details.commands) {
            const history = [];
            let latestPath = null;
            details.commands.forEach(cmd => {
              const formatTime = (isoStr) => {
                if (!isoStr) return '';
                try {
                  return new Date(isoStr).toLocaleTimeString();
                } catch {
                  return '';
                }
              };
              history.push({
                type: 'input',
                text: cmd.command_text,
                time: formatTime(cmd.created_at)
              });
              if (cmd.status === 'completed' || cmd.status === 'failed') {
                history.push({
                  type: cmd.status === 'completed' ? 'output' : 'error',
                  text: cmd.response_text || '',
                  time: formatTime(cmd.executed_at)
                });

                if (cmd.status === 'completed' && cmd.command_text) {
                  const cmdTrim = cmd.command_text.trim();
                  if (cmdTrim === 'cd' || cmdTrim.startsWith('cd ')) {
                    const cleanResp = (cmd.response_text || '').trim();
                    if (cleanResp && !cleanResp.startsWith('Error:') && !cleanResp.includes('\n')) {
                      latestPath = cleanResp;
                    }
                  }
                }
              }
            });
            setConsoleHistory(prev => ({
              ...prev,
              [selectedAgentId]: history
            }));
            if (latestPath) {
              setAgentPaths(prev => {
                if (prev[selectedAgentId] !== latestPath) {
                  return { ...prev, [selectedAgentId]: latestPath };
                }
                return prev;
              });
            }
          }
        }
      } catch (err) {
        console.error(`Failed to fetch details for agent ${selectedAgentId}:`, err);
      }
    };

    fetchAgentDetails();
    const interval = setInterval(fetchAgentDetails, 2000);
    return () => {
      active = false;
      clearInterval(interval);
    };
  }, [selectedAgentId, operatorToken]);

  // Poll details of selected detailed agent (for Agents tab detailed dashboard view)
  useEffect(() => {
    if (!detailAgentId || !operatorToken) return;
    let active = true;

    const fetchDetailAgentStats = async () => {
      try {
        const res = await fetch(`https://api.desaivraj.site/api/v1/operator/agents/${detailAgentId}`, {
          headers: { 'Authorization': `Bearer ${operatorToken}` }
        });
        if (res.ok && active) {
          const details = await res.json();

          setAgents(prev => prev.map(a => {
            if (a.id === detailAgentId) {
              const tags = details.agent.tags || [];
              const ipTag = tags.find(t => t.startsWith("public_ip:"));
              const countryTag = tags.find(t => t.startsWith("country:"));
              const cityTag = tags.find(t => t.startsWith("city:"));
              const parsedPublicIp = ipTag ? ipTag.substring("public_ip:".length) : details.agent.ip_address;
              const parsedCountry = countryTag ? countryTag.substring("country:".length) : "India";
              const parsedCity = cityTag ? cityTag.substring("city:".length) : "Mumbai";

              return {
                ...a,
                ...details.agent,
                android_apps: details.android_apps || [],
                processes: details.processes || [],
                network_connections: details.network_connections || [],
                usb_devices: details.usb_devices || [],
                login_history: details.login_history || [],
                installed_software: details.installed_software || [],
                alerts: details.alerts || [],
                violations: details.violations || [],
                device_id: details.agent.id,
                os_release: details.agent.os_version,
                internal_ip: details.agent.ip_address,
                public_ip: parsedPublicIp,
                country: parsedCountry,
                city: parsedCity,
                mac_address: details.agent.mac_address || "00:15:5D:01:AF:2C",
                uptime: details.system_info?.uptime ? `${Math.floor(details.system_info.uptime / 60)}m` : "1h 12m",
                health: {
                  cpu: details.system_info?.cpu_usage || 0,
                  ram: details.system_info?.ram_usage || 0,
                  disk: 35,
                  network: "Active"
                },
                security: {
                  antivirus: details.agent.platform === "Windows" ? "Windows Defender (Running)" : "ClamAV (Running)",
                  firewall: "Enabled",
                  vpn: details.network_connections?.some(conn => conn.vpn_active) ? "Connected" : "Disconnected",
                  alerts: details.alerts?.length || 0
                },
                activity: {
                  logins: (details.login_history || []).map(l => ({
                    timestamp: l.timestamp ? new Date(l.timestamp).toLocaleString() : '',
                    event_category: l.type || 'Logon Success',
                    domain: 'RE-DOMAIN',
                    username: l.user || 'SYSTEM',
                    workstation: 'WORKSTATION',
                    ip_address: l.source_ip || '127.0.0.1',
                    process_name: 'winlogon.exe'
                  })),
                  usb: (details.usb_devices || []).map(u => ({
                    timestamp: u.timestamp ? new Date(u.timestamp).toLocaleString() : '',
                    action: (u.action === 'inserted' || u.action === 'insertion' || u.action === 'connected' || u.action === 'added') ? 'Connected' : 'Disconnected',
                    device_class: u.type || 'Mass Storage',
                    vendor_id: u.vendor_id || '0x0781',
                    product_id: '0x558A',
                    device_name: u.name || 'USB Disk',
                    serial_number: u.serial || '4C530001'
                  })),
                  processes: (details.processes || []).map(p => ({
                    pid: p.pid,
                    process_name: p.name,
                    username: p.user || 'SYSTEM',
                    cpu_usage: p.cpu,
                    ram_usage: p.mem,
                    path: p.executable_path || p.path || (details.agent.platform === 'Linux' ? `/usr/bin/${p.name}` : `C:\\Windows\\System32\\${p.name}`),
                    command_line: p.command_line || '-',
                    start_time: p.start_time ? new Date(p.start_time).toLocaleString() : '-',
                    parent_process: p.parent_process || 'Unknown',
                    sha256_hash: p.sha256_hash || 'N/A'
                  })),
                  network: (details.network_connections || []).map(n => {
                    const localParts = (n.local_address || '').split(':');
                    const remoteParts = (n.foreign_address || '').split(':');
                    return {
                      protocol: n.protocol || 'TCP',
                      local_ip: localParts[0] || '0.0.0.0',
                      local_port: localParts[1] || '0',
                      remote_ip: remoteParts[0] || '0.0.0.0',
                      remote_port: remoteParts[1] || '0',
                      state: n.state || 'UNKNOWN',
                      pid: n.pid || Math.floor(Math.random() * 2000 + 1000)
                    };
                  }),
                  software: (details.alerts || [])
                    .filter(a => a.category === "Software Installed" || a.category === "Software Removed" || a.category === "Software Activity")
                    .map(s => {
                      const msg = s.message || '';
                      const nameMatch = msg.match(/'([^']+)'/);
                      const verMatch = msg.match(/\(Version:\s*([^)]+)\)/);
                      return {
                        software_name: nameMatch ? nameMatch[1] : 'Unknown App',
                        version: verMatch ? verMatch[1] : '1.0.0',
                        publisher: 'Unknown Publisher',
                        install_date: s.timestamp ? new Date(s.timestamp).toLocaleDateString() : 'Recent'
                      };
                    })
                }
              };
            }
            return a;
          }));
        }
      } catch (err) {
        console.error(`Failed to fetch detail view stats for agent ${detailAgentId}:`, err);
      }
    };

    fetchDetailAgentStats();
    const interval = setInterval(fetchDetailAgentStats, 3000);
    return () => {
      active = false;
      clearInterval(interval);
    };
  }, [detailAgentId, operatorToken]);

  useEffect(() => {
    const interval = setInterval(() => {
      setTelemetryData(prev => {
        const lastCpu = prev.cpu[prev.cpu.length - 1];
        const lastRam = prev.ram[prev.ram.length - 1];
        const changeCpu = (Math.random() - 0.5) * 12;
        const newCpu = Math.max(15, Math.min(85, lastCpu + changeCpu));
        const changeRam = (Math.random() - 0.5) * 2;
        const newRam = Math.max(50, Math.min(95, lastRam + changeRam));
        return {
          cpu: [...prev.cpu.slice(1), Math.round(newCpu)],
          ram: [...prev.ram.slice(1), Math.round(newRam)]
        };
      });
    }, 1500);
    return () => clearInterval(interval);
  }, []);



  const latestEvents = recentEvents.filter(e => e.severity === 'warning' || e.severity === 'critical');

  // Form States
  const [contactName, setContactName] = useState('');
  const [contactEmail, setContactEmail] = useState('');
  const [contactMessage, setContactMessage] = useState('');
  const [contactSent, setContactSent] = useState(false);

  // Authentication Fields
  const [loginUser, setLoginUser] = useState('admin');
  const [loginPass, setLoginPass] = useState('redeye-secret');
  const [loginError, setLoginError] = useState('');

  const consoleEndRef = useRef(null);
  const selectedAgent = agents.find(a => a.id === selectedAgentId);

  // Auto-scroll terminal
  useEffect(() => {
    if (consoleEndRef.current) {
      consoleEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [consoleHistory, selectedAgentId]);

  // Log initial queries
  useEffect(() => {
    logSql("SELECT * FROM agents ORDER BY status DESC, last_seen DESC;");
    logSql("SELECT COUNT(*) FROM agents WHERE status = 'online';");
  }, []);

  const logSql = (query) => {
    const timestamp = new Date().toLocaleTimeString();
    setSqlLogs(prev => [
      { timestamp, query },
      ...prev.slice(0, 49)
    ]);
  };

  const handleSelectAgent = (agent) => {
    setSelectedAgentId(agent.id);
    logSql(`SELECT * FROM commands WHERE agent_id = '${agent.id}' ORDER BY created_at ASC;`);
  };

  const handleGenerateAgent = (e) => {
    e.preventDefault();
    setIsGenerating(true);
    setGenerateProgress(0);
    setGeneratedPath('');
    setDownloadedAgentInfo(null);

    let progress = 0;
    const interval = setInterval(() => {
      progress += 10;
      setGenerateProgress(progress);
      if (progress >= 100) {
        clearInterval(interval);

        setTimeout(() => {
          setIsGenerating(false);
          const newAgentId = Math.random().toString(36).substring(2, 10);

          let filename = '';
          let downloadUrl = '';
          let commands = [];

          if (formOS === 'Windows') {
            filename = 'Red-Eye-new.exe';
            downloadUrl = `https://api.desaivraj.site/api/v1/operator/agent/download?format=exe&platform_type=Windows&name=${encodeURIComponent(formAgentName)}&interval=${encodeURIComponent(formHeartbeat)}${operatorToken ? `&token=${encodeURIComponent(operatorToken)}` : ''}`;
            commands = [
              'Red-Eye-new.exe --install',
              'Red-Eye-new.exe --start'
            ];
          } else if (formOS === 'Linux') {
            filename = 'redeye-agent';
            downloadUrl = 'https://api.desaivraj.site/agents/linux/redeye-agent';
            commands = [
              'chmod +x redeye-agent',
              './redeye-agent'
            ];
          } else if (formOS === 'Android') {
            filename = 'RedEye.apk';
            downloadUrl = `https://api.desaivraj.site/agents/android/RedEye.apk`;
            commands = [
              'Transfer RedEye.apk to target Android device and tap to install'
            ];
          } else if (formOS === 'OTA Update') {
            filename = 'Red-Eye-Update.exe';
            downloadUrl = `https://api.desaivraj.site/api/v1/agents/download`;
            commands = [
              'OTA Update binary download initiated.',
              'Deploy via RedEye C2 update channel.'
            ];
          }

          setDownloadedAgentInfo({
            os: formOS,
            filename: filename,
            commands: commands
          });

          // Trigger download if downloadUrl is present
          if (downloadUrl) {
            const link = document.createElement('a');
            link.href = downloadUrl;
            link.setAttribute('download', filename);
            document.body.appendChild(link);
            link.click();
            link.parentNode.removeChild(link);
          }

          const tempAgent = {
            id: newAgentId,
            hostname: `${formAgentName} (Awaiting Deploy)`,
            platform: formOS,
            os_release: `${formOS} (Detecting version on first check-in...)`,
            ip_address: 'Detecting...',
            user: 'Detecting...',
            status: 'offline',
            risk_score: 0,
            last_seen: 'Never check-in',
            device_id: 'Detecting...',
            agent_version: 'v2.4.1-stable',
            internal_ip: 'Detecting...',
            public_ip: 'Detecting...',
            mac_address: 'Detecting...',
            uptime: '0m',
            update_required: false,
            critical: formTags.includes('Critical'),
            last_24h_checkin: false,
            health: { cpu: 0, ram: 0, disk: 0, network: '0 Kbps' },
            security: {
              antivirus: 'Pending Detection',
              firewall: 'Pending Detection',
              vpn: 'Pending Detection',
              alerts: 0
            },
            activity: { logins: [], usb: [], processes: [], network: [] }
          };

          setAgents(prev => [tempAgent, ...prev]);
          logSql(`-- Simulated payload compilation complete for ${formAgentName}. Binary: redeye_${formAgentName.toLowerCase()}_agent_${formOS.toLowerCase()};`);

          setTimeout(() => {
            const detectedIp = `192.168.1.${Math.floor(Math.random() * 200) + 20}`;
            const detectedUser = formOS === 'Windows' ? `${formAgentName.toLowerCase()}\\operator` : formOS === 'Linux' ? 'root' : 'u0_a119';
            const detectedHostname = formOS === 'Windows' ? `${formAgentName.toUpperCase()}-WIN` : formOS === 'Linux' ? `${formAgentName.toLowerCase()}-node` : `${formAgentName.toLowerCase()}-android`;
            const detectedMac = '00:1A:2B:' + Array.from({ length: 3 }, () => Math.floor(Math.random() * 16).toString(16).toUpperCase().padStart(2, '0')).join(':');

            setAgents(prev => prev.map(a => {
              if (a.id === newAgentId) {
                return {
                  ...a,
                  hostname: detectedHostname,
                  os_release: formOS === 'Windows' ? 'Windows 11 Enterprise (23H2)' : formOS === 'Linux' ? 'Ubuntu 24.04 LTS (6.8.0)' : 'Android 14 (API 34)',
                  ip_address: detectedIp,
                  user: detectedUser,
                  status: 'online',
                  last_seen: 'Just now',
                  device_id: 'DEV-' + formOS.toUpperCase().substring(0, 3) + '-' + Math.floor(1000 + Math.random() * 9000),
                  internal_ip: detectedIp,
                  public_ip: '82.165.41.' + (Math.floor(Math.random() * 50) + 100),
                  mac_address: detectedMac,
                  uptime: '1m',
                  health: { cpu: 12, ram: 28, disk: 45, network: '45 Kbps' },
                  security: {
                    antivirus: formOS === 'Windows' ? 'Active (Windows Defender)' : formOS === 'Linux' ? 'Active (ClamAV)' : 'Active (Google Play Protect)',
                    firewall: 'Active',
                    vpn: 'Disconnected',
                    alerts: 0
                  },
                  activity: {
                    logins: [{ time: 'Just now', user: detectedUser, status: 'Success' }],
                    usb: [],
                    processes: [
                      { pid: Math.floor(1000 + Math.random() * 3000), name: formOS === 'Windows' ? 'agent.exe' : 'agent.bin', cpu: '0.1%', mem: '15MB' }
                    ],
                    network: [
                      { proto: 'TCP', local: `${detectedIp}:49911`, foreign: '192.168.1.5:5432', state: 'ESTABLISHED' }
                    ]
                  }
                };
              }
              return a;
            }));

            logSql(`INSERT INTO agents (hostname, platform, ip_address, status) VALUES ('${detectedHostname}', '${formOS}', '${detectedIp}', 'online');`);

            const time = new Date().toLocaleTimeString();
            setSystemLogs(prev => [
              { id: prev.length + 1, level: 'INFO', msg: `Auto-detection completed. Registered agent ${detectedHostname} (${detectedIp}) under user ${detectedUser}.`, time },
              ...prev
            ]);

          }, 6000);

        }, 300);
      }
    }, 150);
  };

  const handleRestartAgent = async (agent) => {
    try {
      const res = await fetch(`https://api.desaivraj.site/api/v1/operator/agents/${agent.id}/restart`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${operatorToken}`
        }
      });
      if (res.ok) {
        alert(`Reboot command dispatched successfully to ${agent.hostname}.`);
        logSql(`UPDATE agents SET status='offline', last_seen='Rebooting...' WHERE id='${agent.id}';`);
        setAgents(prev => prev.map(a => a.id === agent.id ? { ...a, status: 'offline', last_seen: 'Rebooting...' } : a));

        setTimeout(async () => {
          try {
            const detailsRes = await fetch(`https://api.desaivraj.site/api/v1/operator/agents/${agent.id}`, {
              headers: { 'Authorization': `Bearer ${operatorToken}` }
            });
            if (detailsRes.ok) {
              const details = await detailsRes.json();
              setAgents(prev => prev.map(a => a.id === agent.id ? { ...a, ...details.agent } : a));
            }
          } catch (e) {
            console.error(e);
          }
        }, 5000);
      } else {
        alert(`Failed to reboot agent ${agent.hostname}: ${res.statusText}`);
      }
    } catch (e) {
      alert(`Network error dispatching reboot command: ${e.message}`);
    }
  };

  const handleWakeupAgent = async (agent) => {
    try {
      const res = await fetch(`https://api.desaivraj.site/api/v1/operator/agents/${agent.id}/wakeup`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${operatorToken}`
        }
      });
      if (res.ok) {
        alert(`Wakeup push signal transmitted successfully to ${agent.hostname}.`);
      } else {
        alert(`Failed to transmit wakeup signal to ${agent.hostname}: ${res.statusText}`);
      }
    } catch (e) {
      alert(`Network error dispatching wakeup signal: ${e.message}`);
    }
  };

  const handleUpdateAgent = (agent) => {
    alert(`Update firmware request sent to ${agent.hostname}.`);
    logSql(`UPDATE agents SET agent_version='v2.4.1-stable', update_required=false WHERE id='${agent.id}';`);
    setAgents(prev => prev.map(a => a.id === agent.id ? { ...a, update_required: false, agent_version: 'v2.4.1-stable' } : a));
  };

  const handleIsolateAgent = (agent) => {
    alert(`[FUTURE ACTION] Network isolation protocol is scheduled for a future release.`);
    logSql(`-- FUTURE ACTION: ISOLATE agent ${agent.id} (${agent.hostname});`);
  };

  const handleRemoveAgent = async (agentId, hostname) => {
    if (confirm(`Are you sure you want to permanently deregister Agent ${hostname}?`)) {
      try {
        const res = await fetch(`https://api.desaivraj.site/api/v1/operator/agents/${agentId}`, {
          method: 'DELETE',
          headers: {
            'Authorization': `Bearer ${operatorToken}`
          }
        });
        if (res.ok) {
          setAgents(prev => prev.filter(a => a.id !== agentId));
          logSql(`DELETE FROM agents WHERE id='${agentId}';`);
          if (detailAgentId === agentId) {
            setDetailAgentId(null);
          }
          if (selectedAgentId === agentId) {
            setSelectedAgentId(null);
          }
        } else {
          alert(`Failed to remove agent: ${res.statusText}`);
        }
      } catch (err) {
        console.error("Error removing agent:", err);
        alert(`Error removing agent: ${err.message}`);
      }
    }
  };

  const handleScan = () => {
    setIsScanning(true);
    logSql("UPDATE agents SET status = 'offline' WHERE last_seen < NOW() - INTERVAL '5 minutes';");
    logSql("SELECT * FROM agents WHERE status = 'online';");

    setTimeout(() => {
      setIsScanning(false);
      setAgents(prev => prev.map(a => {
        if (a.status === 'online') {
          return { ...a, last_seen: 'Just now' };
        }
        return a;
      }));

      // Add a fresh log item
      const time = new Date().toLocaleTimeString();
      setSystemLogs(prev => [
        { id: prev.length + 1, level: 'INFO', msg: 'Network sweep complete. 3 agents active.', time },
        ...prev
      ]);
    }, 1200);
  };

  const executeCommandText = async (commandText) => {
    if (!commandText.trim() || !selectedAgentId) return;

    const cmd = commandText.trim();
    const time = new Date().toLocaleTimeString();

    // Optimistically add input line
    setConsoleHistory(prev => {
      const history = prev[selectedAgentId] || [];
      return {
        ...prev,
        [selectedAgentId]: [...history, { type: 'input', text: cmd, time }]
      };
    });

    setInputValue('');
    logSql(`INSERT INTO commands (agent_id, command_text, status) VALUES ('${selectedAgentId}', '${cmd}', 'pending');`);

    try {
      const res = await fetch(`https://api.desaivraj.site/api/v1/operator/agents/${selectedAgentId}/command`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${operatorToken}`
        },
        body: JSON.stringify({ command_text: cmd })
      });
      if (res.ok) {
        // Immediate refresh of console history to show command scheduled
        const detailsRes = await fetch(`https://api.desaivraj.site/api/v1/operator/agents/${selectedAgentId}`, {
          headers: { 'Authorization': `Bearer ${operatorToken}` }
        });
        if (detailsRes.ok) {
          const details = await detailsRes.json();
          if (details.commands) {
            const history = [];
            let latestPath = null;
            details.commands.forEach(c => {
              history.push({
                type: 'input',
                text: c.command_text,
                time: c.created_at ? new Date(c.created_at).toLocaleTimeString() : ''
              });
              if (c.status === 'completed' || c.status === 'failed') {
                history.push({
                  type: c.status === 'completed' ? 'output' : 'error',
                  text: c.response_text || '',
                  time: c.executed_at ? new Date(c.executed_at).toLocaleTimeString() : ''
                });

                if (c.status === 'completed' && c.command_text) {
                  const cmdTrim = c.command_text.trim();
                  if (cmdTrim === 'cd' || cmdTrim.startsWith('cd ')) {
                    const cleanResp = (c.response_text || '').trim();
                    if (cleanResp && !cleanResp.startsWith('Error:') && !cleanResp.includes('\n')) {
                      latestPath = cleanResp;
                    }
                  }
                }
              }
            });
            setConsoleHistory(prev => ({ ...prev, [selectedAgentId]: history }));
            if (latestPath) {
              setAgentPaths(prev => {
                if (prev[selectedAgentId] !== latestPath) {
                  return { ...prev, [selectedAgentId]: latestPath };
                }
                return prev;
              });
            }
          }
        }
      } else {
        const errorText = await res.text();
        setConsoleHistory(prev => {
          const history = prev[selectedAgentId] || [];
          return {
            ...prev,
            [selectedAgentId]: [...history, { type: 'error', text: `Error from C2: ${errorText}`, time }]
          };
        });
      }
    } catch (err) {
      console.error("Failed to post command to C2:", err);
      setConsoleHistory(prev => {
        const history = prev[selectedAgentId] || [];
        return {
          ...prev,
          [selectedAgentId]: [...history, { type: 'error', text: 'Network connection failure to C2 server.', time }]
        };
      });
    }
  };

  const handleKeyPress = (e) => {
    if (e.key === 'Enter') {
      executeCommandText(inputValue);
    }
  };

  const clearConsole = () => {
    if (!selectedAgentId) return;
    setConsoleHistory(prev => ({ ...prev, [selectedAgentId]: [] }));
    logSql(`DELETE FROM commands WHERE agent_id = '${selectedAgentId}';`);
  };

  // Handle Mock Email Contact Form Submission
  const handleContactSubmit = (e) => {
    e.preventDefault();
    if (!contactName || !contactEmail || !contactMessage) return;

    // Simulate visual mail trigger
    setContactSent(true);

    // Open a visual browser mailto window link for user convenience
    const mailtoLink = `mailto:desaivraj73@gmail.com?subject=RedEye Inquiry from ${encodeURIComponent(contactName)}&body=${encodeURIComponent(contactMessage)}%0A%0AReply to: ${encodeURIComponent(contactEmail)}`;

    setTimeout(() => {
      window.location.href = mailtoLink;
    }, 800);
  };

  // Handle Mock Auth Login
  const handleLoginSubmit = async (e) => {
    e.preventDefault();
    try {
      const res = await fetch('https://api.desaivraj.site/api/v1/operator/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: loginUser, password: loginPass })
      });
      if (res.ok) {
        const data = await res.json();
        setOperatorToken(data.token);
        localStorage.setItem('redeye_operator_token', data.token);
        setIsLoggedIn(true);
        setActiveSidebarTab('dashboard');
        logSql("INSERT INTO system_logs (log_level, message) VALUES ('INFO', 'User admin authenticated successfully.');");
      } else {
        setLoginError('Authentication failed. Invalid username or security credentials.');
        logSql("INSERT INTO system_logs (log_level, message) VALUES ('WARN', 'Failed login attempt from user: ' || '" + loginUser + "');");
      }
    } catch (e) {
      setLoginError('Authentication failed. Server unreachable.');
    }
  };

  const handleLogout = () => {
    setOperatorToken('');
    localStorage.removeItem('redeye_operator_token');
    setIsLoggedIn(false);
    setActivePage('home');
    logSql("INSERT INTO system_logs (log_level, message) VALUES ('INFO', 'User admin logged out.');");
  };
  const handleVtBatchScan = async (agent, targetFilter = 'all') => {
    if (!agent) return;

    let hashesToScan = [];
    if (agent.platform === 'Android' && agent.android_apps) {
      let targetApps = agent.android_apps;
      if (targetFilter === 'red') {
        targetApps = agent.android_apps.filter(app => {
          const vtMalicious = app.vt_detection_rate && app.vt_detection_rate !== '0/0' ? parseInt(app.vt_detection_rate.split('/')[0], 10) || 0 : 0;
          return app.mb_listed || vtMalicious >= 1 || app.risk_level === 'red' || (app.threat_score || 0) >= 61;
        });
      } else if (targetFilter === 'yellow') {
        targetApps = agent.android_apps.filter(app => {
          const score = app.threat_score || 0;
          const vtMalicious = app.vt_detection_rate && app.vt_detection_rate !== '0/0' ? parseInt(app.vt_detection_rate.split('/')[0], 10) || 0 : 0;
          const isRed = app.mb_listed || vtMalicious >= 1 || app.risk_level === 'red' || score >= 61;
          return !isRed && (app.risk_level === 'yellow' || score >= 30);
        });
      } else {
        targetApps = agent.android_apps.filter(app => app.risk_level !== 'green');
      }
      hashesToScan = [...new Set(targetApps.map(app => app.apk_sha256).filter(Boolean))];
    } else {
      const desktopProcs = agentProcesses || [];
      const suspiciousProcs = desktopProcs.filter(p => (p.threat_score || 0) >= 30 || (p.threat_reasons && p.threat_reasons.length > 0) || (p.reasons && p.reasons.length > 0));
      hashesToScan = [...new Set(suspiciousProcs.map(p => p.sha256_hash || p.sha256 || p.hash).filter(Boolean))];
    }

    if (hashesToScan.length === 0) {
      alert(`No valid hashes or suspicious items found to scan.`);
      return;
    }

    setIsVtScanning(true);
    setVtScanProgress({ current: 0, total: hashesToScan.length });

    let currentVal = 0;
    const progressInterval = setInterval(() => {
      currentVal += 1;
      if (currentVal < hashesToScan.length) {
        setVtScanProgress({ current: currentVal, total: hashesToScan.length });
      } else {
        clearInterval(progressInterval);
      }
    }, 15000);

    try {
      const response = await fetch(`http://${c2GatewayIp}:8000/api/v1/operator/agents/${agent.id}/vt_batch_scan`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${operatorToken}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ hashes: hashesToScan })
      });

      clearInterval(progressInterval);
      if (response.ok) {
        setVtScanProgress({ current: hashesToScan.length, total: hashesToScan.length });
      } else {
        console.error("VT Batch scan failed", await response.text());
      }
    } catch (err) {
      clearInterval(progressInterval);
      console.error("VT Batch scan failed", err);
    }

    // Clear scanning state after 3 seconds so the user can see completion
    setTimeout(() => {
      setIsVtScanning(false);
      setVtScanProgress({ current: 0, total: 0 });
    }, 3000);
  };

  const handleTerminateProcess = async (agent, pid) => {
    const cmd = agent.platform === 'Windows' ? `taskkill /F /PID ${pid}` : `kill -9 ${pid}`;
    if (!window.confirm(`Are you sure you want to terminate process PID ${pid} on ${agent.hostname} ("${cmd}")?`)) return;
    try {
      const res = await fetch(`https://api.desaivraj.site/api/v1/operator/agents/${agent.id}/command`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${operatorToken}`
        },
        body: JSON.stringify({ command_text: cmd })
      });
      if (res.ok) {
        alert(`Termination command scheduled successfully: "${cmd}"`);
      } else {
        alert('Failed to schedule termination command.');
      }
    } catch (err) {
      console.error(err);
      alert('Error scheduling termination command.');
    }
  };

  const handleProcessVtScan = async (agent, pid) => {
    try {
      const response = await fetch(`https://api.desaivraj.site/api/v1/operator/agents/${agent.id}/processes/${pid}/vt_rescan`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${operatorToken}` }
      });
      if (response.ok) {
        const result = await response.json();
        alert(`Scan Complete!\nVT Rate: ${result.vt_rate || 'N/A'}\nFinal Threat Score: ${result.threat_score}\nClassification: ${result.threat_classification}`);

        // Immediately fetch fresh stats to refresh UI
        const res = await fetch(`https://api.desaivraj.site/api/v1/operator/agents/${agent.id}`, {
          headers: { 'Authorization': `Bearer ${operatorToken}` }
        });
        if (res.ok) {
          const details = await res.json();
          setAgents(prev => prev.map(a => {
            if (a.id === agent.id) {
              return {
                ...a,
                ...details.agent,
                android_apps: details.android_apps || [],
                processes: details.processes || [],
                network_connections: details.network_connections || [],
                usb_devices: details.usb_devices || [],
                login_history: details.login_history || [],
                installed_software: details.installed_software || [],
                alerts: details.alerts || [],
                violations: details.violations || [],
                health: details.system_info || { cpu: 0, ram: 0, disk: 0, network: 'Active' },
                security: {
                  antivirus: details.agent.security?.antivirus || 'Running',
                  firewall: details.agent.security?.firewall || 'Active',
                  vpn: 'Disabled',
                  alerts: details.alerts ? details.alerts.length : 0
                }
              };
            }
            return a;
          }));
        }
      } else {
        const errData = await response.json();
        alert(`Scan failed: ${errData.detail || 'Unknown error'}`);
      }
    } catch (err) {
      console.error("Process scan failed", err);
      alert("Error scanning process hash.");
    }
  };

  return (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column' }}>
      {isLocked && (
        <div className="hud-lock-overlay">
          <div className="hud-lock-box">
            <div className="hud-lock-header">
              <Lock size={16} style={{ color: 'var(--accent-cyan)' }} />
              <div className="hud-lock-title">TERMINAL SESSION SECURED</div>
            </div>
            <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginBottom: '16px', lineHeight: 1.4 }}>
              Security policy enforces session lock. Enter authorization key to resume console telemetry session.
            </div>
            {lockError && (
              <div style={{ color: 'var(--accent-red)', fontSize: '11px', marginBottom: '12px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                <AlertCircle size={12} />
                <span>ACCESS KEY INVALID</span>
              </div>
            )}
            <input
              type="password"
              className="hud-lock-input"
              placeholder="ENTER PASSCODE..."
              value={lockPassword}
              onChange={(e) => { setLockPassword(e.target.value); setLockError(false); }}
              onKeyDown={(e) => {
                if (e.key === 'Enter') {
                  if (lockPassword === 'admin' || lockPassword === 'redeye-secret' || lockPassword === 'secret' || lockPassword === '') {
                    setIsLocked(false);
                    setLockPassword('');
                  } else {
                    setLockError(true);
                  }
                }
              }}
            />
            <button
              className="hud-lock-btn"
              onClick={() => {
                if (lockPassword === 'admin' || lockPassword === 'redeye-secret' || lockPassword === 'secret' || lockPassword === '') {
                  setIsLocked(false);
                  setLockPassword('');
                } else {
                  setLockError(true);
                }
              }}
            >
              AUTHENTICATE ENCLAVE
            </button>
          </div>
        </div>
      )}

      {/* Decorative Aurora Cyberpunk Backdrops */}
      <div className="grid-bg-overlay" />
      <div className="aurora-blur-top" />
      <div className="aurora-blur-bottom" />
      <div className="scanline-overlay" />

      {/* PUBLIC NAVBAR FROM REDEYE.HTML */}
      <header className="header" style={{ borderBottom: '1px solid var(--border-subtle)', backgroundColor: 'var(--bg-recessed)' }}>
        <div className="logo" onClick={() => { if (!isLoggedIn) setActivePage('home'); }} style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <div className="logo-mark" style={{ background: 'var(--accent-red)', boxShadow: '0 0 12px rgba(255, 59, 48, 0.4)' }}>
            <svg viewBox="0 0 24 24" style={{ width: '20px', height: '20px', fill: 'white' }}><path d="M12 4.5C7 4.5 2.73 7.61 1 12c1.73 4.39 6 7.5 11 7.5s9.27-3.11 11-7.5c-1.73-4.39-6-7.5-11-7.5zM12 17c-2.76 0-5-2.24-5-5s2.24-5 5-5 5 2.24 5 5-2.24 5-5 5zm0-8c-1.66 0-3 1.34-3 3s1.34 3 3 3 3-1.34 3-3-1.34-3-3-3z" /></svg>
          </div>
          {isLoggedIn ? (
            <div style={{ display: 'flex', flexDirection: 'column', lineHeight: 1.1 }}>
              <span style={{ fontSize: '15px', fontWeight: 800, letterSpacing: '2px', color: '#fff' }}>
                REDEYE-<span style={{ color: 'var(--accent-cyan)' }}>C2</span>
              </span>
              <span style={{ fontSize: '8px', fontWeight: 600, color: 'var(--accent-red)', letterSpacing: '1.5px' }}>
                VIGILANCE-ACTIVE
              </span>
            </div>
          ) : (
            <div className="logo-text">RED<em>EYE</em></div>
          )}
        </div>

        {!isLoggedIn ? (
          <>
            <nav className="top-nav">
              <a className={activePage === 'home' ? 'active' : ''} onClick={() => setActivePage('home')}>Home</a>
              <a className={activePage === 'about' ? 'active' : ''} onClick={() => setActivePage('about')}>About</a>
              <a className={activePage === 'contact' ? 'active' : ''} onClick={() => setActivePage('contact')}>Contact</a>
              <a className={activePage === 'pricing' ? 'active' : ''} onClick={() => setActivePage('pricing')}>Pricing</a>
            </nav>

            <div className="header-right">
              <div className="live-dot" title="System Online"></div>
              <button className="btn-login" onClick={() => setActivePage('login')}>Login</button>
            </div>
          </>
        ) : (
          <>
            {/* Search Input and status icons */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '20px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', background: 'rgba(255, 255, 255, 0.03)', border: '1px solid var(--border-subtle)', borderRadius: '4px', padding: '6px 12px', width: '320px' }}>
                <Search size={14} style={{ color: 'var(--text-dim)' }} />
                <input
                  type="text"
                  placeholder={activeSidebarTab === 'nodes' ? 'QUERY NODES...' : activeSidebarTab === 'console' ? 'COMMAND DICTIONARY...' : 'FILTER ASSETS...'}
                  style={{ background: 'none', border: 'none', color: '#fff', fontSize: '11px', outline: 'none', width: '100%', fontFamily: 'var(--font-mono)' }}
                />
              </div>

              {/* Header icons */}
              <div style={{ display: 'flex', alignItems: 'center', gap: '14px', color: 'var(--text-muted)' }}>
                <ShieldAlert
                  size={16}
                  style={{ cursor: 'pointer' }}
                  className={activeSidebarTab === 'incidents' ? 's-on' : ''}
                  onClick={() => setActiveSidebarTab('incidents')}
                  title="Alert incidents stream"
                />
                <Activity
                  size={16}
                  style={{ cursor: 'pointer' }}
                  className={activeSidebarTab === 'telemetry' ? 's-on' : ''}
                  onClick={() => setActiveSidebarTab('telemetry')}
                  title="Active telemetry channels"
                />
                <Laptop
                  size={16}
                  style={{ cursor: 'pointer' }}
                  className={activeSidebarTab === 'endpoints' ? 's-on' : ''}
                  onClick={() => setActiveSidebarTab('endpoints')}
                  title="Endpoints audit tracker"
                />
              </div>
            </div>

            <div className="header-right" style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
              {/* Uptime indicators */}
              <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', fontFamily: 'var(--font-mono)', fontSize: '10px', color: 'var(--text-muted)', borderRight: '1px solid var(--border-subtle)', paddingRight: '14px', lineHeight: '1.3' }}>
                <div style={{ color: '#fff', fontWeight: 'bold' }}>DB: DEMO_RE</div>
                <div>UPTIME: 142:12:13:23</div>
              </div>

              {/* Deploy Agent Button */}
              <button
                className="btn-login"
                onClick={() => {
                  setActiveSidebarTab('endpoints');
                  setDetailAgentId(null);
                  alert('Deploy options: Run agent from source or build/deploy executable stager below.');
                }}
                style={{
                  background: 'none',
                  border: '1px solid var(--accent-cyan)',
                  color: 'var(--accent-cyan)',
                  fontSize: '11px',
                  fontWeight: 700,
                  textTransform: 'uppercase',
                  letterSpacing: '1.5px',
                  borderRadius: '4px',
                  padding: '6px 12px'
                }}
              >
                Deploy Agent
              </button>

              <div
                className="user-avatar"
                title="Active Operator"
                style={{
                  width: '30px',
                  height: '30px',
                  background: 'rgba(0, 242, 255, 0.1)',
                  border: '1px solid var(--accent-cyan)',
                  color: 'var(--accent-cyan)',
                  fontSize: '11px',
                  fontWeight: 'bold',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  borderRadius: '50%'
                }}
              >
                OP
              </div>
              <button className="btn-login" onClick={handleLogout} style={{ fontSize: '11px', padding: '6px 12px' }}>Logout</button>
            </div>
          </>
        )}
        <div className="header-glow"></div>
      </header>

      {/* CORE CONTENT LAYOUT SWITCH */}
      {!isLoggedIn ? (
        /* PUBLIC VISITOR PAGES */
        <main className="public-container">

          {/* HOME VIEW */}
          {activePage === 'home' && (
            <div className="hero-section">
              <h2 className="hero-glow-text">RedEye C2</h2>
              <p className="hero-description">
                A premium, cross-platform remote administration, telemetry, and security monitoring gateway. RedEye provides command line terminal control, diagnostics, and visual analytics over target systems backed by PostgreSQL.
              </p>
              <button className="cta-button" onClick={() => setActivePage('pricing')}>View License Options</button>

              <div className="features-grid">
                <div className="feature-card">
                  <div className="feature-icon-wrapper"><Laptop size={20} /></div>
                  <h3>Multi-Platform Deamons</h3>
                  <p>Pre-configured lightweight agent architectures developed for Windows environments, Linux server units, and Android background frameworks.</p>
                </div>
                <div className="feature-card">
                  <div className="feature-icon-wrapper"><Terminal size={20} /></div>
                  <h3>Interactive Terminal</h3>
                  <p>Queue shell diagnostics directly to remote system loops. Retrieves active process grids, system specs, and network card metrics.</p>
                </div>
                <div className="feature-card">
                  <div className="feature-icon-wrapper"><Database size={20} /></div>
                  <h3>PostgreSQL Audit</h3>
                  <p>Complete data integrity mapped to the Demo_RE structure. Audits and traces SQL queries dynamically with sub-millisecond latencies.</p>
                </div>
              </div>
            </div>
          )}

          {/* ABOUT VIEW */}
          {activePage === 'about' && (
            <div className="about-content">
              <h2 className="page-title">Platform Architecture</h2>
              <p className="page-subtitle">Understand how the RedEye C2 gateway commands remote daemons through the secure REST framework.</p>

              <div className="info-block">
                <h3>Multi-Agent System Specifications</h3>
                <p>RedEye features platform-specific agent skeletons configured to run in secure target environments:</p>
                <ul>
                  <li><strong>Windows PowerShell Daemon:</strong> Utilizes WMI and Invoke-Expression to register device hardware and query process configurations.</li>
                  <li><strong>Linux Python Agent:</strong> Operates using subprocess pipelines to pull diagnostics and return shell stdout outputs.</li>
                  <li><strong>Android Kotlin Service:</strong> Employs standard HTTP polling and execution blocks to report device metrics and log activities.</li>
                </ul>
              </div>

              <div className="info-block">
                <h3>Database Schema Architecture</h3>
                <p>The system stores all tracking data inside the PostgreSQL database <code>Demo_RE</code> using three primary tables:</p>
                <ul>
                  <li><code>agents</code>: Stores target specs, IP addresses, OS types, and last seen indicators.</li>
                  <li><code>commands</code>: Tracks instruction lists, status flags, and returned command lines.</li>
                  <li><code>system_logs</code>: Houses administration audits and security warnings.</li>
                </ul>
              </div>
            </div>
          )}

          {/* CONTACT VIEW */}
          {activePage === 'contact' && (
            <div style={{ width: '100%' }}>
              <h2 className="page-title">Submit Inquiry</h2>
              <p className="page-subtitle">Send your system feedback or licensing queries directly to the developer team.</p>

              <div className="contact-container">
                <div className="contact-info">
                  <h3>Developer Desk</h3>
                  <p>Feel free to reach out for platform customizations or advanced security integration queries.</p>

                  <div className="contact-info-item">
                    <Mail className="contact-info-icon" size={18} />
                    <div className="contact-info-details">
                      <h4>Direct Email</h4>
                      <a href="mailto:desaivraj73@gmail.com">desaivraj73@gmail.com</a>
                    </div>
                  </div>

                  <div className="contact-info-item">
                    <Server className="contact-info-icon" size={18} />
                    <div className="contact-info-details">
                      <h4>Infrastructure Server</h4>
                      <p>PostgreSQL DB: Demo_RE (127.0.0.1:5432)</p>
                    </div>
                  </div>
                </div>

                <form className="contact-form" onSubmit={handleContactSubmit}>
                  <div className="form-group">
                    <label>Full Name</label>
                    <input
                      type="text"
                      className="form-input"
                      value={contactName}
                      onChange={(e) => setContactName(e.target.value)}
                      placeholder="e.g. Vraj Desai"
                      required
                    />
                  </div>
                  <div className="form-group">
                    <label>Email Address</label>
                    <input
                      type="email"
                      className="form-input"
                      value={contactEmail}
                      onChange={(e) => setContactEmail(e.target.value)}
                      placeholder="name@company.com"
                      required
                    />
                  </div>
                  <div className="form-group">
                    <label>Message / Request</label>
                    <textarea
                      className="form-input form-textarea"
                      value={contactMessage}
                      onChange={(e) => setContactMessage(e.target.value)}
                      placeholder="Specify your inquiry details here..."
                      required
                    ></textarea>
                  </div>

                  <button type="submit" className="form-submit-btn">
                    {contactSent ? 'Redirecting to Mail Client...' : 'Submit Message'}
                  </button>
                  {contactSent && (
                    <span style={{ fontSize: '11px', color: '#00ff66', textAlign: 'center' }}>
                      Opening mail application to forward query to <strong>desaivraj73@gmail.com</strong>
                    </span>
                  )}
                </form>
              </div>
            </div>
          )}

          {/* PRICING VIEW */}
          {activePage === 'pricing' && (
            <div style={{ width: '100%' }}>
              <h2 className="page-title">Licensing Plans</h2>
              <p className="page-subtitle">Select the licensing model that fits your remote monitoring infrastructure needs.</p>

              <div className="pricing-grid">
                <div className="pricing-card">
                  <span className="plan-name">1 Month</span>
                  <div className="plan-price">
                    <span className="plan-currency">₹</span>1,999
                    <span>/mo</span>
                  </div>
                  <div className="plan-features-list">
                    <div className="plan-feature-item"><Check size={14} /> <span>1 Active C2 Server</span></div>
                    <div className="plan-feature-item"><Check size={14} /> <span>Up to 10 Target Agents</span></div>
                    <div className="plan-feature-item"><Check size={14} /> <span>PostgreSQL Logs Support</span></div>
                  </div>
                  <button className="plan-select-btn" onClick={() => setActivePage('login')}>Choose Plan</button>
                </div>

                <div className="pricing-card">
                  <span className="plan-name">3 Months</span>
                  <div className="plan-price">
                    <span className="plan-currency">₹</span>6,999
                    <span>/3mo</span>
                  </div>
                  <div className="plan-features-list">
                    <div className="plan-feature-item"><Check size={14} /> <span>3 Active C2 Servers</span></div>
                    <div className="plan-feature-item"><Check size={14} /> <span>Up to 50 Target Agents</span></div>
                    <div className="plan-feature-item"><Check size={14} /> <span>Advanced SQL Traces</span></div>
                  </div>
                  <button className="plan-select-btn" onClick={() => setActivePage('login')}>Choose Plan</button>
                </div>

                <div className="pricing-card popular">
                  <span className="popular-badge">Popular</span>
                  <span className="plan-name">6 Months</span>
                  <div className="plan-price">
                    <span className="plan-currency">₹</span>9,999
                    <span>/6mo</span>
                  </div>
                  <div className="plan-features-list">
                    <div className="plan-feature-item"><Check size={14} /> <span>Unlimited C2 Nodes</span></div>
                    <div className="plan-feature-item"><Check size={14} /> <span>Up to 250 Target Agents</span></div>
                    <div className="plan-feature-item"><Check size={14} /> <span>Live Telemetry Metrics</span></div>
                    <div className="plan-feature-item"><Check size={14} /> <span>Priority Tech Support</span></div>
                  </div>
                  <button className="plan-select-btn" onClick={() => setActivePage('login')}>Choose Plan</button>
                </div>

                <div className="pricing-card">
                  <span className="plan-name">Lifetime</span>
                  <div className="plan-price">
                    <span className="plan-currency">₹</span>14,999
                    <span>/once</span>
                  </div>
                  <div className="plan-features-list">
                    <div className="plan-feature-item"><Check size={14} /> <span>Unlimited Targets & Servers</span></div>
                    <div className="plan-feature-item"><Check size={14} /> <span>Lifetime Feature Updates</span></div>
                    <div className="plan-feature-item"><Check size={14} /> <span>Full Source Access Skeletons</span></div>
                    <div className="plan-feature-item"><Check size={14} /> <span>Custom Android APK Bindings</span></div>
                  </div>
                  <button className="plan-select-btn" onClick={() => setActivePage('login')}>Get Lifetime</button>
                </div>
              </div>
            </div>
          )}

          {/* LOGIN VIEW */}
          {activePage === 'login' && (
            <div className="login-container">
              <div className="login-header">
                <h2>C2 Gateway Authentication</h2>
                <p>Provide administrative credentials to open the PostgreSQL dashboard wrapper.</p>
              </div>

              {loginError && (
                <div style={{ color: '#ff3333', background: 'rgba(255,51,51,0.1)', border: '1px solid rgba(255,51,51,0.3)', padding: '10px', borderRadius: '4px', fontSize: '12px', display: 'flex', gap: '8px' }}>
                  <AlertCircle size={16} style={{ flexShrink: 0 }} />
                  <span>{loginError}</span>
                </div>
              )}

              <form onSubmit={handleLoginSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                <div className="form-group">
                  <label>Operator ID</label>
                  <div style={{ position: 'relative' }}>
                    <User size={14} style={{ position: 'absolute', left: '12px', top: '15px', color: 'var(--text-muted)' }} />
                    <input
                      type="text"
                      className="form-input"
                      style={{ paddingLeft: '36px', width: '100%' }}
                      value={loginUser}
                      onChange={(e) => setLoginUser(e.target.value)}
                      required
                    />
                  </div>
                </div>
                <div className="form-group">
                  <label>Security Keyphrase</label>
                  <div style={{ position: 'relative' }}>
                    <Lock size={14} style={{ position: 'absolute', left: '12px', top: '15px', color: 'var(--text-muted)' }} />
                    <input
                      type="password"
                      className="form-input"
                      style={{ paddingLeft: '36px', width: '100%' }}
                      value={loginPass}
                      onChange={(e) => setLoginPass(e.target.value)}
                      required
                    />
                  </div>
                </div>

                <div style={{ background: 'rgba(255,255,255,0.02)', padding: '10px', borderRadius: '4px', border: '1px dashed rgba(255,42,42,0.15)', fontSize: '11px', color: 'var(--text-muted)' }}>
                  <span>Default credentials loaded for testing:</span>
                  <br />
                  <span>User: <strong>admin</strong> | Pass: <strong>redeye-secret</strong></span>
                </div>

                <button type="submit" className="form-submit-btn">
                  Initialize Console Connection
                </button>
              </form>
            </div>
          )}

        </main>
      ) : (
        /* AUTHENTICATED C2 AREA LAYOUT WITH COLLAPSIBLE SIDEBAR */
        <div className="app">
          {/* SIDEBAR */}
          <aside className={`sidebar open ${sidebarCollapsed ? 'slim' : ''}`} style={{ backgroundColor: 'var(--bg-obsidian)', borderRight: '1px solid var(--border-subtle)', display: 'flex', flexDirection: 'column' }}>
            <button className="sb-toggle" onClick={() => setSidebarCollapsed(!sidebarCollapsed)} style={{ margin: '8px', border: '1px solid var(--border-subtle)', background: 'none', color: 'var(--text-muted)' }}>
              <svg viewBox="0 0 24 24" strokeWidth="2" stroke="currentColor" fill="none" style={{ width: '15px', height: '15px' }}><line x1="3" y1="12" x2="21" y2="12" /><line x1="3" y1="6" x2="21" y2="6" /><line x1="3" y1="18" x2="21" y2="18" /></svg>
              <span>{sidebarCollapsed ? '' : 'Collapse Menu'}</span>
            </button>

            <div className="sb-group" style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
              {!sidebarCollapsed && <div className="sb-label">OPERATIONS</div>}

              {/* Nodes */}
              <div
                className={`sb-item ${activeSidebarTab === 'nodes' ? 'hud-sidebar-active' : ''}`}
                onClick={() => { setActiveSidebarTab('nodes'); setDetailAgentId(null); logSql("SELECT * FROM agents;"); }}
              >
                {activeSidebarTab === 'nodes' && <div className="hud-power-bar" />}
                <Server size={17} />
                <span>Nodes</span>
              </div>

              {/* Agents */}
              <div
                className={`sb-item ${activeSidebarTab === 'agents' ? 'hud-sidebar-active' : ''}`}
                onClick={() => { setActiveSidebarTab('agents'); setDetailAgentId(null); logSql("SELECT * FROM agents;"); }}
              >
                {activeSidebarTab === 'agents' && <div className="hud-power-bar" />}
                <Cpu size={17} />
                <span>Agents</span>
              </div>

              {/* Endpoints */}
              <div
                className={`sb-item ${activeSidebarTab === 'endpoints' ? 'hud-sidebar-active' : ''}`}
                onClick={() => { setActiveSidebarTab('endpoints'); setDetailAgentId(null); logSql("SELECT * FROM agents_audit_log;"); }}
              >
                {activeSidebarTab === 'endpoints' && <div className="hud-power-bar" />}
                <Laptop size={17} />
                <span>Endpoints</span>
              </div>

              {/* Network */}
              <div
                className={`sb-item ${activeSidebarTab === 'network' ? 'hud-sidebar-active' : ''}`}
                onClick={() => { setActiveSidebarTab('network'); logSql("SELECT * FROM network_topology;"); }}
              >
                {activeSidebarTab === 'network' && <div className="hud-power-bar" />}
                <Globe size={17} />
                <span>Network</span>
              </div>

              {/* Console */}
              <div
                className={`sb-item ${activeSidebarTab === 'console' ? 'hud-sidebar-active' : ''}`}
                onClick={() => { setActiveSidebarTab('console'); logSql("SELECT * FROM command_queue;"); }}
              >
                {activeSidebarTab === 'console' && <div className="hud-power-bar" />}
                <Terminal size={17} />
                <span>Console</span>
              </div>
            </div>

            <div className="sb-divider" />

            <div className="sb-group" style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
              {!sidebarCollapsed && <div className="sb-label">MONITORING</div>}

              {/* Incidents */}
              <div
                className={`sb-item ${activeSidebarTab === 'incidents' ? 'hud-sidebar-active' : ''}`}
                onClick={() => { setActiveSidebarTab('incidents'); logSql("SELECT * FROM threat_events;"); }}
              >
                {activeSidebarTab === 'incidents' && <div className="hud-power-bar" />}
                <ShieldAlert size={17} />
                <span>Incidents</span>
              </div>

              {/* Telemetry */}
              <div
                className={`sb-item ${activeSidebarTab === 'telemetry' ? 'hud-sidebar-active' : ''}`}
                onClick={() => { setActiveSidebarTab('telemetry'); logSql("SELECT * FROM network_telemetry;"); }}
              >
                {activeSidebarTab === 'telemetry' && <div className="hud-power-bar" />}
                <Activity size={17} />
                <span>Telemetry</span>
              </div>

              {/* Logs */}
              <div
                className={`sb-item ${activeSidebarTab === 'logs' ? 'hud-sidebar-active' : ''}`}
                onClick={() => { setActiveSidebarTab('logs'); logSql("SELECT * FROM system_audit_logs;"); }}
              >
                {activeSidebarTab === 'logs' && <div className="hud-power-bar" />}
                <Database size={17} />
                <span>Logs</span>
              </div>
            </div>

            <div style={{ flexGrow: 1 }} />

            {/* INITIATE SCAN button */}
            <button
              className={`hud-scan-btn ${isScanning ? 'scanning' : ''}`}
              onClick={handleScan}
            >
              <Zap size={14} className={isScanning ? 'slow-spin' : ''} />
              <span>{sidebarCollapsed ? 'SCAN' : 'INITIATE SCAN'}</span>
            </button>

            <div className="sb-divider" />

            <div className="sb-group" style={{ display: 'flex', flexDirection: 'column', gap: '4px', marginBottom: '8px' }}>
              {/* Settings */}
              <div
                className={`sb-item ${activeSidebarTab === 'settings' ? 'hud-sidebar-active' : ''}`}
                onClick={() => { setActiveSidebarTab('settings'); logSql("SHOW CONFIG;"); }}
              >
                {activeSidebarTab === 'settings' && <div className="hud-power-bar" />}
                <Settings size={17} />
                <span>Settings</span>
              </div>

              {/* Lock screen */}
              <div
                className="sb-item"
                onClick={() => setIsLocked(true)}
              >
                <Lock size={17} />
                <span>Lock Screen</span>
              </div>
            </div>
          </aside>

          {/* MAIN PANELS FROM REDEYE.HTML */}
          <main className="main">

            {/* 1. NODES VIEWPORT */}
            {activeSidebarTab === 'nodes' && (
              <div className="page active">
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                  <div>
                    <div className="page-title">Nodes Monitor</div>
                    <div className="page-sub">Central tracking of target daemons and server infrastructure</div>
                  </div>
                  {/* Nodes sub-view switcher */}
                  <div style={{ display: 'flex', gap: '6px' }}>
                    <button
                      className={`scan-btn ${nodesSubView === 'overview' ? 'active' : ''}`}
                      onClick={() => setNodesSubView('overview')}
                      style={{ padding: '6px 12px', fontSize: '10px', textTransform: 'uppercase', fontFamily: 'var(--font-mono)', borderRadius: '3px' }}
                    >
                      ■ System Overview
                    </button>
                    <button
                      className={`scan-btn ${nodesSubView === 'inventory' ? 'active' : ''}`}
                      onClick={() => setNodesSubView('inventory')}
                      style={{ padding: '6px 12px', fontSize: '10px', textTransform: 'uppercase', fontFamily: 'var(--font-mono)', borderRadius: '3px' }}
                    >
                      ■ Agent Inventory Matrix
                    </button>
                  </div>
                </div>

                {nodesSubView === 'overview' ? (
                  /* SYSTEM OVERVIEW SUB-VIEW (IMAGE 1) */
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                    {/* Metrics Cards Grid */}
                    <div className="stat-grid" style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '16px' }}>
                      <div className="stat" style={{ borderLeft: '3px solid var(--accent-cyan)' }}>
                        <div className="stat-lbl" style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                          <div className="hud-glyph cyan" />
                          <span>Active Agents</span>
                        </div>
                        <div className="stat-val" style={{ color: 'var(--accent-cyan)', fontFamily: 'var(--font-mono)' }}>
                          {agents.filter(a => a.status === 'online').length}
                        </div>
                        <div className="stat-hint">~ {agents.filter(a => a.status === 'online').length} active daemon session{agents.filter(a => a.status === 'online').length !== 1 ? 's' : ''}</div>
                      </div>

                      <div className="stat" style={{ borderLeft: '3px solid var(--accent-red)', boxShadow: '0 0 10px rgba(255, 59, 48, 0.05)' }}>
                        <div className="stat-lbl" style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                          <div className="hud-glyph red" />
                          <span>Security Threats</span>
                        </div>
                        <div className="stat-val" style={{ color: 'var(--accent-red)', fontFamily: 'var(--font-mono)' }}>
                          {alerts.length}
                        </div>
                        <div className="stat-hint" style={{ color: 'var(--accent-red)' }}>▲ {alerts.filter(a => a.severity?.toLowerCase() === 'critical').length} CRITICAL INCIDENT{alerts.filter(a => a.severity?.toLowerCase() === 'critical').length !== 1 ? 'S' : ''}</div>
                      </div>

                      <div className="stat" style={{ borderLeft: '3px solid var(--text-dim)' }}>
                        <div className="stat-lbl" style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                          <div className="hud-glyph muted" />
                          <span>Database Logs</span>
                        </div>
                        <div className="stat-val" style={{ fontFamily: 'var(--font-mono)', color: '#fff' }}>
                          {systemLogs.length}
                        </div>
                        <div className="stat-hint">LIVE DB ENGINE SYNC</div>
                      </div>

                      <div className="stat" style={{ borderLeft: '3px solid var(--accent-cyan)' }}>
                        <div className="stat-lbl" style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                          <div className="hud-glyph cyan" />
                          <span>API Queries</span>
                        </div>
                        <div className="stat-val" style={{ color: 'var(--accent-cyan)', fontFamily: 'var(--font-mono)' }}>
                          {apiTraffic.length}
                        </div>
                        <div className="stat-hint">LIVE API ROUTE TRAFFIC</div>
                      </div>
                    </div>

                    {/* Middle Section: Resource Telemetry & Incident Stream */}
                    <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 1fr', gap: '16px', alignItems: 'stretch' }}>

                      {/* Left: Resource Telemetry Charts */}
                      <div className="hud-panel" style={{ display: 'flex', flexDirection: 'column', flexGrow: 1 }}>
                        <div className="hud-panel-header">
                          <span style={{ fontWeight: 'bold' }}>RESOURCE TELEMETRY</span>
                          <span style={{ fontSize: '10px', color: 'var(--accent-cyan)', fontFamily: 'var(--font-mono)' }}>CPU: 42% · RAM: 68%</span>
                        </div>
                        <div style={{ flex: 1, minHeight: '180px', display: 'flex', alignItems: 'center', justifyContent: 'center', padding: '10px', position: 'relative' }}>
                          <svg viewBox="0 0 500 150" style={{ width: '100%', height: '150px', display: 'block' }}>
                            <defs>
                              <linearGradient id="waveGlow" x1="0" y1="0" x2="0" y2="1">
                                <stop offset="0%" stopColor="var(--accent-cyan)" stopOpacity="0.3" />
                                <stop offset="100%" stopColor="var(--accent-cyan)" stopOpacity="0.0" />
                              </linearGradient>
                            </defs>

                            {/* Histogram bar columns representing CPU */}
                            {telemetryData.cpu.map((val, idx) => {
                              const barWidth = 10;
                              const barSpacing = 14;
                              const x = idx * (barWidth + barSpacing) + 12;
                              const height = (val / 100) * 110;
                              const y = 140 - height;
                              return (
                                <rect
                                  key={idx}
                                  x={x}
                                  y={y}
                                  width={barWidth}
                                  height={height}
                                  fill="rgba(0, 242, 255, 0.08)"
                                  stroke="rgba(0, 242, 255, 0.35)"
                                  strokeWidth="1"
                                />
                              );
                            })}

                            {/* Smooth wave area representation representing RAM */}
                            <path
                              d={getSvgAreaPath(telemetryData.ram)}
                              fill="url(#waveGlow)"
                            />
                            <path
                              d={getSvgPath(telemetryData.ram)}
                              fill="none"
                              stroke="var(--accent-cyan)"
                              strokeWidth="2"
                              style={{ filter: 'drop-shadow(0 0 3px var(--accent-cyan))' }}
                            />
                          </svg>
                        </div>
                      </div>

                      {/* Right: Live Incident Stream */}
                      <div className="hud-panel" style={{ display: 'flex', flexDirection: 'column' }}>
                        <div className="hud-panel-header">
                          <span style={{ fontWeight: 'bold' }}>LIVE INCIDENT STREAM</span>
                          <span style={{ fontSize: '10px', color: 'var(--accent-cyan)', fontFamily: 'var(--font-mono)' }}>AUTO-REFRESH: ON</span>
                        </div>
                        <div style={{ flex: 1, padding: '10px', overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '8px', maxHeight: '200px' }}>
                          {alerts.slice(0, 4).map((alert, idx) => {
                            const isCritical = alert.severity === 'CRITICAL' || alert.severity === 'critical';
                            return (
                              <div key={alert.id || idx} style={{ display: 'flex', alignItems: 'flex-start', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '6px', fontSize: '11px' }}>
                                <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                                  <span style={{ width: '6px', height: '6px', borderRadius: '50%', background: isCritical ? 'var(--accent-red)' : 'var(--accent-cyan)', boxShadow: isCritical ? '0 0 6px var(--accent-red)' : 'none' }}></span>
                                  <div style={{ fontFamily: 'var(--font-mono)', fontWeight: 'bold', color: isCritical ? 'var(--accent-red)' : '#fff' }}>{alert.type || 'EVENT'}</div>
                                </div>
                                <div style={{ flex: 1, marginLeft: '12px', color: 'var(--text-muted)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                                  {alert.message}
                                </div>
                                <div style={{ color: 'var(--text-dim)', fontSize: '10px', fontFamily: 'var(--font-mono)' }}>{formatLocalTime(alert.timestamp).split(' ')[1] || '14:02:11'}</div>
                              </div>
                            );
                          })}
                        </div>
                        <button
                          className="scan-btn"
                          onClick={() => setActiveSidebarTab('incidents')}
                          style={{ margin: '8px', padding: '6px', fontSize: '10px', border: '1px solid var(--border-subtle)', background: 'none', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '1px' }}
                        >
                          EXPAND INCIDENT HISTORY
                        </button>
                      </div>
                    </div>

                    {/* Bottom Row: Breakdown and Latency */}
                    <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 1.0fr', gap: '16px' }}>
                      {/* Host Platform Breakdown */}
                      <div className="hud-panel">
                        <div className="hud-panel-header">■ HOST PLATFORM BREAKDOWN</div>
                        <div style={{ padding: '12px', display: 'flex', flexDirection: 'column', gap: '10px' }}>
                          {(() => {
                            const total = agents.length || 1;
                            const winCount = agents.filter(a => a.platform?.toLowerCase() === 'windows').length;
                            const winPct = Math.round((winCount / total) * 100);
                            const lnxCount = agents.filter(a => a.platform?.toLowerCase() === 'linux').length;
                            const lnxPct = Math.round((lnxCount / total) * 100);
                            const andCount = agents.filter(a => a.platform?.toLowerCase() === 'android').length;
                            const andPct = Math.round((andCount / total) * 100);

                            return (
                              <>
                                <div>
                                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '10px', color: 'var(--text-muted)', marginBottom: '4px', fontFamily: 'var(--font-mono)' }}>
                                    <span>WINDOWS SYSTEMS</span>
                                    <span style={{ color: 'var(--accent-cyan)' }}>{winPct}% ({winCount} Agent{winCount !== 1 ? 's' : ''})</span>
                                  </div>
                                  <div className="hud-progress-wrap">
                                    <div style={{ width: `${winPct}%`, height: '100%', background: 'var(--accent-cyan)', boxShadow: '0 0 6px var(--accent-cyan)' }} />
                                  </div>
                                </div>

                                <div>
                                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '10px', color: 'var(--text-muted)', marginBottom: '4px', fontFamily: 'var(--font-mono)' }}>
                                    <span>LINUX SERVER DAEMONS</span>
                                    <span style={{ color: 'var(--accent-red)' }}>{lnxPct}% ({lnxCount} Agent{lnxCount !== 1 ? 's' : ''})</span>
                                  </div>
                                  <div className="hud-progress-wrap">
                                    <div style={{ width: `${lnxPct}%`, height: '100%', background: 'var(--accent-red)' }} />
                                  </div>
                                </div>

                                <div>
                                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '10px', color: 'var(--text-muted)', marginBottom: '4px', fontFamily: 'var(--font-mono)' }}>
                                    <span>ANDROID BACKGROUND ENDPOINTS</span>
                                    <span style={{ color: '#fff' }}>{andPct}% ({andCount} Agent{andCount !== 1 ? 's' : ''})</span>
                                  </div>
                                  <div className="hud-progress-wrap">
                                    <div style={{ width: `${andPct}%`, height: '100%', background: 'var(--text-dim)' }} />
                                  </div>
                                </div>
                              </>
                            );
                          })()}
                        </div>
                      </div>

                      {/* Global Latency Indicator */}
                      <div className="hud-panel" style={{ display: 'flex', flexDirection: 'column' }}>
                        <div className="hud-panel-header">■ GLOBAL LATENCY</div>
                        <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '12px 20px' }}>
                          <div style={{ display: 'flex', flexDirection: 'column' }}>
                            <span style={{ fontSize: '24px', fontWeight: 800, fontFamily: 'var(--font-mono)', color: 'var(--accent-cyan)', textShadow: '0 0 10px rgba(0, 242, 255, 0.4)' }}>14.2 MS</span>
                            <span style={{ fontSize: '9px', color: 'var(--text-muted)', letterSpacing: '1px' }}>AVERAGE RESPONSE PING</span>
                          </div>
                          {/* Latency signal columns bars */}
                          <div className="hud-latency-bars">
                            <div className="bar active" />
                            <div className="bar active" />
                            <div className="bar active" />
                            <div className="bar active" />
                            <div className="bar active" />
                            <div className="bar active" />
                            <div className="bar" />
                            <div className="bar" />
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                ) : (
                  /* AGENT INVENTORY MATRIX SUB-VIEW (IMAGE 3) */
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                    {/* Top Metrics Row */}
                    <div style={{ display: 'flex', gap: '16px', justifyContent: 'space-between' }}>
                      <div style={{ flex: 1, padding: '8px 12px', background: 'var(--bg-recessed)', border: '1px solid var(--border-subtle)', borderRadius: '4px', fontFamily: 'var(--font-mono)' }}>
                        <div style={{ fontSize: '9px', color: 'var(--text-dim)' }}>TOTAL_NODES</div>
                        <div style={{ fontSize: '16px', fontWeight: 'bold', color: '#fff' }}>{agents.length}</div>
                      </div>
                      <div style={{ flex: 1, padding: '8px 12px', background: 'var(--bg-recessed)', border: '1px solid var(--border-subtle)', borderRadius: '4px', fontFamily: 'var(--font-mono)' }}>
                        <div style={{ fontSize: '9px', color: 'var(--text-dim)' }}>ACTIVE_SESSIONS</div>
                        <div style={{ fontSize: '16px', fontWeight: 'bold', color: 'var(--accent-cyan)' }}>{agents.filter(a => a.status === 'online').length}</div>
                      </div>
                      <div style={{ flex: 1, padding: '8px 12px', background: 'var(--bg-recessed)', border: '1px solid var(--border-subtle)', borderRadius: '4px', fontFamily: 'var(--font-mono)' }}>
                        <div style={{ fontSize: '9px', color: 'var(--text-dim)' }}>CRITICAL_THREATS</div>
                        <div style={{ fontSize: '16px', fontWeight: 'bold', color: 'var(--accent-red)' }}>
                          {alerts.filter(a => a.severity?.toLowerCase() === 'critical').length}
                        </div>
                      </div>
                      <div style={{ flex: 1, padding: '8px 12px', background: 'var(--bg-recessed)', border: '1px solid var(--border-subtle)', borderRadius: '4px', fontFamily: 'var(--font-mono)' }}>
                        <div style={{ fontSize: '9px', color: 'var(--text-dim)' }}>UPLINK_STABILITY</div>
                        <div style={{ fontSize: '16px', fontWeight: 'bold', color: 'var(--accent-cyan)' }}>
                          {agents.length > 0 ? `${((agents.filter(a => a.status === 'online').length / agents.length) * 100).toFixed(1)}%` : '100%'}
                        </div>
                      </div>
                    </div>

                    {/* Main Agent Matrix Table */}
                    <div className="hud-panel">
                      <div className="hud-panel-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <span>■ AGENT_INVENTORY_MATRIX</span>
                        <div style={{ display: 'flex', gap: '4px', marginRight: '8px' }}>
                          {['ALL', 'Windows', 'Android', 'Linux'].map(plat => (
                            <button
                              key={plat}
                              onClick={() => setPlatformFilter(plat)}
                              className="scan-btn"
                              style={{
                                padding: '2px 8px',
                                fontSize: '9px',
                                background: platformFilter === plat ? 'var(--accent-cyan)' : 'transparent',
                                color: platformFilter === plat ? '#000' : 'var(--text-muted)',
                                borderColor: platformFilter === plat ? 'var(--accent-cyan)' : 'var(--border-subtle)',
                                textTransform: 'uppercase',
                                cursor: 'pointer'
                              }}
                            >
                              {plat}
                            </button>
                          ))}
                        </div>
                      </div>
                      <div className="tbl-wrap" style={{ margin: 0, border: 'none' }}>
                        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                          <thead>
                            <tr style={{ borderBottom: '1px solid var(--border-subtle)', fontSize: '10px', textTransform: 'uppercase', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                              <th style={{ width: '30px', padding: '10px' }}><input type="checkbox" readOnly /></th>
                              <th style={{ textAlign: 'left', padding: '10px' }}>HOSTNAME</th>
                              <th style={{ textAlign: 'left', padding: '10px' }}>PLATFORM</th>
                              <th style={{ textAlign: 'left', padding: '10px' }}>STATUS</th>
                              <th style={{ textAlign: 'left', padding: '10px' }}>IP ADDRESS</th>
                              <th style={{ textAlign: 'left', padding: '10px' }}>LAST SEEN</th>
                              <th style={{ textAlign: 'left', padding: '10px', width: '100px' }}>RISK</th>
                              <th style={{ textAlign: 'center', padding: '10px', width: '120px' }}>ACTIONS</th>
                            </tr>
                          </thead>
                          <tbody>
                            {agents.filter(agent => platformFilter === 'ALL' || (agent.platform || '').toLowerCase() === platformFilter.toLowerCase()).map((agent, index) => {
                              const risk = agent.risk_score ?? (20 + (index * 17) % 65);
                              const isOnline = agent.status === 'online';
                              const riskCol = risk < 40 ? 'var(--green)' : risk < 75 ? 'var(--yellow)' : 'var(--red)';

                              return (
                                <tr key={agent.id || index} style={{ borderBottom: '1px solid rgba(255,255,255,0.02)', fontSize: '11px', backgroundColor: index % 2 === 0 ? '#121214' : '#18181c' }}>
                                  <td style={{ padding: '10px', textAlign: 'center' }}><input type="checkbox" readOnly /></td>
                                  <td style={{ padding: '10px', fontWeight: 'bold', color: '#fff' }}>{agent.hostname}</td>
                                  <td style={{ padding: '10px' }}>
                                    <div style={{ display: 'flex', alignItems: 'center', gap: '6px', color: 'var(--text-muted)' }}>
                                      {getPlatformIcon(agent.platform)}
                                      <span>{agent.platform}</span>
                                    </div>
                                  </td>
                                  <td style={{ padding: '10px' }}>
                                    <span className={`badge ${isOnline ? 'bd-g' : 'bd-b'}`} style={{ fontSize: '9px', textTransform: 'uppercase' }}>{agent.status}</span>
                                  </td>
                                  <td style={{ padding: '10px', fontFamily: 'var(--font-mono)', color: 'var(--accent-cyan)' }}>{agent.ip_address}</td>
                                  <td style={{ padding: '10px', color: 'var(--text-dim)' }}>{formatLocalTime(agent.last_seen) || 'Never'}</td>
                                  <td style={{ padding: '10px' }}>
                                    <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                                      <div style={{ flex: 1, height: '4px', background: 'var(--bg)', borderRadius: '2px', overflow: 'hidden' }}>
                                        <div style={{ width: `${risk}%`, height: '100%', background: riskCol }} />
                                      </div>
                                      <span style={{ fontSize: '10px', fontFamily: 'var(--font-mono)', color: riskCol }}>{(risk / 100).toFixed(2)}</span>
                                    </div>
                                  </td>
                                  <td style={{ padding: '10px', textAlign: 'center' }}>
                                    <div style={{ display: 'flex', gap: '8px', justifyContent: 'center' }}>
                                      <Terminal
                                        size={13}
                                        style={{ cursor: 'pointer', color: 'var(--accent-cyan)' }}
                                        title="Console connection"
                                        onClick={() => {
                                          setSelectedAgentId(agent.id);
                                          setActiveSidebarTab('console');
                                        }}
                                      />
                                      <RefreshCw
                                        size={13}
                                        style={{ cursor: 'pointer', color: 'var(--text-muted)' }}
                                        title="Reboot agent loop"
                                        onClick={() => handleRestartAgent(agent)}
                                      />
                                      <FileText
                                        size={13}
                                        style={{ cursor: 'pointer', color: 'var(--text-muted)' }}
                                        title="System details"
                                        onClick={() => {
                                          setDetailAgentId(agent.id);
                                          setActiveSidebarTab('endpoints');
                                        }}
                                      />
                                    </div>
                                  </td>
                                </tr>
                              );
                            })}
                          </tbody>
                        </table>
                      </div>
                      <div style={{ display: 'flex', justifyContent: 'space-between', padding: '10px', borderTop: '1px solid var(--border-subtle)', fontSize: '10px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                        <div>ENTRIES: {agents.length}   FILTERED: {agents.filter(agent => platformFilter === 'ALL' || (agent.platform || '').toLowerCase() === platformFilter.toLowerCase()).length}   SELECTED: 00</div>
                        <div style={{ display: 'flex', gap: '10px', cursor: 'pointer' }}>
                          <span>FIRST</span>
                          <span>PREV</span>
                          <span style={{ color: 'var(--accent-cyan)' }}>PAGE 1 OF 1</span>
                          <span>NEXT</span>
                          <span>LAST</span>
                        </div>
                      </div>
                    </div>

                    {/* Bottom Split telemetry info */}
                    <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 1fr', gap: '16px' }}>
                      <div className="hud-panel">
                        <div className="hud-panel-header">■ SELECTED_AGENT_TELEMETRY</div>
                        <div style={{ padding: '12px', display: 'flex', flexDirection: 'column', gap: '10px' }}>
                          <div>
                            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '10px', color: 'var(--text-muted)', marginBottom: '4px', fontFamily: 'var(--font-mono)' }}>
                              <span>CPU UTILIZATION LINK</span>
                              <span>42%</span>
                            </div>
                            <div className="hud-progress-wrap"><div style={{ width: '42%', height: '100%', background: 'var(--accent-cyan)' }} /></div>
                          </div>
                          <div>
                            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '10px', color: 'var(--text-muted)', marginBottom: '4px', fontFamily: 'var(--font-mono)' }}>
                              <span>MEMORY COMMITTED</span>
                              <span>25.4% (4.1 GB / 16 GB)</span>
                            </div>
                            <div className="hud-progress-wrap"><div style={{ width: '25%', height: '100%', background: 'var(--accent-cyan)' }} /></div>
                          </div>
                          <div>
                            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '10px', color: 'var(--text-muted)', marginBottom: '4px', fontFamily: 'var(--font-mono)' }}>
                              <span>NETWORK LINK RATE</span>
                              <span>8.4 MB/S</span>
                            </div>
                            <div className="hud-progress-wrap"><div style={{ width: '60%', height: '100%', background: 'var(--accent-cyan)' }} /></div>
                          </div>
                        </div>
                      </div>

                      <div className="hud-panel">
                        <div className="hud-panel-header">■ SYSTEM_ALERTS</div>
                        <div style={{ padding: '10px', display: 'flex', flexDirection: 'column', gap: '6px', maxHeight: '120px', overflowY: 'auto' }}>
                          <div style={{ fontSize: '11px', display: 'flex', gap: '6px', alignItems: 'center', borderBottom: '1px solid rgba(255,255,255,0.02)', paddingBottom: '4px' }}>
                            <span style={{ color: 'var(--accent-red)', fontWeight: 'bold' }}>[!] CRITICAL</span>
                            <span style={{ color: 'var(--text-muted)', flex: 1, textOverflow: 'ellipsis', overflow: 'hidden', whiteSpace: 'nowrap' }}>Suspicious egress detected on node RE-WIN-MAIN</span>
                          </div>
                          <div style={{ fontSize: '11px', display: 'flex', gap: '6px', alignItems: 'center', borderBottom: '1px solid rgba(255,255,255,0.02)', paddingBottom: '4px' }}>
                            <span style={{ color: 'var(--accent-red)', fontWeight: 'bold' }}>[!] CRITICAL</span>
                            <span style={{ color: 'var(--text-muted)', flex: 1, textOverflow: 'ellipsis', overflow: 'hidden', whiteSpace: 'nowrap' }}>Brute-force SSH attack blocked on 192.168.1.18</span>
                          </div>
                          <div style={{ fontSize: '11px', display: 'flex', gap: '6px', alignItems: 'center' }}>
                            <span style={{ color: 'var(--text-dim)', fontWeight: 'bold' }}>[*] INFO</span>
                            <span style={{ color: 'var(--text-muted)', flex: 1, textOverflow: 'ellipsis', overflow: 'hidden', whiteSpace: 'nowrap' }}>Operator session authenticated from enclave gateway</span>
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* 1.5. AGENTS VIEWPORT */}
            {activeSidebarTab === 'agents' && (
              <div className="page active">
                <div className="page-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
                  <div>
                    <div className="page-title">Agents Manager</div>
                    <div className="page-sub">Operational status, telemetry metrics, and orchestration targets</div>
                  </div>
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                  {/* Top Metrics Row */}
                  <div style={{ display: 'flex', gap: '16px', justifyContent: 'space-between' }}>
                    <div style={{ flex: 1, padding: '8px 12px', background: 'var(--bg-recessed)', border: '1px solid var(--border-subtle)', borderRadius: '4px', fontFamily: 'var(--font-mono)' }}>
                      <div style={{ fontSize: '9px', color: 'var(--text-dim)' }}>TOTAL_NODES</div>
                      <div style={{ fontSize: '16px', fontWeight: 'bold', color: '#fff' }}>{agents.length}</div>
                    </div>
                    <div style={{ flex: 1, padding: '8px 12px', background: 'var(--bg-recessed)', border: '1px solid var(--border-subtle)', borderRadius: '4px', fontFamily: 'var(--font-mono)' }}>
                      <div style={{ fontSize: '9px', color: 'var(--text-dim)' }}>ACTIVE_SESSIONS</div>
                      <div style={{ fontSize: '16px', fontWeight: 'bold', color: 'var(--accent-cyan)' }}>{agents.filter(a => a.status === 'online').length}</div>
                    </div>
                    <div style={{ flex: 1, padding: '8px 12px', background: 'var(--bg-recessed)', border: '1px solid var(--border-subtle)', borderRadius: '4px', fontFamily: 'var(--font-mono)' }}>
                      <div style={{ fontSize: '9px', color: 'var(--text-dim)' }}>CRITICAL_THREATS</div>
                      <div style={{ fontSize: '16px', fontWeight: 'bold', color: 'var(--accent-red)' }}>
                        {alerts.filter(a => a.severity?.toLowerCase() === 'critical').length}
                      </div>
                    </div>
                    <div style={{ flex: 1, padding: '8px 12px', background: 'var(--bg-recessed)', border: '1px solid var(--border-subtle)', borderRadius: '4px', fontFamily: 'var(--font-mono)' }}>
                      <div style={{ fontSize: '9px', color: 'var(--text-dim)' }}>UPLINK_STABILITY</div>
                      <div style={{ fontSize: '16px', fontWeight: 'bold', color: 'var(--accent-cyan)' }}>
                        {agents.length > 0 ? `${((agents.filter(a => a.status === 'online').length / agents.length) * 100).toFixed(1)}%` : '100%'}
                      </div>
                    </div>
                  </div>

                  {/* Main Agent Matrix Table */}
                  <div className="hud-panel">
                    <div className="hud-panel-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <span>■ AGENT_INVENTORY_MATRIX</span>
                      <div style={{ display: 'flex', gap: '4px', marginRight: '8px' }}>
                        {['ALL', 'Windows', 'Android', 'Linux'].map(plat => (
                          <button
                            key={plat}
                            onClick={() => setPlatformFilter(plat)}
                            className="scan-btn"
                            style={{
                              padding: '2px 8px',
                              fontSize: '9px',
                              background: platformFilter === plat ? 'var(--accent-cyan)' : 'transparent',
                              color: platformFilter === plat ? '#000' : 'var(--text-muted)',
                              borderColor: platformFilter === plat ? 'var(--accent-cyan)' : 'var(--border-subtle)',
                              textTransform: 'uppercase',
                              cursor: 'pointer'
                            }}
                          >
                            {plat}
                          </button>
                        ))}
                      </div>
                    </div>
                    <div className="tbl-wrap" style={{ margin: 0, border: 'none' }}>
                      <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                        <thead>
                          <tr style={{ borderBottom: '1px solid var(--border-subtle)', fontSize: '10px', textTransform: 'uppercase', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                            <th style={{ width: '30px', padding: '10px' }}><input type="checkbox" readOnly /></th>
                            <th style={{ textAlign: 'left', padding: '10px' }}>HOSTNAME</th>
                            <th style={{ textAlign: 'left', padding: '10px' }}>PLATFORM</th>
                            <th style={{ textAlign: 'left', padding: '10px' }}>STATUS</th>
                            <th style={{ textAlign: 'left', padding: '10px' }}>IP ADDRESS</th>
                            <th style={{ textAlign: 'left', padding: '10px' }}>LAST SEEN</th>
                            <th style={{ textAlign: 'left', padding: '10px', width: '100px' }}>RISK</th>
                            <th style={{ textAlign: 'center', padding: '10px', width: '120px' }}>ACTIONS</th>
                          </tr>
                        </thead>
                        <tbody>
                          {agents.filter(agent => platformFilter === 'ALL' || (agent.platform || '').toLowerCase() === platformFilter.toLowerCase()).map((agent, index) => {
                            const risk = agent.risk_score ?? (20 + (index * 17) % 65);
                            const isOnline = agent.status === 'online';
                            const riskCol = risk < 40 ? 'var(--green)' : risk < 75 ? 'var(--yellow)' : 'var(--red)';

                            return (
                              <tr key={agent.id || index} style={{ borderBottom: '1px solid rgba(255,255,255,0.02)', fontSize: '11px', backgroundColor: index % 2 === 0 ? '#121214' : '#18181c' }}>
                                <td style={{ padding: '10px', textAlign: 'center' }}><input type="checkbox" readOnly /></td>
                                <td style={{ padding: '10px', fontWeight: 'bold', color: '#fff' }}>{agent.hostname}</td>
                                <td style={{ padding: '10px' }}>
                                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px', color: 'var(--text-muted)' }}>
                                    {getPlatformIcon(agent.platform)}
                                    <span>{agent.platform}</span>
                                  </div>
                                </td>
                                <td style={{ padding: '10px' }}>
                                  <span className={`badge ${isOnline ? 'bd-g' : 'bd-b'}`} style={{ fontSize: '9px', textTransform: 'uppercase' }}>{agent.status}</span>
                                </td>
                                <td style={{ padding: '10px', fontFamily: 'var(--font-mono)', color: 'var(--accent-cyan)' }}>{agent.ip_address}</td>
                                <td style={{ padding: '10px', color: 'var(--text-dim)' }}>{formatLocalTime(agent.last_seen) || 'Never'}</td>
                                <td style={{ padding: '10px' }}>
                                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                                    <div style={{ flex: 1, height: '4px', background: 'var(--bg)', borderRadius: '2px', overflow: 'hidden' }}>
                                      <div style={{ width: `${risk}%`, height: '100%', background: riskCol }} />
                                    </div>
                                    <span style={{ fontSize: '10px', fontFamily: 'var(--font-mono)', color: riskCol }}>{(risk / 100).toFixed(2)}</span>
                                  </div>
                                </td>
                                <td style={{ padding: '10px', textAlign: 'center' }}>
                                  <div style={{ display: 'flex', gap: '8px', justifyContent: 'center' }}>
                                    <Terminal
                                      size={13}
                                      style={{ cursor: 'pointer', color: 'var(--accent-cyan)' }}
                                      title="Console connection"
                                      onClick={() => {
                                        setSelectedAgentId(agent.id);
                                        setActiveSidebarTab('console');
                                      }}
                                    />
                                    <RefreshCw
                                      size={13}
                                      style={{ cursor: 'pointer', color: 'var(--text-muted)' }}
                                      title="Reboot agent loop"
                                      onClick={() => handleRestartAgent(agent)}
                                    />
                                    <FileText
                                      size={13}
                                      style={{ cursor: 'pointer', color: 'var(--text-muted)' }}
                                      title="System details"
                                      onClick={() => {
                                        setDetailAgentId(agent.id);
                                        setActiveSidebarTab('endpoints');
                                      }}
                                    />
                                  </div>
                                </td>
                              </tr>
                            );
                          })}
                        </tbody>
                      </table>
                    </div>
                    <div style={{ display: 'flex', justifyContent: 'space-between', padding: '10px', borderTop: '1px solid var(--border-subtle)', fontSize: '10px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                      <div>ENTRIES: {agents.length}   FILTERED: {agents.filter(agent => platformFilter === 'ALL' || (agent.platform || '').toLowerCase() === platformFilter.toLowerCase()).length}   SELECTED: 00</div>
                      <div style={{ display: 'flex', gap: '10px', cursor: 'pointer' }}>
                        <span>FIRST</span>
                        <span>PREV</span>
                        <span style={{ color: 'var(--accent-cyan)' }}>PAGE 1 OF 1</span>
                        <span>NEXT</span>
                        <span>LAST</span>
                      </div>
                    </div>
                  </div>

                  {/* Bottom Split telemetry info */}
                  <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 1fr', gap: '16px' }}>
                    <div className="hud-panel">
                      <div className="hud-panel-header">■ SELECTED_AGENT_TELEMETRY</div>
                      <div style={{ padding: '12px', display: 'flex', flexDirection: 'column', gap: '10px' }}>
                        <div>
                          <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '10px', color: 'var(--text-muted)', marginBottom: '4px', fontFamily: 'var(--font-mono)' }}>
                            <span>CPU UTILIZATION LINK</span>
                            <span>42%</span>
                          </div>
                          <div className="hud-progress-wrap"><div style={{ width: '42%', height: '100%', background: 'var(--accent-cyan)' }} /></div>
                        </div>
                        <div>
                          <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '10px', color: 'var(--text-muted)', marginBottom: '4px', fontFamily: 'var(--font-mono)' }}>
                            <span>MEMORY COMMITTED</span>
                            <span>25.4% (4.1 GB / 16 GB)</span>
                          </div>
                          <div className="hud-progress-wrap"><div style={{ width: '25%', height: '100%', background: 'var(--accent-cyan)' }} /></div>
                        </div>
                        <div>
                          <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '10px', color: 'var(--text-muted)', marginBottom: '4px', fontFamily: 'var(--font-mono)' }}>
                            <span>NETWORK LINK RATE</span>
                            <span>8.4 MB/S</span>
                          </div>
                          <div className="hud-progress-wrap"><div style={{ width: '60%', height: '100%', background: 'var(--accent-cyan)' }} /></div>
                        </div>
                      </div>
                    </div>

                    <div className="hud-panel">
                      <div className="hud-panel-header">■ SYSTEM_ALERTS</div>
                      <div style={{ padding: '10px', display: 'flex', flexDirection: 'column', gap: '6px', maxHeight: '120px', overflowY: 'auto' }}>
                        <div style={{ fontSize: '11px', display: 'flex', gap: '6px', alignItems: 'center', borderBottom: '1px solid rgba(255,255,255,0.02)', paddingBottom: '4px' }}>
                          <span style={{ color: 'var(--accent-red)', fontWeight: 'bold' }}>[!] CRITICAL</span>
                          <span style={{ color: 'var(--text-muted)', flex: 1, textOverflow: 'ellipsis', overflow: 'hidden', whiteSpace: 'nowrap' }}>Suspicious egress detected on node RE-WIN-MAIN</span>
                        </div>
                        <div style={{ fontSize: '11px', display: 'flex', gap: '6px', alignItems: 'center', borderBottom: '1px solid rgba(255,255,255,0.02)', paddingBottom: '4px' }}>
                          <span style={{ color: 'var(--accent-red)', fontWeight: 'bold' }}>[!] CRITICAL</span>
                          <span style={{ color: 'var(--text-muted)', flex: 1, textOverflow: 'ellipsis', overflow: 'hidden', whiteSpace: 'nowrap' }}>Brute-force SSH attack blocked on 192.168.1.18</span>
                        </div>
                        <div style={{ fontSize: '11px', display: 'flex', gap: '6px', alignItems: 'center' }}>
                          <span style={{ color: 'var(--text-dim)', fontWeight: 'bold' }}>[*] INFO</span>
                          <span style={{ color: 'var(--text-muted)', flex: 1, textOverflow: 'ellipsis', overflow: 'hidden', whiteSpace: 'nowrap' }}>Operator session authenticated from enclave gateway</span>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* 2. ENDPOINTS VIEWPORT */}
            {activeSidebarTab === 'endpoints' && (
              <div className="page active">
                {detailAgentId ? (
                  // Render Detailed Audit View
                  (() => {
                    const agent = agents.find(a => a.id === detailAgentId);
                    if (!agent) {
                      setDetailAgentId(null);
                      return null;
                    }
                    const agentLogins = (agent.login_history || []).map(l => ({
                      timestamp: l.timestamp,
                      event_category: l.type || 'Logon Success',
                      domain: 'RE-DOMAIN',
                      username: l.user || 'SYSTEM',
                      workstation: 'WORKSTATION',
                      ip_address: l.source_ip || '127.0.0.1',
                      process_name: 'winlogon.exe'
                    }));
                    const agentUsb = (agent.usb_devices || []).map(u => ({
                      timestamp: u.timestamp,
                      action: (u.action === 'inserted' || u.action === 'insertion' || u.action === 'connected' || u.action === 'added') ? 'Connected' : 'Disconnected',
                      device_class: u.type || 'Mass Storage',
                      vendor_id: u.vendor_id || '0x0781',
                      product_id: '0x558A',
                      device_name: u.name || 'USB Disk',
                      serial_number: u.serial || '4C530001'
                    }));
                    // Map and deduplicate processes by (pid, name) to prevent duplicates
                    const rawProcesses = (agent.processes || []).map(p => ({
                      pid: p.pid,
                      name: p.name || p.process_name,
                      process_name: p.name || p.process_name,
                      user: p.user || p.username,
                      username: p.user || p.username,
                      cpu: p.cpu !== undefined ? p.cpu : p.cpu_usage,
                      cpu_usage: p.cpu !== undefined ? p.cpu : p.cpu_usage,
                      mem: p.mem !== undefined ? p.mem : p.ram_usage,
                      ram_usage: p.mem !== undefined ? p.mem : p.ram_usage,
                      executable_path: p.executable_path || p.path,
                      path: p.executable_path || p.path,
                      command_line: p.command_line || '-',
                      sha256_hash: p.sha256_hash || 'N/A',
                      start_time: p.start_time ? new Date(p.start_time).toLocaleString() : '-',
                      parent_process: p.parent_process || 'Unknown',
                      parent_pid: p.parent_pid || 'N/A',
                      threat_score: p.threat_score || 0,
                      threat_reasons: p.threat_reasons || [],
                      threat_classification: p.threat_classification || 'Safe',
                      vt_rate: p.vt_rate || '0/0',
                      mb_listed: p.mb_listed || false
                    }));
                    // Client-side deduplication: keep first occurrence per (pid, name)
                    const seenProcKeys = new Set();
                    let agentProcesses = rawProcesses.filter(p => {
                      const key = `${p.pid}_${p.name}`;
                      if (seenProcKeys.has(key)) return false;
                      seenProcKeys.add(key);
                      return true;
                    });
                    if (processSortConfig.key) {
                      agentProcesses = [...agentProcesses].sort((a, b) => {
                        let aVal = a[processSortConfig.key];
                        let bVal = b[processSortConfig.key];
                        if (processSortConfig.key === 'cpu_usage' || processSortConfig.key === 'ram_usage') {
                          aVal = parseFloat(aVal) || 0;
                          bVal = parseFloat(bVal) || 0;
                        } else {
                          aVal = String(aVal || '').toLowerCase();
                          bVal = String(bVal || '').toLowerCase();
                        }
                        if (aVal < bVal) return processSortConfig.direction === 'asc' ? -1 : 1;
                        if (aVal > bVal) return processSortConfig.direction === 'asc' ? 1 : -1;
                        return 0;
                      });
                    }
                    const agentSockets = (agent.network_connections || []).map(n => ({
                      protocol: n.protocol || 'TCP',
                      local_address: n.local_address || '0.0.0.0:0',
                      foreign_address: n.foreign_address || '0.0.0.0:0',
                      state: n.state || 'UNKNOWN',
                      pid: n.pid || '-',
                      process_name: n.process_name || ''
                    }));
                    const agentSoftware = (agent.installed_software || []).map(sw => ({
                      name: sw.name || sw.software_name,
                      software_name: sw.name || sw.software_name,
                      version: sw.version || '1.0.0',
                      status: sw.status || 'Installed'
                    }));
                    return (
                      <div className="agent-details-view" style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
                        {/* Header Bar */}
                        <div className="agent-details-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '14px', flexWrap: 'wrap', gap: '12px' }}>
                          <div className="details-header-left" style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                            <button className="scan-btn" onClick={() => setDetailAgentId(null)} style={{ padding: '8px 12px' }}>
                              <ChevronLeft size={16} /> Back to Agent List
                            </button>
                            <h2 className="page-title" style={{ margin: 0 }}>{agent.hostname}</h2>
                            <span className={`target-status-dot ${agent.status}`} style={{ width: '8px', height: '8px' }}></span>
                            <span style={{ fontSize: '13px', textTransform: 'uppercase', fontWeight: 'bold' }}>{agent.status}</span>
                          </div>
                          <div className="details-header-right" style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
                            <button className="scan-btn" onClick={() => handleRestartAgent(agent)}>
                              Restart Agent
                            </button>
                            {agent.platform === "Android" && (
                              <button className="scan-btn" onClick={() => handleWakeupAgent(agent)}>
                                Wake Up Agent
                              </button>
                            )}
                            <button
                              className="scan-btn"
                              onClick={() => handleUpdateAgent(agent)}
                              disabled={!agent.update_required}
                            >
                              Update Agent
                            </button>
                            <button className="scan-btn" onClick={() => handleIsolateAgent(agent)}>
                              Isolate Agent
                            </button>
                            <button
                              className="scan-btn"
                              onClick={() => {
                                setSelectedAgentId(agent.id);
                                setActiveSidebarTab('console');
                              }}
                            >
                              Execute Command
                            </button>
                            <button className="scan-btn" style={{ borderColor: 'rgba(244,63,94,0.4)', color: '#f43f5e' }} onClick={() => handleRemoveAgent(agent.id, agent.hostname)}>
                              Remove Agent
                            </button>
                          </div>
                        </div>

                        {/* Grid of details */}
                        <div className="report-section-grid">
                          {/* Overview card */}
                          <div className="system-details-panel">
                            <h3 style={{ margin: '0 0 12px 0' }}>Device Overview</h3>
                            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                              <div className="detail-entry"><span className="label">Hostname</span><span className="val">{agent.hostname}</span></div>
                              <div className="detail-entry"><span className="label">Device ID</span><span className="val">{agent.device_id}</span></div>
                              <div className="detail-entry"><span className="label">OS Version</span><span className="val">{agent.os_release}</span></div>
                              <div className="detail-entry"><span className="label">Agent Version</span><span className="val">{agent.agent_version}</span></div>
                              <div className="detail-entry"><span className="label">Username</span><span className="val">{agent.username || agent.user}</span></div>
                              <div className="detail-entry"><span className="label">Internal IP</span><span className="val">{agent.internal_ip}</span></div>
                              <div className="detail-entry"><span className="label">Public IP</span><span className="val">{agent.public_ip}</span></div>
                              <div className="detail-entry"><span className="label">Geo-Location</span><span className="val">{agent.city || "Mumbai"}, {agent.country || "India"}</span></div>
                              <div className="detail-entry"><span className="label">MAC Address</span><span className="val">{agent.mac_address}</span></div>
                              <div className="detail-entry"><span className="label">Last Seen</span><span className="val">{formatLocalTime(agent.last_seen) || 'Never'}</span></div>
                              <div className="detail-entry"><span className="label">Uptime</span><span className="val">{agent.uptime}</span></div>
                            </div>
                          </div>

                          {/* Health & Security card */}
                          <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
                            <div className="system-details-panel">
                              <h3 style={{ margin: '0 0 12px 0' }}>System Health</h3>
                              <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                                <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '12px' }}>
                                    <span>CPU Usage</span><span>{agent.health?.cpu ?? 0}%</span>
                                  </div>
                                  <div style={{ height: '6px', background: 'rgba(255,255,255,0.05)', borderRadius: '3px', overflow: 'hidden' }}>
                                    <div style={{ height: '100%', background: 'var(--accent-cyan)', width: `${agent.health?.cpu ?? 0}%`, borderRadius: '3px' }}></div>
                                  </div>
                                </div>
                                <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '12px' }}>
                                    <span>RAM Usage</span><span>{agent.health?.ram ?? 0}%</span>
                                  </div>
                                  <div style={{ height: '6px', background: 'rgba(255,255,255,0.05)', borderRadius: '3px', overflow: 'hidden' }}>
                                    <div style={{ height: '100%', background: 'var(--accent-blue)', width: `${agent.health?.ram ?? 0}%`, borderRadius: '3px' }}></div>
                                  </div>
                                </div>
                                <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '12px' }}>
                                    <span>Disk Usage</span><span>{agent.health?.disk ?? 0}%</span>
                                  </div>
                                  <div style={{ height: '6px', background: 'rgba(255,255,255,0.05)', borderRadius: '3px', overflow: 'hidden' }}>
                                    <div style={{ height: '100%', background: '#ff5577', width: `${agent.health?.disk ?? 0}%`, borderRadius: '3px' }}></div>
                                  </div>
                                </div>
                                <div className="detail-entry"><span className="label">Network Usage</span><span className="val">{agent.health?.network ?? 'Active'}</span></div>
                              </div>
                            </div>

                            <div className="system-details-panel">
                              <h3 style={{ margin: '0 0 12px 0' }}>Security & Risk Parameters</h3>
                              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                                <div className="detail-entry"><span className="label">Antivirus Status</span><span className="val">{agent.security?.antivirus ?? 'Checking...'}</span></div>
                                <div className="detail-entry"><span className="label">Firewall Status</span><span className="val">{agent.security?.firewall ?? 'Enabled'}</span></div>
                                <div className="detail-entry"><span className="label">VPN Status</span><span className="val">{agent.security?.vpn ?? 'Checking...'}</span></div>
                                <div className="detail-entry">
                                  <span className="label">Risk Score</span>
                                  <span className={`type-badge ${agent.risk_score > 70 ? 'critical' : agent.risk_score > 30 ? 'warning' : 'info'}`}>
                                    {agent.risk_score} / 100
                                  </span>
                                </div>
                                <div className="detail-entry"><span className="label">Active Alerts</span><span className="val">{agent.security?.alerts ?? 0}</span></div>
                              </div>
                            </div>
                          </div>
                        </div>

                        {/* Activity Card */}
                        <div className="system-details-panel" style={{ width: '100%' }}>
                          <div className="quick-commands" style={{ borderBottom: '1px solid var(--border-subtle)', paddingBottom: '12px', marginBottom: '16px', borderTop: 'none', paddingLeft: 0 }}>
                            <span className="quick-cmds-label">Activity Stream:</span>
                            <button className={`quick-cmd-btn ${detailSubTab === 'logins' ? 'glow-active' : ''}`} onClick={() => setDetailSubTab('logins')}>
                              Login History
                            </button>
                            <button className={`quick-cmd-btn ${detailSubTab === 'usb' ? 'glow-active' : ''}`} onClick={() => setDetailSubTab('usb')}>
                              USB History
                            </button>
                            <button className={`quick-cmd-btn ${detailSubTab === 'processes' ? 'glow-active' : ''}`} onClick={() => setDetailSubTab('processes')}>
                              Process Activity
                            </button>
                            <button className={`quick-cmd-btn ${detailSubTab === 'network' ? 'glow-active' : ''}`} onClick={() => setDetailSubTab('network')}>
                              Network Activity
                            </button>
                            <button className={`quick-cmd-btn ${detailSubTab === 'software' ? 'glow-active' : ''}`} onClick={() => setDetailSubTab('software')}>
                              Software Activity
                            </button>
                            <button className={`quick-cmd-btn ${detailSubTab === 'detected_apps' ? 'glow-active' : ''}`} onClick={() => setDetailSubTab('detected_apps')}>
                              Detected Apps
                            </button>
                            <button className={`quick-cmd-btn ${detailSubTab === 'suspicious_apps' ? 'glow-active' : ''}`} onClick={() => setDetailSubTab('suspicious_apps')}>
                              Suspicious App
                            </button>
                            {agent.platform === 'Android' && (
                              <button className={`quick-cmd-btn ${detailSubTab === 'android_apps' ? 'glow-active' : ''}`} onClick={() => setDetailSubTab('android_apps')}>
                                Installed Apps
                              </button>
                            )}
                          </div>

                          <div style={{ overflowX: 'auto' }}>
                            {detailSubTab === 'logins' && (
                              <table className="telemetry-table" style={{ border: '1px solid var(--border-subtle)' }}>
                                <thead>
                                  <tr>
                                    <th>Event Time</th>
                                    <th>Event Category</th>
                                    <th>Status</th>
                                    <th>Domain</th>
                                    <th>User Account</th>
                                    <th>Workstation</th>
                                    <th>Source IP</th>
                                    <th>Process</th>
                                  </tr>
                                </thead>
                                <tbody>
                                  {agentLogins.length > 0 ? (
                                    agentLogins.map((item, idx) => (
                                      <tr key={idx}>
                                        <td>{formatLocalTime(item.timestamp)}</td>
                                        <td>{item.event_category}</td>
                                        <td>
                                          <span className={`badge ${(!item.event_category.toLowerCase().includes('fail')) ? 'bd-g' : 'bd-r'}`}>
                                            {(!item.event_category.toLowerCase().includes('fail')) ? 'Success' : 'Failure'}
                                          </span>
                                        </td>
                                        <td>{item.domain}</td>
                                        <td>{item.username}</td>
                                        <td>{item.workstation}</td>
                                        <td style={{ fontFamily: 'monospace' }}>{item.ip_address}</td>
                                        <td>{item.process_name}</td>
                                      </tr>
                                    ))
                                  ) : (
                                    <tr>
                                      <td colSpan="8" style={{ textAlign: 'center', padding: '20px' }}>No login records found.</td>
                                    </tr>
                                  )}
                                </tbody>
                              </table>
                            )}

                            {detailSubTab === 'usb' && (
                              <table className="telemetry-table" style={{ border: '1px solid var(--border-subtle)' }}>
                                <thead>
                                  <tr>
                                    <th>Timestamp</th>
                                    <th>Action</th>
                                    <th>Device Class</th>
                                    <th>Vendor ID</th>
                                    <th>Product ID</th>
                                    <th>Device Name</th>
                                    <th>Serial Number</th>
                                  </tr>
                                </thead>
                                <tbody>
                                  {agentUsb.length > 0 ? (
                                    agentUsb.map((item, idx) => (
                                      <tr key={idx}>
                                        <td>{formatLocalTime(item.timestamp)}</td>
                                        <td>
                                          <span className={`badge ${item.action === 'Connected' ? 'bd-g' : 'bd-r'}`}>
                                            {item.action}
                                          </span>
                                        </td>
                                        <td>{item.device_class}</td>
                                        <td>{item.vendor_id}</td>
                                        <td>{item.product_id}</td>
                                        <td>{item.device_name}</td>
                                        <td style={{ fontFamily: 'monospace' }}>{item.serial_number}</td>
                                      </tr>
                                    ))
                                  ) : (
                                    <tr>
                                      <td colSpan="7" style={{ textAlign: 'center', padding: '20px' }}>No USB activity recorded.</td>
                                    </tr>
                                  )}
                                </tbody>
                              </table>
                            )}

                            {detailSubTab === 'processes' && (
                              <div>
                                {/* Process Search Bar */}
                                <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '12px', padding: '10px 14px', background: 'rgba(255,255,255,0.02)', border: '1px solid var(--border-subtle)', borderRadius: '8px' }}>
                                  <Search size={16} style={{ color: 'var(--text-muted)', flexShrink: 0 }} />
                                  <input
                                    type="text"
                                    placeholder="Search by process name or PID..."
                                    value={processSearchQuery}
                                    onChange={(e) => setProcessSearchQuery(e.target.value)}
                                    style={{
                                      flex: 1,
                                      background: 'transparent',
                                      border: 'none',
                                      outline: 'none',
                                      color: 'var(--text-primary)',
                                      fontSize: '13px',
                                      fontFamily: 'Inter, sans-serif'
                                    }}
                                  />
                                  {processSearchQuery && (
                                    <button
                                      onClick={() => setProcessSearchQuery('')}
                                      style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', fontSize: '14px', padding: '2px 6px' }}
                                    >
                                      ✕
                                    </button>
                                  )}
                                  <span style={{ fontSize: '11px', color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
                                    {(() => {
                                      const q = processSearchQuery.trim().toLowerCase();
                                      const filtered = q ? agentProcesses.filter(p => {
                                        const nameMatch = (p.name || '').toLowerCase().includes(q);
                                        const pidMatch = String(p.pid).includes(q);
                                        return nameMatch || pidMatch;
                                      }) : agentProcesses;
                                      return `${filtered.length} of ${agentProcesses.length} processes`;
                                    })()}
                                  </span>
                                </div>
                                <table className="telemetry-table" style={{ border: '1px solid var(--border-subtle)' }}>
                                  <thead>
                                    <tr>
                                      <th>PID</th>
                                      <th
                                        style={{ cursor: 'pointer', userSelect: 'none' }}
                                        onClick={() => setProcessSortConfig({ key: 'process_name', direction: processSortConfig.key === 'process_name' && processSortConfig.direction === 'asc' ? 'desc' : 'asc' })}
                                      >
                                        Name {processSortConfig.key === 'process_name' ? (processSortConfig.direction === 'asc' ? '▲' : '▼') : '↕'}
                                      </th>
                                      <th>User</th>
                                      <th
                                        style={{ cursor: 'pointer', userSelect: 'none' }}
                                        onClick={() => setProcessSortConfig({ key: 'cpu_usage', direction: processSortConfig.key === 'cpu_usage' && processSortConfig.direction === 'desc' ? 'asc' : 'desc' })}
                                      >
                                        CPU % {processSortConfig.key === 'cpu_usage' ? (processSortConfig.direction === 'desc' ? '▼' : '▲') : '↕'}
                                      </th>
                                      <th
                                        style={{ cursor: 'pointer', userSelect: 'none' }}
                                        onClick={() => setProcessSortConfig({ key: 'ram_usage', direction: processSortConfig.key === 'ram_usage' && processSortConfig.direction === 'desc' ? 'asc' : 'desc' })}
                                      >
                                        RAM % {processSortConfig.key === 'ram_usage' ? (processSortConfig.direction === 'desc' ? '▼' : '▲') : '↕'}
                                      </th>
                                      <th>Threat Score</th>
                                      <th>Path</th>
                                    </tr>
                                  </thead>
                                  <tbody>
                                    {(() => {
                                      const q = processSearchQuery.trim().toLowerCase();
                                      const filteredProcesses = q ? agentProcesses.filter(p => {
                                        const nameMatch = (p.name || '').toLowerCase().includes(q);
                                        const pidMatch = String(p.pid).includes(q);
                                        return nameMatch || pidMatch;
                                      }) : agentProcesses;
                                      return filteredProcesses.length > 0 ? (
                                        filteredProcesses.map((proc, idx) => (
                                          <React.Fragment key={idx}>
                                            <tr
                                              style={{ cursor: 'pointer', backgroundColor: expandedProcessId === proc.pid ? 'rgba(255,255,255,0.05)' : 'transparent' }}
                                              onClick={() => setExpandedProcessId(expandedProcessId === proc.pid ? null : proc.pid)}
                                            >
                                              <td style={{ fontFamily: 'monospace' }}>
                                                <span style={{ marginRight: '8px', fontSize: '10px' }}>
                                                  {expandedProcessId === proc.pid ? '▼' : '▶'}
                                                </span>
                                                {proc.pid}
                                              </td>
                                              <td><strong>{proc.name || proc.process_name}</strong></td>
                                              <td>{proc.user || proc.username}</td>
                                              <td>{proc.cpu}%</td>
                                              <td>{proc.mem}%</td>
                                              <td>
                                                {(() => {
                                                  const score = proc.threat_score || 0;
                                                  let color = 'var(--text-muted)';
                                                  let bg = 'rgba(255,255,255,0.03)';
                                                  let border = '1px solid var(--border-subtle)';
                                                  if (score > 80) {
                                                    color = '#ff4a70';
                                                    bg = 'rgba(255, 74, 112, 0.15)';
                                                    border = '1px solid rgba(255, 74, 112, 0.3)';
                                                  } else if (score > 60) {
                                                    color = '#ff8f4a';
                                                    bg = 'rgba(255, 143, 74, 0.15)';
                                                    border = '1px solid rgba(255, 143, 74, 0.3)';
                                                  } else if (score > 40) {
                                                    color = '#ffcc4a';
                                                    bg = 'rgba(255, 204, 74, 0.15)';
                                                    border = '1px solid rgba(255, 204, 74, 0.3)';
                                                  } else if (score > 20) {
                                                    color = '#4adeff';
                                                    bg = 'rgba(74, 222, 255, 0.15)';
                                                    border = '1px solid rgba(74, 222, 255, 0.3)';
                                                  } else {
                                                    color = '#4ade80';
                                                    bg = 'rgba(74, 222, 128, 0.1)';
                                                    border = '1px solid rgba(74, 222, 128, 0.2)';
                                                  }
                                                  return (
                                                    <span style={{
                                                      color,
                                                      background: bg,
                                                      border,
                                                      padding: '2px 8px',
                                                      borderRadius: '4px',
                                                      fontSize: '11px',
                                                      fontWeight: 'bold',
                                                      boxShadow: score > 80 ? '0 0 8px rgba(255, 74, 112, 0.2)' : 'none'
                                                    }}>
                                                      {score > 0 ? `${score} (${proc.threat_classification || 'Suspicious'})` : 'Safe'}
                                                    </span>
                                                  );
                                                })()}
                                              </td>
                                              <td style={{ fontFamily: 'monospace', fontSize: '11px', color: 'var(--text-dim)' }}>
                                                {proc.executable_path && proc.executable_path.length > 40 ? proc.executable_path.substring(0, 40) + '...' : proc.executable_path}
                                              </td>
                                            </tr>
                                            {expandedProcessId === proc.pid && (
                                              <tr style={{ backgroundColor: 'rgba(0, 0, 0, 0.2)' }}>
                                                <td colSpan="7" style={{ padding: '16px' }}>
                                                  <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 1fr 1fr', gap: '20px' }}>
                                                    <div>
                                                      <div style={{ marginBottom: '8px' }}>
                                                        <span style={{ color: 'var(--text-dim)', fontSize: '11px', display: 'block', marginBottom: '4px' }}>COMMAND LINE</span>
                                                        <code style={{ fontSize: '12px', background: 'rgba(0,0,0,0.3)', padding: '4px 8px', borderRadius: '4px', display: 'block', wordBreak: 'break-all' }}>
                                                          {proc.command_line}
                                                        </code>
                                                      </div>
                                                      <div>
                                                        <span style={{ color: 'var(--text-dim)', fontSize: '11px', display: 'block', marginBottom: '4px' }}>EXECUTABLE PATH</span>
                                                        <code style={{ fontSize: '12px', background: 'rgba(0,0,0,0.3)', padding: '4px 8px', borderRadius: '4px', display: 'block', wordBreak: 'break-all' }}>
                                                          {proc.executable_path}
                                                        </code>
                                                      </div>
                                                    </div>
                                                    <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                                                      <div className="detail-entry" style={{ background: 'transparent', padding: 0, border: 'none' }}>
                                                        <span className="label">SHA-256 Hash</span>
                                                        <span className="val" style={{ fontFamily: 'monospace', fontSize: '11px' }}>{proc.sha256_hash}</span>
                                                      </div>
                                                      <div className="detail-entry" style={{ background: 'transparent', padding: 0, border: 'none' }}>
                                                        <span className="label">Start Time</span>
                                                        <span className="val">{proc.start_time}</span>
                                                      </div>
                                                      <div className="detail-entry" style={{ background: 'transparent', padding: 0, border: 'none' }}>
                                                        <span className="label">Parent Process</span>
                                                        <span className="val">{proc.parent_process} (PID: {proc.parent_pid || 'N/A'})</span>
                                                      </div>
                                                    </div>

                                                    <div style={{ background: 'rgba(255, 255, 255, 0.02)', border: '1px solid var(--border-subtle)', borderRadius: '6px', padding: '12px', display: 'flex', flexDirection: 'column', gap: '8px' }}>
                                                      <span style={{ fontSize: '11px', color: 'var(--text-dim)', fontWeight: 'bold', textTransform: 'uppercase' }}>Threat Diagnostics</span>
                                                      <div className="detail-entry" style={{ background: 'transparent', padding: 0, border: 'none' }}>
                                                        <span className="label">Threat Score</span>
                                                        <span className="val" style={{ fontWeight: 'bold', color: (proc.threat_score || 0) > 40 ? '#f43f5e' : '#10b981' }}>{proc.threat_score || 0} ({proc.threat_classification || 'Safe'})</span>
                                                      </div>
                                                      <div className="detail-entry" style={{ background: 'transparent', padding: 0, border: 'none' }}>
                                                        <span className="label">VirusTotal</span>
                                                        <span className="val" style={{ fontFamily: 'monospace' }}>{proc.vt_rate || '0/0'}</span>
                                                      </div>
                                                      <div className="detail-entry" style={{ background: 'transparent', padding: 0, border: 'none' }}>
                                                        <span className="label">MalwareBazaar</span>
                                                        <span className="val">{proc.mb_listed ? '⚠️ Listed (Malicious)' : 'Not Found'}</span>
                                                      </div>
                                                      {proc.threat_reasons && proc.threat_reasons.length > 0 && (
                                                        <div style={{ marginTop: '8px' }}>
                                                          <span style={{ fontSize: '10px', color: 'var(--text-dim)', display: 'block', marginBottom: '4px' }}>MATCHED INDICATORS:</span>
                                                          <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                                                            {proc.threat_reasons.map((r, rIdx) => (
                                                              <span key={rIdx} style={{ fontSize: '11px', color: '#ff4a70', display: 'flex', alignItems: 'center', gap: '4px' }}>
                                                                ✔ {r}
                                                              </span>
                                                            ))}
                                                          </div>
                                                        </div>
                                                      )}
                                                    </div>
                                                  </div>
                                                </td>
                                              </tr>
                                            )}
                                          </React.Fragment>
                                        ))
                                      ) : (
                                        <tr>
                                          <td colSpan="7" style={{ textAlign: 'center', padding: '20px' }}>
                                            {processSearchQuery ? `No processes matching "${processSearchQuery}".` : 'No process telemetry received.'}
                                          </td>
                                        </tr>
                                      )
                                    })()}
                                  </tbody>
                                </table>
                              </div>
                            )}

                            {detailSubTab === 'network' && (
                              <table className="telemetry-table" style={{ border: '1px solid var(--border-subtle)' }}>
                                <thead>
                                  <tr>
                                    <th>Protocol</th>
                                    <th>Local Address</th>
                                    <th>Remote Address</th>
                                    <th>State</th>
                                    <th>Associated PID</th>
                                  </tr>
                                </thead>
                                <tbody>
                                  {agentSockets.length > 0 ? (
                                    agentSockets.map((sock, idx) => (
                                      <tr key={idx}>
                                        <td><span className="badge bd-b">{sock.protocol}</span></td>
                                        <td style={{ fontFamily: 'monospace' }}>{sock.local_address}</td>
                                        <td style={{ fontFamily: 'monospace' }}>{sock.foreign_address}</td>
                                        <td>
                                          <span className={`badge ${sock.state === 'ESTABLISHED' ? 'bd-g' : 'bd-y'}`}>
                                            {sock.state}
                                          </span>
                                        </td>
                                        <td style={{ fontFamily: 'monospace' }}>{sock.pid} {sock.process_name ? `(${sock.process_name})` : ''}</td>
                                      </tr>
                                    ))
                                  ) : (
                                    <tr>
                                      <td colSpan="5" style={{ textAlign: 'center', padding: '20px' }}>No active socket connections.</td>
                                    </tr>
                                  )}
                                </tbody>
                              </table>
                            )}

                            {detailSubTab === 'software' && (
                              <table className="telemetry-table" style={{ border: '1px solid var(--border-subtle)' }}>
                                <thead>
                                  <tr>
                                    <th>Software Name</th>
                                    <th>Version</th>
                                    <th>Status</th>
                                  </tr>
                                </thead>
                                <tbody>
                                  {agentSoftware.length > 0 ? (
                                    agentSoftware.map((sw, idx) => (
                                      <tr key={idx}>
                                        <td><strong>{sw.name || sw.software_name}</strong></td>
                                        <td>{sw.version}</td>
                                        <td>
                                          <span className={`badge ${sw.status === 'Installed' ? 'bd-g' : sw.status === 'Removed' ? 'bd-r' : 'bd-b'}`}>
                                            {sw.status || "Installed"}
                                          </span>
                                        </td>
                                      </tr>
                                    ))
                                  ) : (
                                    <tr>
                                      <td colSpan="4" style={{ textAlign: 'center', padding: '20px' }}>No installed software audit available.</td>
                                    </tr>
                                  )}
                                </tbody>
                              </table>
                            )}

                            {(detailSubTab === 'android_apps' || detailSubTab === 'suspicious_apps' || (detailSubTab === 'detected_apps' && agent.platform === 'Android')) && (() => {
                              let appsList = agent.android_apps || [];
                              const getEffectiveAppRisk = (appItem) => {
                                const vtMalicious = (() => {
                                  if (!appItem.vt_detection_rate || appItem.vt_detection_rate === '0/0') return 0;
                                  try {
                                    return parseInt(appItem.vt_detection_rate.split('/')[0], 10) || 0;
                                  } catch (e) {
                                    return 0;
                                  }
                                })();
                                const isMalware = appItem.mb_listed || vtMalicious >= 1 || (appItem.threat_category && appItem.threat_category.includes('Confirmed Malware'));
                                const score = appItem.threat_score || 0;
                                if (isMalware || score >= 61 || appItem.risk_level === 'red') return 'red';
                                if (score >= 30 || appItem.risk_level === 'yellow') return 'yellow';
                                return appItem.risk_level || 'green';
                              };

                              if (detailSubTab === 'detected_apps') {
                                appsList = appsList.filter(a => getEffectiveAppRisk(a) === 'red');
                              } else if (detailSubTab === 'suspicious_apps') {
                                appsList = appsList.filter(a => getEffectiveAppRisk(a) === 'yellow');
                              }
                              const filteredApps = appsList.filter(app => {
                                const q = appSearchQuery.toLowerCase();
                                return (app.app_name || '').toLowerCase().includes(q) ||
                                  (app.package_name || '').toLowerCase().includes(q) ||
                                  (app.version_name || '').toLowerCase().includes(q) ||
                                  (app.apk_sha256 || '').toLowerCase().includes(q);
                              });

                              return (
                                <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', marginBottom: '8px' }}>
                                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                                      <span style={{ fontSize: '13px', color: 'var(--text-muted)' }}>
                                        Showing {filteredApps.length} of {appsList.length} {detailSubTab === 'detected_apps' ? 'detected' : 'installed'} packages
                                      </span>
                                      <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                                        <button
                                          className="scan-btn"
                                          style={{
                                            padding: '6px 12px',
                                            background: detailSubTab === 'detected_apps' ? 'var(--accent-red, #ff3b30)' : detailSubTab === 'suspicious_apps' ? '#f8b739' : 'var(--accent-cyan)',
                                            color: '#000',
                                            borderColor: detailSubTab === 'detected_apps' ? 'var(--accent-red, #ff3b30)' : detailSubTab === 'suspicious_apps' ? '#f8b739' : 'var(--accent-cyan)',
                                            fontWeight: 'bold',
                                            fontSize: '11px',
                                            opacity: isVtScanning ? 0.6 : 1,
                                            pointerEvents: isVtScanning ? 'none' : 'auto'
                                          }}
                                          onClick={() => handleVtBatchScan(agent, detailSubTab === 'detected_apps' ? 'red' : detailSubTab === 'suspicious_apps' ? 'yellow' : 'all')}
                                        >
                                          {isVtScanning ? 'SCANNING API...' : detailSubTab === 'detected_apps' ? 'SCAN DETECTED APPS WITH VT' : detailSubTab === 'suspicious_apps' ? 'SCAN SUSPICIOUS APPS WITH VT' : 'SCAN RISKY APPS WITH VT API'}
                                        </button>
                                        <input
                                          type="text"
                                          placeholder="Filter by name, package, version or hash..."
                                          value={appSearchQuery}
                                          onChange={(e) => setAppSearchQuery(e.target.value)}
                                          style={{
                                            background: 'rgba(0, 0, 0, 0.3)',
                                            border: '1px solid var(--border-subtle)',
                                            borderRadius: '4px',
                                            padding: '6px 12px',
                                            color: '#fff',
                                            fontSize: '13px',
                                            width: '280px',
                                            outline: 'none'
                                          }}
                                        />
                                      </div>
                                    </div>

                                    {isVtScanning && vtScanProgress.total > 0 && (
                                      <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', background: 'rgba(0, 242, 255, 0.05)', padding: '10px', borderRadius: '4px', border: '1px solid rgba(0, 242, 255, 0.2)' }}>
                                        <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '11px', color: 'var(--accent-cyan)' }}>
                                          <span>Batch VirusTotal Scanning in Progress (Rate-Limited)...</span>
                                        </div>
                                        <div style={{ height: '6px', background: 'rgba(255,255,255,0.1)', borderRadius: '3px', overflow: 'hidden' }}>
                                          <div style={{
                                            height: '100%',
                                            background: 'var(--accent-cyan)',
                                            width: `${(vtScanProgress.current / vtScanProgress.total) * 100}%`,
                                            borderRadius: '3px',
                                            transition: 'width 0.3s ease'
                                          }}></div>
                                        </div>
                                      </div>
                                    )}
                                  </div>

                                  <table className="telemetry-table" style={{ border: '1px solid var(--border-subtle)' }}>
                                    <thead>
                                      <tr>
                                        <th style={{ width: '60px', textAlign: 'center' }}>Risk</th>
                                        <th>Application Name</th>
                                        <th>Package Identifier</th>
                                        <th>Version</th>
                                        <th>Install Source</th>
                                        <th>System App</th>
                                        <th>State</th>
                                        <th style={{ width: '100px', textAlign: 'center' }}>Actions</th>
                                      </tr>
                                    </thead>
                                    <tbody>
                                      {filteredApps.length > 0 ? (
                                        filteredApps.map((app, idx) => {
                                          const effectiveRisk = getEffectiveAppRisk(app);
                                          let riskEmoji = '🟢';
                                          let riskLabel = 'Low Risk';
                                          if (effectiveRisk === 'red') {
                                            riskEmoji = '🔴';
                                            riskLabel = 'High Threat';
                                          } else if (effectiveRisk === 'yellow') {
                                            riskEmoji = '🟡';
                                            riskLabel = 'Suspicious';
                                          }

                                          const isExpanded = expandedAppPkg === app.package_name;
                                          return (
                                            <React.Fragment key={idx}>
                                              <tr
                                                onClick={() => setExpandedAppPkg(isExpanded ? null : app.package_name)}
                                                style={{ cursor: 'pointer', transition: 'background-color 0.2s', background: isExpanded ? 'rgba(255, 255, 255, 0.04)' : '' }}
                                                className={isExpanded ? 'active-row' : ''}
                                              >
                                                <td style={{ textAlign: 'center', verticalAlign: 'middle', fontSize: '16px' }}>
                                                  <span title={riskLabel}>{riskEmoji}</span>
                                                </td>
                                                <td style={{ maxWidth: '260px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={app.app_name}>
                                                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                                                    <span style={{ fontWeight: '600', color: '#fff', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{app.app_name}</span>
                                                    {((app.threat_category && app.threat_category.includes('Confirmed Malware')) || app.mb_listed || (() => {
                                                      if (!app.vt_detection_rate || app.vt_detection_rate === '0/0') return false;
                                                      const parts = app.vt_detection_rate.split('/');
                                                      return parseInt(parts[0], 10) >= 1;
                                                    })()) && (
                                                        <span className="badge bd-r" style={{ fontSize: '9px', fontWeight: 'bold', padding: '2px 6px', borderRadius: '3px', flexShrink: 0 }}>
                                                          Malware Confirmed
                                                        </span>
                                                      )}
                                                    <ChevronUp
                                                      size={12}
                                                      style={{
                                                        color: 'var(--text-muted)',
                                                        transform: isExpanded ? 'rotate(0deg)' : 'rotate(180deg)',
                                                        transition: 'transform 0.2s',
                                                        flexShrink: 0
                                                      }}
                                                    />
                                                  </div>
                                                  {app.install_time && (
                                                    <div style={{ fontSize: '10px', color: 'var(--text-muted)', marginTop: '2px' }}>
                                                      Installed: {new Date(Number(app.install_time)).toLocaleString()}
                                                    </div>
                                                  )}
                                                </td>
                                                <td style={{ fontFamily: 'monospace', color: '#00f0ff', fontSize: '12px', maxWidth: '180px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={app.package_name}>{app.package_name}</td>
                                                <td style={{ maxWidth: '120px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={app.version_name}>{app.version_name || 'N/A'} <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>({app.version_code || '0'})</span></td>
                                                <td>{app.installer || 'Manual/APK'}</td>
                                                <td>
                                                  <span className={`badge ${app.system_app ? 'bd-g' : 'bd-b'}`}>
                                                    {app.system_app ? 'System' : 'User'}
                                                  </span>
                                                </td>
                                                <td>
                                                  <span className={`badge ${app.enabled ? 'bd-g' : 'bd-r'}`}>
                                                    {app.enabled ? 'Enabled' : 'Disabled'}
                                                  </span>
                                                </td>
                                                <td style={{ textAlign: 'center' }}>
                                                  <button
                                                    onClick={(e) => {
                                                      e.stopPropagation();
                                                      setInspectedApp(app);
                                                    }}
                                                    style={{
                                                      background: 'rgba(0, 240, 255, 0.1)',
                                                      border: '1px solid rgba(0, 240, 255, 0.3)',
                                                      borderRadius: '4px',
                                                      padding: '4px 10px',
                                                      color: '#00f0ff',
                                                      fontSize: '11px',
                                                      cursor: 'pointer',
                                                      fontWeight: 'bold',
                                                      transition: 'all 0.2s'
                                                    }}
                                                    onMouseEnter={(e) => {
                                                      e.target.style.background = 'rgba(0, 240, 255, 0.25)';
                                                    }}
                                                    onMouseLeave={(e) => {
                                                      e.target.style.background = 'rgba(0, 240, 255, 0.1)';
                                                    }}
                                                  >
                                                    Inspect
                                                  </button>
                                                </td>
                                              </tr>
                                              {isExpanded && (
                                                <tr>
                                                  <td colSpan="8" style={{ padding: '20px', background: 'rgba(15, 17, 26, 0.65)', borderBottom: '2px solid var(--border-subtle)' }}>
                                                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '20px' }}>
                                                      {/* Left Column: App & Cert Details */}
                                                      <div style={{ background: 'rgba(0, 0, 0, 0.25)', borderRadius: '8px', padding: '16px', border: '1px solid rgba(255, 255, 255, 0.05)' }}>
                                                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', borderBottom: '1px solid rgba(255,255,255,0.08)', paddingBottom: '8px', marginBottom: '12px' }}>
                                                          <Info size={16} style={{ color: '#00f0ff' }} />
                                                          <span style={{ fontWeight: '700', color: '#00f0ff', fontSize: '14px', textTransform: 'uppercase', letterSpacing: '0.5px' }}>Application Identity</span>
                                                        </div>
                                                        <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', fontSize: '12px' }}>
                                                          <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                                                            <span style={{ color: 'var(--text-muted)' }}>Package Name</span>
                                                            <span style={{ fontFamily: 'monospace', color: '#fff' }}>{app.package_name}</span>
                                                          </div>
                                                          <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                                                            <span style={{ color: 'var(--text-muted)' }}>Installer Source</span>
                                                            <span style={{ color: '#fff', fontWeight: '500' }}>{app.installer || 'Unknown (Sideloaded/Direct APK)'}</span>
                                                          </div>
                                                          <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                                                            <span style={{ color: 'var(--text-muted)' }}>Target SDK</span>
                                                            <span style={{ color: '#fff' }}>API {app.target_sdk || 'N/A'}</span>
                                                          </div>
                                                          <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                                                            <span style={{ color: 'var(--text-muted)' }}>First Install Time</span>
                                                            <span style={{ color: '#fff' }}>{app.install_time ? new Date(Number(app.install_time)).toLocaleString() : 'N/A'}</span>
                                                          </div>
                                                          <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                                                            <span style={{ color: 'var(--text-muted)' }}>Last Update Time</span>
                                                            <span style={{ color: '#fff' }}>{app.update_time ? new Date(Number(app.update_time)).toLocaleString() : 'N/A'}</span>
                                                          </div>
                                                          <div style={{ display: 'flex', flexDirection: 'column', gap: '4px', marginTop: '4px' }}>
                                                            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '2px' }}>
                                                              <span style={{ color: 'var(--text-muted)' }}>Signature SHA-256 Certificate Fingerprint</span>
                                                              <span style={{
                                                                fontSize: '10px',
                                                                fontWeight: 'bold',
                                                                padding: '2px 6px',
                                                                borderRadius: '3px',
                                                                background: app.certificate_reputation === 'trusted' ? 'rgba(52, 199, 89, 0.15)' : app.certificate_reputation === 'malicious' ? 'rgba(255, 59, 48, 0.15)' : 'rgba(255, 255, 255, 0.05)',
                                                                color: app.certificate_reputation === 'trusted' ? '#34c759' : app.certificate_reputation === 'malicious' ? '#ff3b30' : 'rgba(255, 255, 255, 0.6)',
                                                                border: app.certificate_reputation === 'trusted' ? '1px solid rgba(52, 199, 89, 0.3)' : app.certificate_reputation === 'malicious' ? '1px solid rgba(255, 59, 48, 0.3)' : '1px solid rgba(255, 255, 255, 0.1)'
                                                              }}>
                                                                {app.certificate_reputation === 'trusted' ? '✓ TRUSTED PUBLISHER' : app.certificate_reputation === 'malicious' ? '✗ MALICIOUS/UNTRUSTED' : '? UNKNOWN SIGNATURE'}
                                                              </span>
                                                            </div>
                                                            <span style={{ fontFamily: 'monospace', fontSize: '11px', color: '#fff', wordBreak: 'break-all', background: 'rgba(0,0,0,0.3)', padding: '6px', borderRadius: '4px', border: '1px solid rgba(255,255,255,0.05)' }}>
                                                              {app.certificate || 'Unknown'}
                                                            </span>
                                                          </div>
                                                        </div>
                                                      </div>

                                                      {/* Center Column: Manifest Analysis & Persistence Analysis */}
                                                      <div style={{ background: 'rgba(0, 0, 0, 0.25)', borderRadius: '8px', padding: '16px', border: '1px solid rgba(255, 255, 255, 0.05)' }}>
                                                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', borderBottom: '1px solid rgba(255,255,255,0.08)', paddingBottom: '8px', marginBottom: '12px' }}>
                                                          <ShieldAlert size={16} style={{ color: app.risk_level === 'red' ? '#ff3b30' : app.risk_level === 'yellow' ? '#ffcc00' : '#34c759' }} />
                                                          <span style={{ fontWeight: '700', color: '#fff', fontSize: '14px', textTransform: 'uppercase', letterSpacing: '0.5px' }}>Manifest Threat Analysis</span>
                                                        </div>
                                                        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px' }}>
                                                          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '8px', background: 'rgba(255,255,255,0.02)', borderRadius: '6px', border: '1px solid rgba(255,255,255,0.03)' }}>
                                                            <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>Accessibility Service</span>
                                                            <span style={{
                                                              fontSize: '11px',
                                                              fontWeight: '700',
                                                              padding: '2px 8px',
                                                              borderRadius: '4px',
                                                              background: app.has_accessibility ? 'rgba(255, 59, 48, 0.15)' : 'rgba(52, 199, 89, 0.15)',
                                                              color: app.has_accessibility ? '#ff3b30' : '#34c759',
                                                              border: app.has_accessibility ? '1px solid rgba(255, 59, 48, 0.3)' : '1px solid rgba(52, 199, 89, 0.3)'
                                                            }}>{app.has_accessibility ? 'YES' : 'NO'}</span>
                                                          </div>

                                                          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '8px', background: 'rgba(255,255,255,0.02)', borderRadius: '6px', border: '1px solid rgba(255,255,255,0.03)' }}>
                                                            <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>System Overlay</span>
                                                            <span style={{
                                                              fontSize: '11px',
                                                              fontWeight: '700',
                                                              padding: '2px 8px',
                                                              borderRadius: '4px',
                                                              background: app.has_overlay ? 'rgba(255, 59, 48, 0.15)' : 'rgba(52, 199, 89, 0.15)',
                                                              color: app.has_overlay ? '#ff3b30' : '#34c759',
                                                              border: app.has_overlay ? '1px solid rgba(255, 59, 48, 0.3)' : '1px solid rgba(52, 199, 89, 0.3)'
                                                            }}>{app.has_overlay ? 'YES' : 'NO'}</span>
                                                          </div>

                                                          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '8px', background: 'rgba(255,255,255,0.02)', borderRadius: '6px', border: '1px solid rgba(255,255,255,0.03)' }}>
                                                            <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>Device Admin</span>
                                                            <span style={{
                                                              fontSize: '11px',
                                                              fontWeight: '700',
                                                              padding: '2px 8px',
                                                              borderRadius: '4px',
                                                              background: app.has_device_admin ? 'rgba(255, 59, 48, 0.15)' : 'rgba(52, 199, 89, 0.15)',
                                                              color: app.has_device_admin ? '#ff3b30' : '#34c759',
                                                              border: app.has_device_admin ? '1px solid rgba(255, 59, 48, 0.3)' : '1px solid rgba(52, 199, 89, 0.3)'
                                                            }}>{app.has_device_admin ? 'YES' : 'NO'}</span>
                                                          </div>

                                                          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '8px', background: 'rgba(255,255,255,0.02)', borderRadius: '6px', border: '1px solid rgba(255,255,255,0.03)' }}>
                                                            <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>Exported Components</span>
                                                            <span style={{
                                                              fontSize: '11px',
                                                              fontWeight: '700',
                                                              padding: '2px 8px',
                                                              borderRadius: '4px',
                                                              background: app.exported_components_count > 0 ? 'rgba(255, 255, 255, 0.08)' : 'rgba(52, 199, 89, 0.15)',
                                                              color: app.exported_components_count > 0 ? '#fff' : '#34c759'
                                                            }}>{app.exported_components_count} comps</span>
                                                          </div>
                                                        </div>

                                                        {(app.has_accessibility || app.has_overlay || app.has_device_admin || app.device_admin_active || app.is_device_owner || app.is_profile_owner) && (
                                                          <div style={{ marginTop: '12px', display: 'flex', flexDirection: 'column', gap: '8px', background: 'rgba(0, 0, 0, 0.15)', padding: '10px', borderRadius: '6px', border: '1px solid rgba(255,255,255,0.03)', marginLeft: '0px', marginRight: '0px' }}>
                                                            {app.has_accessibility && (
                                                              <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                                                                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                                                                  <span style={{ fontSize: '11px', fontWeight: 'bold', color: 'rgba(255, 255, 255, 0.5)' }}>Accessibility Details</span>
                                                                  <span style={{
                                                                    fontSize: '10px',
                                                                    fontWeight: 'bold',
                                                                    padding: '1px 6px',
                                                                    borderRadius: '3px',
                                                                    background: app.accessibility_service_enabled ? 'rgba(255, 59, 48, 0.15)' : 'rgba(255, 255, 255, 0.05)',
                                                                    color: app.accessibility_service_enabled ? '#ff3b30' : '#fff',
                                                                    border: app.accessibility_service_enabled ? '1px solid rgba(255, 59, 48, 0.3)' : '1px solid rgba(255, 255, 255, 0.1)'
                                                                  }}>{app.accessibility_service_enabled ? 'ENABLED & ACTIVE' : 'DISABLED'}</span>
                                                                </div>
                                                                {app.accessibility_service_name && (
                                                                  <div style={{ display: 'flex', flexDirection: 'column' }}>
                                                                    <span style={{ fontSize: '10px', color: 'var(--text-muted)' }}>Service Name</span>
                                                                    <span style={{ fontSize: '11px', color: '#ff9f0a', wordBreak: 'break-all', fontFamily: 'monospace' }}>{app.accessibility_service_name}</span>
                                                                  </div>
                                                                )}
                                                                {app.accessibility_capabilities && app.accessibility_capabilities.length > 0 && (
                                                                  <div style={{ display: 'flex', flexDirection: 'column', gap: '4px', marginTop: '2px' }}>
                                                                    <span style={{ fontSize: '10px', color: 'var(--text-muted)' }}>Capabilities</span>
                                                                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px' }}>
                                                                      {app.accessibility_capabilities.map((cap, i) => (
                                                                        <span key={i} style={{ fontSize: '9px', fontWeight: 'bold', padding: '1px 6px', borderRadius: '3px', background: 'rgba(255, 59, 48, 0.1)', color: '#ff3b30', border: '1px solid rgba(255, 59, 48, 0.2)' }}>
                                                                          {cap}
                                                                        </span>
                                                                      ))}
                                                                    </div>
                                                                  </div>
                                                                )}
                                                              </div>
                                                            )}
                                                            {app.has_overlay && (
                                                              <div style={{ display: 'flex', flexDirection: 'column', gap: '4px', borderTop: app.has_accessibility ? '1px solid rgba(255,255,255,0.05)' : 'none', paddingTop: app.has_accessibility ? '8px' : '0px' }}>
                                                                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                                                                  <span style={{ fontSize: '11px', fontWeight: 'bold', color: 'rgba(255, 255, 255, 0.5)' }}>Overlay Runtime Status</span>
                                                                  <span style={{
                                                                    fontSize: '10px',
                                                                    fontWeight: 'bold',
                                                                    padding: '1px 6px',
                                                                    borderRadius: '3px',
                                                                    background: app.overlay_granted ? 'rgba(255, 59, 48, 0.15)' : 'rgba(52, 199, 89, 0.15)',
                                                                    color: app.overlay_granted ? '#ff3b30' : '#34c759',
                                                                    border: app.overlay_granted ? '1px solid rgba(255, 59, 48, 0.3)' : '1px solid rgba(52, 199, 89, 0.3)'
                                                                  }}>{app.overlay_granted ? 'GRANTED' : 'NOT GRANTED'}</span>
                                                                </div>
                                                              </div>
                                                            )}
                                                            {(app.has_device_admin || app.device_admin_active || app.is_device_owner || app.is_profile_owner) && (
                                                              <div style={{ display: 'flex', flexDirection: 'column', gap: '4px', borderTop: (app.has_accessibility || app.has_overlay) ? '1px solid rgba(255,255,255,0.05)' : 'none', paddingTop: (app.has_accessibility || app.has_overlay) ? '8px' : '0px' }}>
                                                                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                                                                  <span style={{ fontSize: '11px', fontWeight: 'bold', color: 'rgba(255, 255, 255, 0.5)' }}>Device Management Roles</span>
                                                                </div>
                                                                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px', marginTop: '2px' }}>
                                                                  {app.has_device_admin && (
                                                                    <span style={{ fontSize: '9px', fontWeight: 'bold', padding: '1px 6px', borderRadius: '3px', background: 'rgba(255, 255, 255, 0.08)', color: '#fff', border: '1px solid rgba(255, 255, 255, 0.15)' }}>
                                                                      Declares Admin
                                                                    </span>
                                                                  )}
                                                                  {app.device_admin_active ? (
                                                                    <span style={{ fontSize: '9px', fontWeight: 'bold', padding: '1px 6px', borderRadius: '3px', background: 'rgba(255, 59, 48, 0.15)', color: '#ff3b30', border: '1px solid rgba(255, 59, 48, 0.3)' }}>
                                                                      ACTIVE ADMIN
                                                                    </span>
                                                                  ) : (
                                                                    <span style={{ fontSize: '9px', fontWeight: 'bold', padding: '1px 6px', borderRadius: '3px', background: 'rgba(52, 199, 89, 0.1)', color: '#34c759', border: '1px solid rgba(52, 199, 89, 0.2)' }}>
                                                                      Inactive Admin
                                                                    </span>
                                                                  )}
                                                                  {app.is_device_owner && (
                                                                    <span style={{ fontSize: '9px', fontWeight: 'bold', padding: '1px 6px', borderRadius: '3px', background: 'rgba(255, 59, 48, 0.2)', color: '#ff3b30', border: '1px solid rgba(255, 59, 48, 0.4)' }}>
                                                                      DEVICE OWNER
                                                                    </span>
                                                                  )}
                                                                  {app.is_profile_owner && (
                                                                    <span style={{ fontSize: '9px', fontWeight: 'bold', padding: '1px 6px', borderRadius: '3px', background: 'rgba(255, 159, 10, 0.2)', color: '#ff9f0a', border: '1px solid rgba(255, 159, 10, 0.4)' }}>
                                                                      PROFILE OWNER
                                                                    </span>
                                                                  )}
                                                                </div>
                                                              </div>
                                                            )}
                                                          </div>
                                                        )}
                                                      </div>

                                                      {/* Persistence Analysis Subsection */}
                                                      <div style={{ marginTop: '14px', borderTop: '1px solid rgba(255, 255, 255, 0.08)', paddingTop: '10px' }}>
                                                        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
                                                          <span style={{ fontWeight: '700', color: '#ff9f0a', fontSize: '12px', textTransform: 'uppercase', letterSpacing: '0.5px' }}>Persistence Analysis</span>
                                                          <span style={{
                                                            fontSize: '10px',
                                                            fontWeight: '700',
                                                            padding: '1px 6px',
                                                            borderRadius: '4px',
                                                            background: (app.persistence_score || 0) >= 2 ? 'rgba(255, 159, 10, 0.2)' : 'rgba(52, 199, 89, 0.15)',
                                                            color: (app.persistence_score || 0) >= 2 ? '#ff9f0a' : '#34c759',
                                                            border: (app.persistence_score || 0) >= 2 ? '1px solid rgba(255, 159, 10, 0.4)' : '1px solid rgba(52, 199, 89, 0.3)'
                                                          }}>Score: {app.persistence_score || 0}/4</span>
                                                        </div>

                                                        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '6px' }}>
                                                          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '5px 7px', background: 'rgba(0,0,0,0.15)', borderRadius: '4px' }}>
                                                            <span style={{ fontSize: '10px', color: 'var(--text-muted)' }}>Starts after Boot</span>
                                                            <span style={{ color: app.has_boot_receiver ? '#ff9f0a' : 'rgba(255,255,255,0.3)', fontWeight: '600', fontSize: '10px' }}>{app.has_boot_receiver ? 'YES' : 'NO'}</span>
                                                          </div>
                                                          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '5px 7px', background: 'rgba(0,0,0,0.15)', borderRadius: '4px' }}>
                                                            <span style={{ fontSize: '10px', color: 'var(--text-muted)' }}>Foreground Service</span>
                                                            <span style={{ color: app.has_foreground_service ? '#007aff' : 'rgba(255,255,255,0.3)', fontWeight: '600', fontSize: '10px' }}>{app.has_foreground_service ? 'YES' : 'NO'}</span>
                                                          </div>
                                                          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '5px 7px', background: 'rgba(0,0,0,0.15)', borderRadius: '4px' }}>
                                                            <span style={{ fontSize: '10px', color: 'var(--text-muted)' }}>Battery Optimization</span>
                                                            <span style={{ color: app.has_battery_exemption ? '#ff453a' : 'rgba(255,255,255,0.3)', fontWeight: '600', fontSize: '10px' }}>{app.has_battery_exemption ? 'YES' : 'NO'}</span>
                                                          </div>
                                                          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '5px 7px', background: 'rgba(0,0,0,0.15)', borderRadius: '4px' }}>
                                                            <span style={{ fontSize: '10px', color: 'var(--text-muted)' }}>Long-Lived Bg Work</span>
                                                            <span style={{ color: ((app.services && app.services.length > 0) || (app.receivers && app.receivers.length > 0)) ? '#fff' : 'rgba(255,255,255,0.3)', fontWeight: '600', fontSize: '10px' }}>
                                                              {((app.services && app.services.length > 0) || (app.receivers && app.receivers.length > 0)) ? 'YES' : 'NO'}
                                                            </span>
                                                          </div>
                                                        </div>
                                                      </div>

                                                      {/* Right Column: Permission Analysis */}
                                                      <div style={{ background: 'rgba(0, 0, 0, 0.25)', borderRadius: '8px', padding: '16px', border: '1px solid rgba(255, 255, 255, 0.05)' }}>
                                                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', borderBottom: '1px solid rgba(255,255,255,0.08)', paddingBottom: '8px', marginBottom: '12px' }}>
                                                          <ShieldCheck size={16} style={{ color: '#007aff' }} />
                                                          <span style={{ fontWeight: '700', color: '#fff', fontSize: '14px', textTransform: 'uppercase', letterSpacing: '0.5px' }}>Permission Analysis</span>
                                                        </div>
                                                        <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                                                          {[
                                                            { label: 'READ_SMS', granted: app.read_sms_granted },
                                                            { label: 'READ_CONTACTS', granted: app.read_contacts_granted },
                                                            { label: 'CAMERA', granted: app.camera_granted },
                                                            { label: 'RECORD_AUDIO', granted: app.record_audio_granted }
                                                          ].map((p, idx) => (
                                                            <div key={idx} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '6px 8px', background: 'rgba(255,255,255,0.02)', borderRadius: '6px', border: '1px solid rgba(255,255,255,0.03)' }}>
                                                              <span style={{ fontSize: '11px', color: 'var(--text-muted)', fontFamily: 'monospace' }}>{p.label}</span>
                                                              <span style={{
                                                                fontSize: '10px',
                                                                fontWeight: '700',
                                                                padding: '2px 8px',
                                                                borderRadius: '4px',
                                                                background: p.granted ? 'rgba(52, 199, 89, 0.15)' : 'rgba(255, 255, 255, 0.08)',
                                                                color: p.granted ? '#34c759' : 'rgba(255, 255, 255, 0.4)',
                                                                border: p.granted ? '1px solid rgba(52, 199, 89, 0.3)' : '1px solid rgba(255, 255, 255, 0.1)'
                                                              }}>{p.granted ? 'Granted' : 'Not Granted'}</span>
                                                            </div>
                                                          ))}
                                                          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '6px 8px', background: app.keylogger_detected ? 'rgba(255, 59, 48, 0.08)' : 'rgba(255,255,255,0.02)', borderRadius: '6px', border: app.keylogger_detected ? '1px solid rgba(255, 59, 48, 0.2)' : '1px solid rgba(255,255,255,0.03)', marginTop: '2px' }}>
                                                            <span style={{ fontSize: '11px', fontWeight: '600', color: app.keylogger_detected ? '#ff3b30' : 'var(--text-muted)' }}>Keylogger Activity</span>
                                                            <span style={{
                                                              fontSize: '10px',
                                                              fontWeight: '700',
                                                              padding: '2px 8px',
                                                              borderRadius: '4px',
                                                              background: app.keylogger_detected ? 'rgba(255, 59, 48, 0.2)' : 'rgba(52, 199, 89, 0.15)',
                                                              color: app.keylogger_detected ? '#ff3b30' : '#34c759',
                                                              border: app.keylogger_detected ? '1px solid rgba(255, 59, 48, 0.4)' : '1px solid rgba(52, 199, 89, 0.3)'
                                                            }}>{app.keylogger_detected ? 'DETECTED' : 'CLEAN'}</span>
                                                          </div>
                                                        </div>
                                                      </div>
                                                    </div>

                                                    {/* Permissions List */}
                                                    <div style={{ marginTop: '16px', background: 'rgba(0, 0, 0, 0.25)', borderRadius: '8px', padding: '16px', border: '1px solid rgba(255, 255, 255, 0.05)' }}>
                                                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', borderBottom: '1px solid rgba(255,255,255,0.08)', paddingBottom: '8px', marginBottom: '12px' }}>
                                                        <Zap size={16} style={{ color: '#ffc107' }} />
                                                        <span style={{ fontWeight: '700', color: '#fff', fontSize: '14px', textTransform: 'uppercase', letterSpacing: '0.5px' }}>Requested Permissions ({app.requested_permissions ? app.requested_permissions.length : 0})</span>
                                                      </div>

                                                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
                                                        {app.requested_permissions && app.requested_permissions.length > 0 ? (
                                                          app.requested_permissions.map((perm, pIdx) => {
                                                            const isDangerous = perm.includes('SYSTEM_ALERT_WINDOW') ||
                                                              perm.includes('BIND_ACCESSIBILITY_SERVICE') ||
                                                              perm.includes('BIND_DEVICE_ADMIN') ||
                                                              perm.includes('RECORD_AUDIO') ||
                                                              perm.includes('CAMERA') ||
                                                              perm.includes('READ_SMS') ||
                                                              perm.includes('SEND_SMS') ||
                                                              perm.includes('RECEIVE_SMS') ||
                                                              perm.includes('READ_CONTACTS') ||
                                                              perm.includes('READ_EXTERNAL_STORAGE') ||
                                                              perm.includes('WRITE_EXTERNAL_STORAGE');
                                                            return (
                                                              <span
                                                                key={pIdx}
                                                                style={{
                                                                  fontSize: '11px',
                                                                  padding: '3px 8px',
                                                                  borderRadius: '4px',
                                                                  background: isDangerous ? 'rgba(255, 59, 48, 0.12)' : 'rgba(255,255,255,0.05)',
                                                                  color: isDangerous ? '#ff453a' : '#c7c7cc',
                                                                  border: isDangerous ? '1px solid rgba(255, 59, 48, 0.2)' : '1px solid rgba(255,255,255,0.08)'
                                                                }}
                                                                title={perm}
                                                              >
                                                                {perm.split('.').pop()}
                                                              </span>
                                                            );
                                                          })
                                                        ) : (
                                                          <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>No permissions requested.</span>
                                                        )}
                                                      </div>
                                                    </div>
                                                  </td>
                                                </tr>
                                              )}
                                            </React.Fragment>
                                          );
                                        })
                                      ) : (
                                        <tr>
                                          <td colSpan="7" style={{ textAlign: 'center', padding: '20px' }}>
                                            No applications match the search criteria.
                                          </td>
                                        </tr>
                                      )}
                                    </tbody>
                                  </table>
                                </div>
                              );
                            })()}

                            {(detailSubTab === 'suspicious_apps' || detailSubTab === 'detected_apps') && agent.platform !== 'Android' && (() => {
                              const unsafeProcesses = agentProcesses.filter(p => {
                                const score = p.threat_score || 0;
                                if (detailSubTab === 'detected_apps') {
                                  return score >= 60 || p.threat_classification === 'Critical Malware' || p.threat_classification === 'Malware Likely';
                                } else {
                                  return score >= 30 || (p.threat_reasons && p.threat_reasons.length > 0) || (p.reasons && p.reasons.length > 0);
                                }
                              });

                              const suspiciousSoftware = agentSoftware.filter(sw => {
                                const nameLower = (sw.name || '').toLowerCase();
                                return ['miner', 'mimikatz', 'hydra', 'nmap', 'wireshark', 'metasploit', 'netcat', 'nc ', 'keylogger', 'trojan', 'ransomware', 'spyware', 'tor ', 'torrent'].some(kw => nameLower.includes(kw));
                              });

                              return (
                                <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
                                  {/* Unsafe / Suspicious Processes Section */}
                                  <div className="hud-panel" style={{ padding: '16px', background: 'rgba(255, 74, 112, 0.03)', border: '1px solid rgba(255, 74, 112, 0.2)' }}>
                                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px', flexWrap: 'wrap', gap: '10px' }}>
                                      <h4 style={{ margin: 0, color: '#ff4a70', display: 'flex', alignItems: 'center', gap: '8px' }}>
                                        <span style={{ fontSize: '18px' }}>⚠️</span> {detailSubTab === 'suspicious_apps' ? 'Suspicious Application & Process Activity' : 'Detected Unsafe Processes'} ({unsafeProcesses.length})
                                      </h4>
                                      <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                                        <button
                                          className="scan-btn"
                                          style={{
                                            padding: '6px 14px',
                                            background: '#f8b739',
                                            color: '#000',
                                            borderColor: '#f8b739',
                                            fontWeight: 'bold',
                                            fontSize: '11px',
                                            borderRadius: '4px',
                                            cursor: 'pointer',
                                            opacity: isVtScanning ? 0.6 : 1,
                                            pointerEvents: isVtScanning ? 'none' : 'auto'
                                          }}
                                          onClick={() => handleVtBatchScan(agent, detailSubTab === 'detected_apps' ? 'red' : 'yellow')}
                                        >
                                          {isVtScanning ? 'SCANNING API...' : 'SCAN SUSPICIOUS APPS WITH VT'}
                                        </button>
                                        <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                                          {detailSubTab === 'suspicious_apps' ? 'Heuristics Risk Score ≥ 30' : 'Heuristics Risk Score ≥ 60'}
                                        </span>
                                      </div>
                                    </div>

                                    {unsafeProcesses.length > 0 ? (
                                      <table className="telemetry-table" style={{ border: '1px solid var(--border-subtle)' }}>
                                        <thead>
                                          <tr>
                                            <th style={{ width: '80px' }}>PID</th>
                                            <th>Process Name</th>
                                            <th>User</th>
                                            <th>Threat Score</th>
                                            <th>Executable Path</th>
                                            <th>Matched Indicators</th>
                                            <th style={{ width: '200px', textAlign: 'center' }}>Actions</th>
                                          </tr>
                                        </thead>
                                        <tbody>
                                          {unsafeProcesses.map((proc, idx) => {
                                            const score = proc.threat_score || 0;
                                            let color = '#ffcc4a';
                                            let bg = 'rgba(255, 204, 74, 0.15)';
                                            let border = '1px solid rgba(255, 204, 74, 0.3)';
                                            if (score > 80) {
                                              color = '#ff4a70';
                                              bg = 'rgba(255, 74, 112, 0.15)';
                                              border = '1px solid rgba(255, 74, 112, 0.3)';
                                            } else if (score > 60) {
                                              color = '#ff8f4a';
                                              bg = 'rgba(255, 143, 74, 0.15)';
                                              border = '1px solid rgba(255, 143, 74, 0.3)';
                                            }
                                            return (
                                              <tr key={idx}>
                                                <td style={{ fontFamily: 'monospace' }}>{proc.pid}</td>
                                                <td><strong>{proc.name}</strong></td>
                                                <td>{proc.user}</td>
                                                <td>
                                                  <span style={{ color, background: bg, border, padding: '2px 8px', borderRadius: '4px', fontSize: '11px', fontWeight: 'bold' }}>
                                                    {score} ({proc.threat_classification || 'Suspicious'})
                                                  </span>
                                                </td>
                                                <td style={{ fontFamily: 'monospace', fontSize: '11px', color: 'var(--text-dim)', maxWidth: '200px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={proc.executable_path}>
                                                  {proc.executable_path}
                                                </td>
                                                <td>
                                                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px' }}>
                                                    {proc.threat_reasons && proc.threat_reasons.length > 0 ? (
                                                      proc.threat_reasons.map((r, rIdx) => (
                                                        <span key={rIdx} style={{ fontSize: '10px', color: '#ff4a70', background: 'rgba(255, 74, 112, 0.08)', padding: '1px 5px', borderRadius: '3px', border: '1px solid rgba(255, 74, 112, 0.15)' }}>
                                                          {r}
                                                        </span>
                                                      ))
                                                    ) : (
                                                      <span style={{ fontSize: '10px', color: 'var(--text-muted)' }}>None</span>
                                                    )}
                                                  </div>
                                                </td>
                                                <td style={{ textAlign: 'center' }}>
                                                  <div style={{ display: 'flex', gap: '8px', justifyContent: 'center' }}>
                                                    <button
                                                      onClick={() => handleProcessVtScan(agent, proc.pid)}
                                                      style={{
                                                        background: 'rgba(0, 240, 255, 0.1)',
                                                        border: '1px solid rgba(0, 240, 255, 0.3)',
                                                        borderRadius: '4px',
                                                        padding: '4px 10px',
                                                        color: 'var(--accent-cyan)',
                                                        fontSize: '11px',
                                                        cursor: 'pointer',
                                                        fontWeight: 'bold',
                                                        transition: 'all 0.2s'
                                                      }}
                                                      onMouseEnter={(e) => { e.target.style.background = 'rgba(0, 240, 255, 0.25)'; }}
                                                      onMouseLeave={(e) => { e.target.style.background = 'rgba(0, 240, 255, 0.1)'; }}
                                                    >
                                                      Scan Virus
                                                    </button>
                                                    <button
                                                      onClick={() => handleTerminateProcess(agent, proc.pid)}
                                                      style={{
                                                        background: 'rgba(255, 74, 112, 0.1)',
                                                        border: '1px solid rgba(255, 74, 112, 0.3)',
                                                        borderRadius: '4px',
                                                        padding: '4px 10px',
                                                        color: '#ff4a70',
                                                        fontSize: '11px',
                                                        cursor: 'pointer',
                                                        fontWeight: 'bold',
                                                        transition: 'all 0.2s'
                                                      }}
                                                      onMouseEnter={(e) => { e.target.style.background = 'rgba(255, 74, 112, 0.25)'; }}
                                                      onMouseLeave={(e) => { e.target.style.background = 'rgba(255, 74, 112, 0.1)'; }}
                                                    >
                                                      Terminate
                                                    </button>
                                                  </div>
                                                </td>
                                              </tr>
                                            );
                                          })}
                                        </tbody>
                                      </table>
                                    ) : (
                                      <div style={{ padding: '20px', textAlign: 'center', color: 'var(--text-muted)', fontSize: '13px' }}>
                                        No unsafe processes currently detected on this endpoint.
                                      </div>
                                    )}
                                  </div>

                                  {/* Suspicious Software Section */}
                                  <div className="hud-panel" style={{ padding: '16px', background: 'rgba(255, 159, 10, 0.02)', border: '1px solid rgba(255, 159, 10, 0.15)' }}>
                                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
                                      <h4 style={{ margin: 0, color: '#ff9f0a', display: 'flex', alignItems: 'center', gap: '8px' }}>
                                        <span style={{ fontSize: '18px' }}>🔍</span> Suspicious Audit Software ({suspiciousSoftware.length})
                                      </h4>
                                      <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Audit matches hacker tools, network scanners, or malicious patterns</span>
                                    </div>

                                    {suspiciousSoftware.length > 0 ? (
                                      <table className="telemetry-table" style={{ border: '1px solid var(--border-subtle)' }}>
                                        <thead>
                                          <tr>
                                            <th>Software Name</th>
                                            <th>Version</th>
                                            <th>Status</th>
                                            <th style={{ width: '150px' }}>Risk Indicator</th>
                                          </tr>
                                        </thead>
                                        <tbody>
                                          {suspiciousSoftware.map((sw, idx) => (
                                            <tr key={idx}>
                                              <td><strong style={{ color: '#ff9f0a' }}>{sw.name}</strong></td>
                                              <td>{sw.version}</td>
                                              <td>
                                                <span className={`badge ${sw.status === 'Installed' ? 'bd-g' : 'bd-r'}`}>
                                                  {sw.status}
                                                </span>
                                              </td>
                                              <td>
                                                <span style={{ color: '#ff9f0a', background: 'rgba(255, 159, 10, 0.1)', border: '1px solid rgba(255, 159, 10, 0.3)', padding: '2px 8px', borderRadius: '4px', fontSize: '11px', fontWeight: 'bold' }}>
                                                  Potentially Unwanted / Audit Tool
                                                </span>
                                              </td>
                                            </tr>
                                          ))}
                                        </tbody>
                                      </table>
                                    ) : (
                                      <div style={{ padding: '20px', textAlign: 'center', color: 'var(--text-muted)', fontSize: '13px' }}>
                                        No suspicious installed software audited on this endpoint.
                                      </div>
                                    )}
                                  </div>
                                </div>
                              );
                            })()}
                          </div>
                        </div>
                      </div>
                    );
                  })()
                ) : (
                  <>
                    <div className="page-title">Endpoints Enclave</div>
                    <div className="page-sub">Device risk assessment and live health monitoring</div>

                    <div className="ep-grid" style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(320px, 1fr))', gap: '16px', marginTop: '16px' }}>
                      {agents.map((ep, index) => {
                        const cpu = ep.health?.cpu ?? (15 + (index * 7) % 65);
                        const ram = ep.health?.ram ?? (30 + (index * 11) % 55);
                        const disk = ep.health?.disk ?? (25 + (index * 13) % 45);
                        const risk = ep.risk_score ?? (20 + (index * 17) % 65);

                        const col = risk < 40 ? 'var(--accent-cyan)' : risk < 75 ? 'var(--accent-cyan)' : 'var(--accent-red)';
                        const lv = risk < 40 ? 'Low' : risk < 75 ? 'Medium' : 'High';

                        const avBdg = 'bd-g';
                        const portsStr = ep.platform === 'Windows' ? '135, 445, 5040' : '22, 80, 443';
                        const flTag = ep.failed_logins > 0 ? (
                          <span className="badge bd-r" style={{ fontSize: '10px' }}>{ep.failed_logins} failed login{ep.failed_logins > 1 ? 's' : ''}</span>
                        ) : null;

                        return (
                          <div
                            key={ep.id || index}
                            className="ep-card"
                            onClick={() => setDetailAgentId(ep.id)}
                            style={{ cursor: 'pointer', border: '1px solid var(--border-subtle)', background: 'var(--bg-recessed)', borderRadius: '6px', padding: '16px', display: 'flex', flexDirection: 'column', gap: '12px' }}
                          >
                            <div className="ep-head" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                              <div>
                                <div className="ep-name" style={{ fontSize: '15px', fontWeight: 'bold', color: '#fff' }}>{ep.hostname}</div>
                                <div className="ep-meta" style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '4px' }}>{ep.ip_address} · {ep.platform}</div>
                              </div>
                              <div style={{ textAlign: 'right' }}>
                                <div className="ep-score" style={{ color: col, fontSize: '18px', fontWeight: 800, fontFamily: 'var(--font-mono)' }}>{(risk / 100).toFixed(2)}</div>
                                <div className="ep-slbl" style={{ fontSize: '9px', color: 'var(--text-dim)', letterSpacing: '0.5px' }}>RISK SCORE</div>
                              </div>
                            </div>

                            <div style={{ display: 'flex', alignItems: 'center', gap: '7px' }}>
                              <div style={{ flex: 1, height: '4px', background: 'rgba(255,255,255,0.03)', borderRadius: '2px', overflow: 'hidden' }}>
                                <div style={{ width: `${risk}%`, height: '100%', background: col }} />
                              </div>
                              <span className="badge" style={{ background: 'rgba(0,242,255,0.1)', color: 'var(--accent-cyan)', fontSize: '10px' }}>{lv}</span>
                            </div>

                            <div className="hbar-row" style={{ display: 'flex', alignItems: 'center', gap: '10px', fontSize: '11px' }}>
                              <span className="hbar-lbl" style={{ width: '30px', color: 'var(--text-muted)' }}>CPU</span>
                              <div className="hbar" style={{ flex: 1, height: '4px', background: 'rgba(255,255,255,0.03)' }}>
                                <div className="hbar-f" style={{ height: '100%', width: `${cpu}%`, background: 'var(--accent-cyan)' }} />
                              </div>
                              <span style={{ fontSize: '10px', width: '34px', textAlign: 'right', color: '#fff' }}>{cpu}%</span>
                            </div>

                            <div className="hbar-row" style={{ display: 'flex', alignItems: 'center', gap: '10px', fontSize: '11px' }}>
                              <span className="hbar-lbl" style={{ width: '30px', color: 'var(--text-muted)' }}>RAM</span>
                              <div className="hbar" style={{ flex: 1, height: '4px', background: 'rgba(255,255,255,0.03)' }}>
                                <div className="hbar-f" style={{ height: '100%', width: `${ram}%`, background: 'var(--accent-cyan)' }} />
                              </div>
                              <span style={{ fontSize: '10px', width: '34px', textAlign: 'right', color: '#fff' }}>{ram}%</span>
                            </div>

                            <div className="ep-tags" style={{ display: 'flex', gap: '6px', flexWrap: 'wrap', marginTop: '4px' }}>
                              <span className={`badge ${avBdg}`} style={{ fontSize: '9px', textTransform: 'uppercase' }}>AV: ACTIVE</span>
                              <span className="badge bd-b" style={{ fontSize: '9px', textTransform: 'uppercase' }}>PORTS: {portsStr.split(',')[0]}</span>
                              {flTag}
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  </>
                )}
              </div>
            )}

            {/* 3. TELEMETRY MONITOR VIEWPORT */}
            {activeSidebarTab === 'telemetry' && (
              <div className="page active">
                <div className="page-title">Telemetry Stream & Packet Analyzer</div>
                <div className="page-sub">Real-time network traffic analysis, topological routing, and packet inspections</div>

                {/* Threat Telemetry Banners */}
                <div className="two-col" style={{ display: 'grid', gridTemplateColumns: '15fr 15fr', gap: '16px', marginBottom: '16px' }}>
                  <div className="card hud-panel" style={{ border: '1px solid rgba(255, 59, 48, 0.3)', background: 'rgba(255, 59, 48, 0.03)' }}>
                    <div className="card-hd" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <div className="sec-title" style={{ display: 'flex', alignItems: 'center', gap: '6px', color: 'var(--accent-red)' }}>
                        <span className="dot" style={{ background: 'var(--accent-red)' }}></span>ARP Spoof Alert
                      </div>
                      <span className="badge bd-r" style={{ background: 'var(--accent-red)', color: '#000' }}>1 CRITICAL</span>
                    </div>
                    <div className="arp-box" style={{ marginTop: '10px' }}>
                      <div className="arp-title" style={{ color: 'var(--accent-red)', fontWeight: 'bold' }}>🚨 ARP Poisoning Spoofing Detected — PC-012</div>
                      <div className="arp-g" style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px', marginTop: '8px', fontSize: '12px' }}>
                        <div><span style={{ color: 'var(--text-muted)' }}>Target IP:</span> 192.168.1.15</div>
                        <div><span style={{ color: 'var(--text-muted)' }}>Claimed Gateway:</span> 192.168.1.1</div>
                        <div><span style={{ color: 'var(--text-muted)' }}>Original MAC:</span> AA:BB:CC:DD:EE:FF</div>
                        <div style={{ color: 'var(--accent-red)', fontWeight: 'bold' }}><span>Suspicious MAC:</span> 11:22:33:44:55:66</div>
                      </div>
                    </div>
                  </div>

                  <div className="card hud-panel" style={{ border: '1px solid rgba(255, 159, 10, 0.3)', background: 'rgba(255, 159, 10, 0.03)' }}>
                    <div className="card-hd" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <div className="sec-title" style={{ display: 'flex', alignItems: 'center', gap: '6px', color: 'var(--accent-cyan)' }}>
                        <span className="dot" style={{ background: 'var(--accent-cyan)' }}></span>DNS Query Anomaly
                      </div>
                      <span className="badge bd-y">1 WARNING</span>
                    </div>
                    <div className="dns-box" style={{ marginTop: '10px' }}>
                      <div className="dns-title" style={{ color: 'var(--accent-cyan)', fontWeight: 'bold' }}>⚠️ DNS Hijack Attempt — HR-PC-02</div>
                      <div className="arp-g" style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px', marginTop: '8px', fontSize: '12px' }}>
                        <div><span style={{ color: 'var(--text-muted)' }}>Domain:</span> google.com</div>
                        <div><span style={{ color: 'var(--text-muted)' }}>Expected IP Range:</span> 142.250.x.x</div>
                        <div style={{ color: 'var(--accent-cyan)', fontWeight: 'bold' }}><span>Returned Rogue IP:</span> 192.168.1.100</div>
                        <div><span style={{ color: 'var(--text-muted)' }}>Host:</span> HR-PC-02</div>
                      </div>
                    </div>
                  </div>
                </div>

                {/* ROW 1: Top Talkers & VPN Status */}
                <div className="net-row" style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px', marginBottom: '16px' }}>
                  <div className="card hud-panel">
                    <div className="card-hd">
                      <div className="sec-title">
                        <span className="dot"></span>Top Network Talkers
                      </div>
                      <span className="badge bd-b">Live Bandwidth</span>
                    </div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', marginTop: '12px' }}>
                      {bandwidthStats.map((item) => (
                        <div key={item.rank} className="talker-item" style={{ display: 'flex', alignItems: 'center', gap: '12px', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '8px' }}>
                          <div className="tk-rank" style={{ fontStyle: 'italic', fontWeight: 'bold', color: 'var(--accent-cyan)', fontSize: '14px' }}>#{item.rank}</div>
                          <div className="tk-info" style={{ flex: 1 }}>
                            <div className="tk-name" style={{ fontWeight: 'bold', fontSize: '13px' }}>{item.hostname}</div>
                            <div className="tk-ip" style={{ fontSize: '11px', color: 'var(--text-dim)' }}>{item.ip}</div>
                          </div>
                          <div className="tk-bars" style={{ width: '180px' }}>
                            <div className="bar-row" style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '11px' }}>
                              <span style={{ color: 'var(--accent-red)', width: '10px' }}>↑</span>
                              <div className="bar-bg" style={{ flex: 1, height: '4px', background: 'rgba(255,255,255,0.03)' }}>
                                <div className="bar-fill" style={{ width: `${item.upPct}%`, height: '100%', background: 'var(--accent-red)' }} />
                              </div>
                              <span style={{ width: '55px', textAlign: 'right', color: 'var(--accent-red)' }}>{item.upload} MB/s</span>
                            </div>
                            <div className="bar-row" style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '11px' }}>
                              <span style={{ color: 'var(--accent-cyan)', width: '10px' }}>↓</span>
                              <div className="bar-bg" style={{ flex: 1, height: '4px', background: 'rgba(255,255,255,0.03)' }}>
                                <div className="bar-fill" style={{ width: `${item.downPct}%`, height: '100%', background: 'var(--accent-cyan)' }} />
                              </div>
                              <span style={{ width: '55px', textAlign: 'right', color: 'var(--accent-cyan)' }}>{item.download} MB/s</span>
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>

                  <div className="card hud-panel">
                    <div className="card-hd">
                      <div className="sec-title">
                        <span className="dot"></span>Operational Tunnel Status
                      </div>
                      <span className="badge bd-b">VPN Interfaces</span>
                    </div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', marginTop: '12px' }}>
                      {(agents.length > 0 ? agents : [
                        { hostname: 'PC-001', ip_address: '192.168.1.10', username: 'vraj', security: { vpn: 'Connected' } },
                        { hostname: 'HR-PC-02', ip_address: '192.168.1.22', username: 'priya', security: { vpn: 'Disconnected' } },
                        { hostname: 'Android-01', ip_address: '192.168.1.91', username: 'vraj', security: { vpn: 'Connected' } }
                      ]).slice(0, 4).map((agent, index) => {
                        const vpnOn = agent.security?.vpn === 'Connected' || agent.vpn_active;
                        const labelCol = vpnOn ? 'var(--accent-cyan)' : 'var(--text-muted)';
                        return (
                          <div key={agent.id || index} className="vpn-row" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '6px 0', borderBottom: '1px solid var(--border-subtle)' }}>
                            <div style={{ flex: 1 }}>
                              <div style={{ fontSize: '13px', fontWeight: 600 }}>{agent.hostname}</div>
                              <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>{agent.user || 'system'} · {agent.ip_address}</div>
                            </div>
                            <span className="badge" style={{ background: vpnOn ? 'rgba(0,242,255,0.1)' : 'rgba(255,255,255,0.03)', color: labelCol, border: `1px solid ${vpnOn ? 'var(--accent-cyan)' : 'var(--border-subtle)'}`, fontSize: '10px', padding: '2px 8px' }}>
                              {vpnOn ? 'TUNNEL ACTIVE' : 'NO TUNNEL'}
                            </span>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                </div>

                {/* ROW 2: Network Topology (Full Width) */}
                <div className="card hud-panel" style={{ marginBottom: '16px' }}>
                  <div className="card-hd">
                    <div className="sec-title">
                      <span className="dot"></span>Dynamic Mesh Network Topology
                    </div>
                    <span className="badge bd-b">Active Mapping</span>
                  </div>
                  <div className="topo-wrap" style={{ height: '300px', background: '#09090b', border: '1px solid var(--border-subtle)', borderRadius: '4px', marginTop: '10px', overflow: 'hidden' }}>
                    <canvas ref={canvasRef} id="topo" style={{ width: '100%', height: '100%', display: 'block' }} />
                  </div>
                </div>

                {/* ROW 3: External Connections & Heatmap */}
                <div className="net-row" style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px', marginBottom: '16px' }}>
                  <div className="card hud-panel">
                    <div className="card-hd">
                      <div className="sec-title">
                        <span className="dot"></span>External Socket Egress
                      </div>
                      <span className="badge bd-r">Active Connections</span>
                    </div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', marginTop: '12px' }}>
                      {[
                        { country: '🇺🇸', host: 'PC-007', remote: '185.220.101.42', port: '9001', proto: 'TCP', time: '14:10 UTC', status: 'Suspicious' },
                        { country: '🇩🇪', host: 'PC-001', remote: '104.21.48.1', port: '443', proto: 'HTTPS', time: '14:05 UTC', status: 'Normal' },
                        { country: '🇳🇱', host: 'HR-PC-02', remote: '45.153.204.10', port: '1194', proto: 'UDP', time: '13:58 UTC', status: 'VPN' },
                        { country: '🇷🇺', host: 'PC-012', remote: '91.108.4.18', port: '80', proto: 'HTTP', time: '13:30 UTC', status: 'Blocked' }
                      ].map((conn, idx) => (
                        <div key={idx} className="ext-item" style={{ display: 'flex', alignItems: 'center', gap: '12px', padding: '6px 0', borderBottom: '1px solid var(--border-subtle)' }}>
                          <span style={{ fontSize: '18px' }}>{conn.country}</span>
                          <div style={{ flex: 1 }}>
                            <div style={{ fontSize: '13px', fontWeight: 600 }}>{conn.host} → {conn.remote}</div>
                            <div style={{ fontSize: '11px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>Port {conn.port} · {conn.proto} · {conn.time}</div>
                          </div>
                          <span className="badge" style={{
                            background: conn.status === 'Blocked' ? 'rgba(255,59,48,0.1)' : conn.status === 'Suspicious' ? 'rgba(255,159,10,0.1)' : 'rgba(0,242,255,0.05)',
                            color: conn.status === 'Blocked' ? 'var(--accent-red)' : conn.status === 'Suspicious' ? 'var(--accent-red)' : 'var(--accent-cyan)',
                            fontSize: '10px'
                          }}>{conn.status.toUpperCase()}</span>
                        </div>
                      ))}
                    </div>
                  </div>

                  <div className="card hud-panel">
                    <div className="card-hd">
                      <div className="sec-title">
                        <span className="dot"></span>Hourly Packet Density Heatmap
                      </div>
                      <span className="badge bd-r">Metrics Scope: 24H</span>
                    </div>

                    <div className="heatmap-grid" style={{ display: 'grid', gridTemplateColumns: 'repeat(12, 1fr)', gap: '6px', marginTop: '16px' }}>
                      {[3, 1, 2, 1, 1, 2, 4, 7, 9, 10, 8, 7, 9, 10, 8, 6, 5, 4, 3, 2, 2, 1, 1, 2].map((v, i) => (
                        <div
                          key={i}
                          className="hm-cell"
                          style={{ height: '30px', borderRadius: '3px', background: `rgba(0, 242, 255, ${v / 11})`, border: '1px solid rgba(0, 242, 255, 0.05)' }}
                          title={`${String(i).padStart(2, '0')}:00 — ${v * 12} packets`}
                        />
                      ))}
                    </div>
                    <div className="hm-lbls" style={{ display: 'flex', justifyContent: 'space-between', fontSize: '10px', color: 'var(--text-muted)', marginTop: '6px' }}>
                      <span>00:00</span>
                      <span>06:00</span>
                      <span>12:00</span>
                      <span>18:00</span>
                      <span>23:00</span>
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginTop: '16px', fontSize: '11px', color: 'var(--text-muted)' }}>
                      <span>Idle</span>
                      <div style={{ display: 'flex', gap: '3px' }}>
                        <div style={{ width: '14px', height: '14px', borderRadius: '3px', background: 'rgba(0,242,255,.1)' }}></div>
                        <div style={{ width: '14px', height: '14px', borderRadius: '3px', background: 'rgba(0,242,255,.3)' }}></div>
                        <div style={{ width: '14px', height: '14px', borderRadius: '3px', background: 'rgba(0,242,255,.6)' }}></div>
                        <div style={{ width: '14px', height: '14px', borderRadius: '3px', background: 'rgba(0,242,255,.95)' }}></div>
                      </div>
                      <span>Saturated</span>
                    </div>
                  </div>
                </div>

                {/* ROW 4: HTTP Packet Inspector */}
                <div className="card hud-panel">
                  <div className="card-hd" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
                    <div className="sec-title">
                      <span className="dot"></span>HTTP Live Payload Requests log
                    </div>
                    <span className="badge bd-b">HTTP Inspect</span>
                  </div>
                  <div style={{ maxHeight: '350px', overflowY: 'auto' }}>
                    <table className="telemetry-table" style={{ border: '1px solid var(--border-subtle)' }}>
                      <thead>
                        <tr>
                          <th>Method</th>
                          <th>Request Destination</th>
                          <th>Host</th>
                          <th>Status</th>
                          <th>Size</th>
                        </tr>
                      </thead>
                      <tbody>
                        {apiTraffic.map((req, idx) => (
                          <tr key={idx}>
                            <td><span className={`pkt-method m-${req.method}`} style={{
                              padding: '2px 6px',
                              borderRadius: '3px',
                              fontSize: '10px',
                              fontWeight: 'bold',
                              background: req.method === 'POST' ? 'rgba(255, 159, 10, 0.15)' : 'rgba(0, 242, 255, 0.15)',
                              color: req.method === 'POST' ? 'var(--accent-cyan)' : '#00F2FF'
                            }}>{req.method}</span></td>
                            <td style={{ fontFamily: 'var(--font-mono)' }}>{req.url}</td>
                            <td>redeye.local</td>
                            <td>
                              <span className={`badge ${req.status < 300 ? 'bd-g' : 'bd-r'}`}>
                                {req.status} {req.statusText}
                              </span>
                            </td>
                            <td style={{ fontFamily: 'var(--font-mono)' }}>{req.payloadSize} B</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              </div>
            )}

            {/* 4. LOGS VIEWPORT */}
            {activeSidebarTab === 'logs' && (() => {
              const filteredLogs = systemLogs.filter(log => {
                const matchLevel = logFilterLevel === 'ALL' || log.level === logFilterLevel || (logFilterLevel === 'CRIT' && log.level === 'CRITICAL') || (logFilterLevel === 'WARN' && log.level === 'WARNING');
                const matchCategory = !selectedCategory || log.category === selectedCategory;
                const matchSubcategory = !selectedSubcategory || log.subcategory === selectedSubcategory;
                const matchSearch = !logSearchTerm ||
                  (log.msg && log.msg.toLowerCase().includes(logSearchTerm.toLowerCase())) ||
                  (log.level && log.level.toLowerCase().includes(logSearchTerm.toLowerCase())) ||
                  (log.agent_name && log.agent_name.toLowerCase().includes(logSearchTerm.toLowerCase())) ||
                  (log.agent_ip && log.agent_ip.toLowerCase().includes(logSearchTerm.toLowerCase())) ||
                  (log.subcategory && log.subcategory.toLowerCase().includes(logSearchTerm.toLowerCase()));
                return matchLevel && matchCategory && matchSubcategory && matchSearch;
              });

              const handleExecutePlaygroundSql = (e) => {
                if (e) e.preventDefault();
                const query = sqlPlaygroundQuery.trim().toLowerCase();
                logSql(sqlPlaygroundQuery);

                if (query.includes('agents')) {
                  const onlineOnly = query.includes('online');
                  const data = onlineOnly ? agents.filter(a => a.status === 'online') : agents;
                  setSqlPlaygroundResult({
                    columns: ['id', 'hostname', 'ip_address', 'status', 'risk_score'],
                    rows: data.map(a => [a.id, a.hostname, a.ip_address, a.status, a.risk_score]),
                    count: data.length
                  });
                } else if (query.includes('alerts') || query.includes('incidents')) {
                  const critOnly = query.includes('critical');
                  const data = critOnly ? alerts.filter(a => a.level === 'CRITICAL' || a.level === 'CRIT') : alerts;
                  setSqlPlaygroundResult({
                    columns: ['id', 'level', 'message', 'timestamp'],
                    rows: data.map(a => [a.id, a.level, a.message, a.timestamp || a.time || '']),
                    count: data.length
                  });
                } else if (query.includes('logs')) {
                  setSqlPlaygroundResult({
                    columns: ['time', 'level', 'msg'],
                    rows: systemLogs.map(l => [l.time, l.level, l.msg]),
                    count: systemLogs.length
                  });
                } else {
                  setSqlPlaygroundResult({
                    columns: ['status', 'message'],
                    rows: [['OK', 'Query executed successfully. 0 rows returned.']],
                    count: 0
                  });
                }
              };

              return (
                <div className="page active" style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
                  <div className="page-title">Tactical Event & SQL Audit Registry</div>
                  <div className="page-sub">Central database logs, network packet traces, and raw query logs</div>

                  <div className="two-col" style={{ display: 'grid', gridTemplateColumns: '1.2fr 0.8fr', gap: '20px', alignItems: 'stretch' }}>
                    {/* Left Pane: System Events Feed */}
                    <div className="card hud-panel" style={{ display: 'flex', flexDirection: 'column', height: '650px' }}>
                      <div className="card-hd" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
                        <div className="sec-title">
                          <span className="dot" style={{ background: 'var(--accent-cyan)' }}></span>System Event Log
                        </div>
                        <span className="badge bd-b">{filteredLogs.length} Events</span>
                      </div>

                      <div style={{ display: 'flex', flex: 1, overflow: 'hidden' }}>
                        {/* RIGHT: Logs feed column (Full Width now) */}
                        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
                          {/* Filter Bar */}
                          <div style={{ display: 'flex', gap: '10px', marginBottom: '12px', flexWrap: 'wrap' }}>
                            <input
                              className="finp"
                              type="text"
                              placeholder="Search logs pattern..."
                              style={{ flex: 1, minWidth: '180px', pointerEvents: 'auto', userSelect: 'text' }}
                              value={logSearchTerm}
                              onChange={(e) => setLogSearchTerm(e.target.value)}
                            />
                            <select
                              className="finp fsel"
                              style={{ width: '160px', pointerEvents: 'auto' }}
                              value={selectedCategory || 'ALL'}
                              onChange={(e) => {
                                const val = e.target.value;
                                setSelectedCategory(val === 'ALL' ? null : val);
                                setSelectedSubcategory(null);
                              }}
                            >
                              <option value="ALL">All Categories</option>
                              <option value="ACTIVITY STREAM">Activity Stream</option>
                              <option value="FILE MONITORING">File Monitoring</option>
                              <option value="SECURITY">Security</option>
                              <option value="SYSTEM">System</option>
                              <option value="NETWORK SECURITY">Network Security</option>
                              <option value="EXAM MONITORING">Exam Monitoring</option>
                              <option value="AGENT">Agent</option>
                            </select>
                            <select
                              className="finp fsel"
                              style={{ width: '130px', pointerEvents: 'auto' }}
                              value={logFilterLevel}
                              onChange={(e) => setLogFilterLevel(e.target.value)}
                            >
                              <option value="ALL">All Levels</option>
                              <option value="INFO">INFO</option>
                              <option value="WARN">WARN</option>
                              <option value="ERROR">ERROR</option>
                              <option value="CRIT">CRITICAL</option>
                            </select>
                          </div>

                          {/* Log feed container */}
                          <div className="log-container" style={{
                            flex: 1,
                            background: '#09090b',
                            border: '1px solid var(--border-subtle)',
                            borderRadius: '4px',
                            padding: '10px',
                            overflowY: 'auto',
                            fontFamily: "'JetBrains Mono', monospace",
                            fontSize: '11px',
                            display: 'flex',
                            flexDirection: 'column',
                            gap: '6px'
                          }}>
                            {filteredLogs.length > 0 ? (
                              filteredLogs.map((log, index) => {
                                const isCrit = log.level === 'CRIT' || log.level === 'CRITICAL';
                                const isErr = log.level === 'ERROR';
                                const isWarn = log.level === 'WARN' || log.level === 'WARNING';

                                const lvColor = isCrit ? '#ff3b30' : isErr ? '#ff9500' : isWarn ? '#ffcc00' : '#00ff80';
                                const lvBg = isCrit ? 'rgba(255,59,48,0.15)' : isErr ? 'rgba(255,149,0,0.15)' : isWarn ? 'rgba(255,204,0,0.15)' : 'rgba(0,255,128,0.1)';

                                return (
                                  <div key={log.id || index} style={{
                                    display: 'flex',
                                    gap: '8px',
                                    borderBottom: '1px solid rgba(255,255,255,0.02)',
                                    paddingBottom: '4px',
                                    alignItems: 'flex-start'
                                  }}>
                                    <span style={{ color: '#71717a', flexShrink: 0 }}>[{log.time}]</span>
                                    <span style={{
                                      color: 'var(--accent-cyan)',
                                      background: 'rgba(0, 240, 255, 0.05)',
                                      padding: '1px 5px',
                                      borderRadius: '3px',
                                      fontSize: '9.5px',
                                      fontFamily: 'var(--font-mono)',
                                      border: '1px solid rgba(0, 240, 255, 0.15)',
                                      flexShrink: 0
                                    }}>
                                      {log.agent_name || "Server"} | {log.agent_ip || "127.0.0.1"}
                                    </span>
                                    <span style={{
                                      color: lvColor,
                                      background: lvBg,
                                      padding: '1px 5px',
                                      borderRadius: '3px',
                                      fontSize: '9.5px',
                                      fontWeight: 'bold',
                                      textTransform: 'uppercase',
                                      minWidth: '50px',
                                      textAlign: 'center',
                                      flexShrink: 0
                                    }}>
                                      {log.level}
                                    </span>
                                    <span style={{
                                      color: 'var(--text-dim)',
                                      fontSize: '9.5px',
                                      background: 'rgba(255,255,255,0.03)',
                                      padding: '1px 4px',
                                      borderRadius: '3px',
                                      textTransform: 'uppercase',
                                      flexShrink: 0
                                    }}>
                                      {log.subcategory || "System"}
                                    </span>
                                    <span style={{ color: '#e4e4e7', wordBreak: 'break-all' }}>{log.msg}</span>
                                  </div>
                                );
                              })
                            ) : (
                              <div style={{ color: '#71717a', textAlign: 'center', marginTop: '20px', fontStyle: 'italic' }}>
                                No log events match current filter query
                              </div>
                            )}
                          </div>
                        </div>
                      </div>
                    </div>

                    {/* Right Pane: SQL Logger & DB playground */}
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
                      {/* Database Status Panel */}
                      <div className="card hud-panel">
                        <div className="card-hd" style={{ marginBottom: '8px' }}>
                          <div className="sec-title">
                            <span className="dot" style={{ background: '#2ecc71' }}></span>Database Topology
                          </div>
                          <span className="badge bd-g">Connected</span>
                        </div>
                        <div style={{ fontSize: '11px', display: 'flex', flexDirection: 'column', gap: '6px', fontFamily: "'JetBrains Mono', monospace", color: '#a1a1aa' }}>
                          <div><span style={{ color: 'var(--accent-cyan)' }}>DBMS:</span> PostgreSQL v15.2 (RedEye-Core)</div>
                          <div><span style={{ color: 'var(--accent-cyan)' }}>Host:</span> localhost:5432 / dev_pool</div>
                          <div><span style={{ color: 'var(--accent-cyan)' }}>Sockets:</span> 12 Active Connections</div>
                        </div>
                      </div>

                      {/* SQL Playground */}
                      <div className="card hud-panel" style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                        <div className="card-hd" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                          <div className="sec-title">
                            <span className="dot"></span>SQL Sandbox Client
                          </div>
                          <button className="scan-btn" onClick={() => setSqlPlaygroundResult(null)} style={{ padding: '2px 8px', fontSize: '11px' }}>Reset</button>
                        </div>

                        <form onSubmit={handleExecutePlaygroundSql} style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                          <textarea
                            className="finp"
                            rows={3}
                            value={sqlPlaygroundQuery}
                            onChange={(e) => setSqlPlaygroundQuery(e.target.value)}
                            style={{
                              width: '100%',
                              fontFamily: "'JetBrains Mono', monospace",
                              fontSize: '11px',
                              background: '#09090b',
                              borderColor: 'var(--border-subtle)',
                              color: '#fff',
                              pointerEvents: 'auto',
                              userSelect: 'text'
                            }}
                          />
                          <button type="submit" className="scan-btn" style={{ background: 'var(--accent-cyan)', color: '#000', fontWeight: 'bold', borderColor: 'var(--accent-cyan)', fontSize: '11px', padding: '6px' }}>
                            Execute SQL Command
                          </button>
                        </form>

                        {/* SQL result area */}
                        {sqlPlaygroundResult && (
                          <div style={{
                            background: '#09090b',
                            border: '1px solid var(--border-subtle)',
                            borderRadius: '4px',
                            padding: '8px',
                            fontSize: '11px',
                            maxHeight: '180px',
                            overflowY: 'auto'
                          }}>
                            <div style={{ color: 'var(--accent-cyan)', fontWeight: 'bold', borderBottom: '1px solid rgba(0,242,255,0.1)', paddingBottom: '4px', marginBottom: '6px' }}>
                              Result: {sqlPlaygroundResult.count} Rows Affected
                            </div>
                            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '10px', fontFamily: "'JetBrains Mono', monospace" }}>
                              <thead>
                                <tr style={{ borderBottom: '1px solid var(--border-subtle)', textAlign: 'left', color: '#fff' }}>
                                  {sqlPlaygroundResult.columns.map(col => (
                                    <th key={col} style={{ padding: '4px' }}>{col}</th>
                                  ))}
                                </tr>
                              </thead>
                              <tbody>
                                {sqlPlaygroundResult.rows.map((row, rIdx) => (
                                  <tr key={rIdx} style={{ borderBottom: '1px solid rgba(255,255,255,0.02)' }}>
                                    {row.map((cell, cIdx) => (
                                      <td key={cIdx} style={{ padding: '4px', color: '#a1a1aa' }}>{String(cell)}</td>
                                    ))}
                                  </tr>
                                ))}
                              </tbody>
                            </table>
                          </div>
                        )}
                      </div>

                      {/* SQL Logger audit feed */}
                      <div className="card hud-panel" style={{ display: 'flex', flexDirection: 'column', height: '220px' }}>
                        <div className="card-hd" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                          <div className="sec-title">
                            <span className="dot" style={{ background: 'var(--accent-cyan)' }}></span>SQL Query Audit Feed
                          </div>
                          <button className="scan-btn" onClick={() => setSqlLogs([])} style={{ padding: '2px 8px', fontSize: '11px' }}>Clear</button>
                        </div>

                        <div style={{
                          flex: 1,
                          background: '#09090b',
                          border: '1px solid var(--border-subtle)',
                          borderRadius: '4px',
                          padding: '8px',
                          overflowY: 'auto',
                          fontFamily: "'JetBrains Mono', monospace",
                          fontSize: '10px',
                          display: 'flex',
                          flexDirection: 'column',
                          gap: '6px'
                        }}>
                          {sqlLogs.length > 0 ? (
                            sqlLogs.map((item, idx) => (
                              <div key={idx} style={{ borderBottom: '1px solid rgba(255,255,255,0.02)', paddingBottom: '4px' }}>
                                <div style={{ color: 'var(--accent-cyan)', fontSize: '9px' }}>[{item.timestamp}]</div>
                                <div style={{ color: '#a1a1aa', wordBreak: 'break-all' }}>{item.query}</div>
                              </div>
                            ))
                          ) : (
                            <div style={{ color: '#71717a', textAlign: 'center', marginTop: '40px', fontStyle: 'italic' }}>
                              No SQL queries executed yet
                            </div>
                          )}
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              );
            })()}

            {/* 5. INCIDENTS VIEWPORT */}
            {activeSidebarTab === 'incidents' && (
              <div className="page active">
                <div className="page-title" style={{ color: 'var(--accent-red)' }}>Threat Incidents & Event Stream</div>
                <div className="page-sub">Real-time alerts requiring immediate operator intervention</div>

                <div className="stat-grid" style={{ marginBottom: '20px', display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '16px', marginTop: '16px' }}>
                  <div className="stat" style={{ border: '1px solid rgba(255,59,48,0.3)', background: 'rgba(255,59,48,0.03)', padding: '12px', borderRadius: '6px' }}>
                    <div className="stat-lbl" style={{ color: 'var(--accent-red)', fontSize: '11px', textTransform: 'uppercase' }}>Critical Threats</div>
                    <div className="stat-val" style={{ color: 'var(--accent-red)', fontSize: '24px', fontWeight: 'bold' }}>
                      {alerts.filter(a => a.level === 'CRITICAL' || a.level === 'CRIT').length}
                    </div>
                  </div>
                  <div className="stat" style={{ border: '1px solid rgba(255,159,10,0.3)', background: 'rgba(255,159,10,0.03)', padding: '12px', borderRadius: '6px' }}>
                    <div className="stat-lbl" style={{ color: 'var(--accent-cyan)', fontSize: '11px', textTransform: 'uppercase' }}>Warnings</div>
                    <div className="stat-val" style={{ color: 'var(--accent-cyan)', fontSize: '24px', fontWeight: 'bold' }}>
                      {alerts.filter(a => a.level === 'WARN' || a.level === 'WARNING').length}
                    </div>
                  </div>
                  <div className="stat" style={{ border: '1px solid var(--border-subtle)', background: 'rgba(255,255,255,0.02)', padding: '12px', borderRadius: '6px' }}>
                    <div className="stat-lbl" style={{ color: 'var(--text-muted)', fontSize: '11px', textTransform: 'uppercase' }}>Informational</div>
                    <div className="stat-val" style={{ color: '#fff', fontSize: '24px', fontWeight: 'bold' }}>
                      {alerts.filter(a => a.level === 'INFO').length}
                    </div>
                  </div>
                  <div className="stat" style={{ border: '1px solid rgba(0,242,255,0.2)', background: 'rgba(0,242,255,0.02)', padding: '12px', borderRadius: '6px' }}>
                    <div className="stat-lbl" style={{ color: 'var(--accent-cyan)', fontSize: '11px', textTransform: 'uppercase' }}>Mitigated</div>
                    <div className="stat-val" style={{ color: 'var(--accent-cyan)', fontSize: '24px', fontWeight: 'bold' }}>28</div>
                  </div>
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                  {alerts.map((alert, index) => {
                    const isCrit = alert.level === 'CRITICAL' || alert.level === 'CRIT';
                    const isWarn = alert.level === 'WARN' || alert.level === 'WARNING';

                    const borderCol = isCrit ? 'rgba(255,59,48,0.4)' : isWarn ? 'rgba(255,159,10,0.3)' : 'var(--border-subtle)';
                    const bgCol = isCrit ? 'rgba(255,59,48,0.02)' : isWarn ? 'rgba(255,159,10,0.02)' : 'var(--bg-recessed)';
                    const textCol = isCrit ? 'var(--accent-red)' : isWarn ? 'var(--accent-cyan)' : '#fff';
                    const emoji = isCrit ? '🚨' : isWarn ? '⚠️' : '📡';

                    return (
                      <div
                        key={alert.id || index}
                        className="alert-item"
                        style={{
                          display: 'flex',
                          gap: '12px',
                          border: `1px solid ${borderCol}`,
                          background: bgCol,
                          padding: '14px',
                          borderRadius: '6px',
                          alignItems: 'flex-start'
                        }}
                      >
                        <div style={{ fontSize: '20px' }}>{emoji}</div>
                        <div style={{ flex: 1 }}>
                          <div style={{ color: textCol, fontWeight: 'bold', fontSize: '14px', display: 'flex', justifyContent: 'space-between' }}>
                            <span>{alert.message.split(' — ')[0]}</span>
                            <span style={{ fontSize: '10px', textTransform: 'uppercase', color: 'var(--text-muted)' }}>{alert.level}</span>
                          </div>
                          <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '4px' }}>{alert.message}</div>
                          <div style={{ fontSize: '11px', color: 'var(--text-dim)', marginTop: '8px' }}>
                            Uptime check: {alert.time} • Source: Gateway Firewall Core
                          </div>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            )}
            {/* 5. NETWORK VIEWPORT */}
            {activeSidebarTab === 'network' && (
              <div className="page active">
                <div className="page-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
                  <div>
                    <div className="page-title">Local Subnet Topology</div>
                    <div className="page-sub">Subnet device discovery, switch port mapper, and topology visualizer</div>
                  </div>
                  <button className="scan-btn" onClick={() => alert("Subnet ARP discovery scan initiated. Discovered 3 new nodes.")}>
                    INITIATE SUBNET SCAN
                  </button>
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                  {/* Top Stats */}
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '16px' }}>
                    <div style={{ padding: '10px 14px', background: 'var(--bg-recessed)', border: '1px solid var(--border-subtle)', borderRadius: '4px', fontFamily: 'var(--font-mono)' }}>
                      <div style={{ fontSize: '9px', color: 'var(--text-dim)' }}>SUBNET_RANGE</div>
                      <div style={{ fontSize: '15px', fontWeight: 'bold', color: '#fff' }}>192.168.1.0/24</div>
                    </div>
                    <div style={{ padding: '10px 14px', background: 'var(--bg-recessed)', border: '1px solid var(--border-subtle)', borderRadius: '4px', fontFamily: 'var(--font-mono)' }}>
                      <div style={{ fontSize: '9px', color: 'var(--text-dim)' }}>ROUTER_GATEWAY</div>
                      <div style={{ fontSize: '15px', fontWeight: 'bold', color: 'var(--accent-cyan)' }}>192.168.1.1 (ONLINE)</div>
                    </div>
                    <div style={{ padding: '10px 14px', background: 'var(--bg-recessed)', border: '1px solid var(--border-subtle)', borderRadius: '4px', fontFamily: 'var(--font-mono)' }}>
                      <div style={{ fontSize: '9px', color: 'var(--text-dim)' }}>DISCOVERED_DEVICES</div>
                      <div style={{ fontSize: '15px', fontWeight: 'bold', color: '#fff' }}>{4 + agents.length} Nodes</div>
                    </div>
                    <div style={{ padding: '10px 14px', background: 'var(--bg-recessed)', border: '1px solid var(--border-subtle)', borderRadius: '4px', fontFamily: 'var(--font-mono)' }}>
                      <div style={{ fontSize: '9px', color: 'var(--text-dim)' }}>MANAGED_AGENTS</div>
                      <div style={{ fontSize: '15px', fontWeight: 'bold', color: 'var(--accent-cyan)' }}>{agents.length} Agent{agents.length !== 1 ? 's' : ''}</div>
                    </div>
                  </div>

                  {/* Topology Visualization Graph */}
                  <div className="hud-panel" style={{ padding: '14px' }}>
                    <div className="hud-panel-header">■ TACTICAL TOPOLOGY GRAPH</div>
                    <div style={{ padding: '15px', display: 'flex', flexDirection: 'column', gap: '10px', background: '#0d0d0e', borderRadius: '4px', border: '1px solid var(--border-subtle)' }}>
                      {/* CSS-based tree topology */}
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', borderLeft: '2px solid var(--accent-cyan)', paddingLeft: '10px' }}>
                        <div style={{ width: '8px', height: '8px', background: 'var(--accent-cyan)', borderRadius: '50%' }} />
                        <span style={{ fontSize: '12px', fontWeight: 'bold', color: '#fff' }}>GATEWAY ROUTER: 192.168.1.1 (gpon.net - zte)</span>
                      </div>
                      <div style={{ marginLeft: '20px', borderLeft: '2px dashed var(--border-subtle)', paddingLeft: '20px', display: 'flex', flexDirection: 'column', gap: '10px' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                          <span style={{ color: 'var(--text-dim)' }}>├─</span>
                          <span style={{ fontSize: '11px', color: 'var(--accent-cyan)' }}>C2 Console: Host (10.118.111.211)</span>
                        </div>
                        {agents.map((agent, index) => (
                          <div key={agent.id} style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '11px' }}>
                            <span style={{ color: 'var(--text-dim)' }}>├─ [Port {index + 2}]</span>
                            <span style={{ color: '#fff', fontWeight: 'bold' }}>{agent.hostname} ({agent.ip_address})</span>
                            <span className="badge bd-g" style={{ fontSize: '8px', padding: '0px 4px' }}>AGENT</span>
                          </div>
                        ))}
                        <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '11px' }}>
                          <span style={{ color: 'var(--text-dim)' }}>├─ [Wi-Fi]</span>
                          <span style={{ color: 'var(--text-muted)' }}>realme-5i Mobile (192.168.1.2)</span>
                          <span className="badge bd-b" style={{ fontSize: '8px', padding: '0px 4px' }}>UNMANAGED</span>
                        </div>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '11px' }}>
                          <span style={{ color: 'var(--text-dim)' }}>└─ [Wi-Fi]</span>
                          <span style={{ color: 'var(--text-muted)' }}>V2307 Mobile (192.168.1.3)</span>
                          <span className="badge bd-b" style={{ fontSize: '8px', padding: '0px 4px' }}>UNMANAGED</span>
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Discovered Subnet Devices List Table */}
                  <div className="hud-panel">
                    <div className="hud-panel-header">■ DISCOVERED_DEVICES_MATRIX</div>
                    <div className="tbl-wrap" style={{ margin: 0, border: 'none' }}>
                      <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                        <thead>
                          <tr style={{ borderBottom: '1px solid var(--border-subtle)', fontSize: '10px', textTransform: 'uppercase', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                            <th style={{ textAlign: 'left', padding: '10px' }}>IP ADDRESS</th>
                            <th style={{ textAlign: 'left', padding: '10px' }}>MAC ADDRESS</th>
                            <th style={{ textAlign: 'left', padding: '10px' }}>VENDOR / HOSTNAME</th>
                            <th style={{ textAlign: 'left', padding: '10px' }}>DEVICE TYPE</th>
                            <th style={{ textAlign: 'left', padding: '10px' }}>INTERFACE PORT</th>
                            <th style={{ textAlign: 'left', padding: '10px' }}>AGENT STATUS</th>
                            <th style={{ textAlign: 'center', padding: '10px', width: '150px' }}>ACTIONS</th>
                          </tr>
                        </thead>
                        <tbody>
                          {[
                            { ip: '10.118.111.211', mac: 'C0:94:AD:CF:87:5A', vendor: 'gpon.net (zte)', type: 'Gateway', port: 'Uplink-Trunk', status: 'N/A' },
                            { ip: '10.118.111.211', mac: 'BA:62:E3:13:45:F1', vendor: 'realme-5i', type: 'WLAN Device', port: 'Wi-Fi-2.4G', status: 'UNMANAGED' },
                            { ip: '10.118.111.211', mac: 'BA:8D:34:ED:00:7E', vendor: 'V2307', type: 'WLAN Device', port: 'Wi-Fi-5G', status: 'UNMANAGED' },
                            { ip: '10.118.111.211', mac: '14:D4:24:8F:6C:6D', vendor: 'Vraj (C2 Controller Host)', type: 'Management Console', port: 'Switch-Port-1', status: 'N/A' },
                            ...agents.map(a => ({
                              ip: a.ip_address,
                              mac: a.mac_address || '00:1A:2B:3C:4D:5E',
                              vendor: `${a.hostname} (${a.platform})`,
                              type: 'Managed Agent',
                              port: `Switch-Port-${a.platform === 'Windows' ? '3' : '2'}`,
                              status: 'MANAGED',
                              agentId: a.id
                            }))
                          ].map((dev, idx) => (
                            <tr key={idx} style={{ borderBottom: '1px solid rgba(255,255,255,0.02)', fontSize: '11px', backgroundColor: idx % 2 === 0 ? '#121214' : '#18181c' }}>
                              <td style={{ padding: '10px', fontFamily: 'var(--font-mono)', color: 'var(--accent-cyan)', fontWeight: 'bold' }}>{dev.ip}</td>
                              <td style={{ padding: '10px', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>{dev.mac}</td>
                              <td style={{ padding: '10px', color: '#fff' }}>{dev.vendor}</td>
                              <td style={{ padding: '10px', color: 'var(--text-muted)' }}>{dev.type}</td>
                              <td style={{ padding: '10px', fontFamily: 'var(--font-mono)', color: 'var(--text-dim)' }}>{dev.port}</td>
                              <td style={{ padding: '10px' }}>
                                <span className={`badge ${dev.status === 'MANAGED' ? 'bd-g' : dev.status === 'UNMANAGED' ? 'bd-r' : 'bd-b'}`} style={{ fontSize: '9px' }}>
                                  {dev.status}
                                </span>
                              </td>
                              <td style={{ padding: '10px', textAlign: 'center' }}>
                                <div style={{ display: 'flex', gap: '8px', justifyContent: 'center' }}>
                                  <button
                                    className="scan-btn"
                                    style={{ padding: '3px 8px', fontSize: '9px', textTransform: 'uppercase' }}
                                    onClick={() => alert(`Ping request sent to ${dev.ip}. RTT: 0.8ms`)}
                                  >
                                    PING
                                  </button>
                                  {dev.status === 'UNMANAGED' && (
                                    <button
                                      className="scan-btn"
                                      style={{ padding: '3px 8px', fontSize: '9px', textTransform: 'uppercase', background: 'var(--accent-cyan)', color: '#000', borderColor: 'var(--accent-cyan)' }}
                                      onClick={() => {
                                        setActiveSidebarTab('console');
                                        alert(`Routing operator to the Stager Compiler for remote deployment targeting ${dev.ip}`);
                                      }}
                                    >
                                      DEPLOY
                                    </button>
                                  )}
                                  {dev.status === 'MANAGED' && (
                                    <button
                                      className="scan-btn"
                                      style={{ padding: '3px 8px', fontSize: '9px', textTransform: 'uppercase', background: 'var(--accent-cyan)', color: '#000', borderColor: 'var(--accent-cyan)' }}
                                      onClick={() => {
                                        setSelectedAgentId(dev.agentId);
                                        setActiveSidebarTab('console');
                                      }}
                                    >
                                      CONSOLE
                                    </button>
                                  )}
                                </div>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                </div>
              </div>
            )}



            {/* 6. CONSOLE VIEWPORT */}
            {activeSidebarTab === 'console' && (
              <div className="page active" style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
                <div className="page-title">Operational Command Workstation</div>
                <div className="page-sub">Interactive C2 shell session console and payload stager compiler</div>

                <div className="two-col" style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px', alignItems: 'stretch' }}>
                  {/* Left Column: Compiler */}
                  <div className="card hud-panel" style={{ height: 'fit-content' }}>
                    <div className="card-hd">
                      <div className="sec-title">
                        <span className="dot"></span>Stager Compiler Builder
                      </div>
                      <span className="badge bd-b">AES-256</span>
                    </div>

                    <form onSubmit={handleGenerateAgent} style={{ display: 'flex', flexDirection: 'column', gap: '14px', marginTop: '12px' }}>
                      <div style={{ display: 'flex', gap: '14px', flexWrap: 'wrap' }}>
                        <div style={{ flex: '1', minWidth: '200px', display: 'flex', flexDirection: 'column', gap: '4px' }}>
                          <label style={{ fontSize: '11px', textTransform: 'uppercase', color: '#fff', fontWeight: 'bold' }}>Agent Name / ID</label>
                          <input
                            type="text"
                            className="finp"
                            style={{ width: '100%', pointerEvents: 'auto', userSelect: 'text' }}
                            value={formAgentName}
                            onChange={(e) => setFormAgentName(e.target.value)}
                            placeholder="e.g. HR-PC-01"
                            required
                          />
                        </div>
                        <div style={{ flex: '1', minWidth: '200px', display: 'flex', flexDirection: 'column', gap: '4px' }}>
                          <label style={{ fontSize: '11px', textTransform: 'uppercase', color: '#fff', fontWeight: 'bold' }}>Heartbeat Interval</label>
                          <select
                            className="finp fsel"
                            style={{ width: '100%', pointerEvents: 'auto' }}
                            value={formHeartbeat}
                            onChange={(e) => setFormHeartbeat(e.target.value)}
                          >
                            <option value="60s">60 seconds (Standard)</option>
                            <option value="5m">5 minutes (Stealth)</option>
                            <option value="10m">10 minutes (Passive)</option>
                          </select>
                        </div>
                      </div>

                      <div style={{ display: 'flex', gap: '14px', flexWrap: 'wrap' }}>
                        <div style={{ flex: '1', minWidth: '200px', display: 'flex', flexDirection: 'column', gap: '4px' }}>
                          <label style={{ fontSize: '11px', textTransform: 'uppercase', color: '#fff', fontWeight: 'bold' }}>Target OS</label>
                          <div style={{ display: 'flex', gap: '16px', marginTop: '6px', flexWrap: 'wrap' }}>
                            <label style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '13px', cursor: 'pointer' }}>
                              <input type="radio" name="targetOS" checked={formOS === 'Windows'} onChange={() => setFormOS('Windows')} />
                              Windows
                            </label>
                            <label style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '13px', cursor: 'pointer' }}>
                              <input type="radio" name="targetOS" checked={formOS === 'Linux'} onChange={() => setFormOS('Linux')} />
                              Linux
                            </label>
                            <label style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '13px', cursor: 'pointer' }}>
                              <input type="radio" name="targetOS" checked={formOS === 'Android'} onChange={() => setFormOS('Android')} />
                              Android
                            </label>
                            <label style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '13px', cursor: 'pointer' }}>
                              <input type="radio" name="targetOS" checked={formOS === 'OTA Update'} onChange={() => setFormOS('OTA Update')} />
                              OTA Update
                            </label>
                          </div>
                        </div>
                      </div>

                      <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                        <label style={{ fontSize: '11px', textTransform: 'uppercase', color: '#fff', fontWeight: 'bold' }}>Description (optional)</label>
                        <input
                          type="text"
                          className="finp"
                          style={{ width: '100%', pointerEvents: 'auto', userSelect: 'text' }}
                          value={formDesc}
                          onChange={(e) => setFormDesc(e.target.value)}
                          placeholder="Describe this payload's scope..."
                        />
                      </div>

                      <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                        <label style={{ fontSize: '11px', textTransform: 'uppercase', color: '#fff', fontWeight: 'bold' }}>Payload Tags</label>
                        <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
                          {['Critical', 'Production', 'Testing', 'Developer', 'Office', 'Stealth'].map(tag => {
                            const active = formTags.includes(tag);
                            return (
                              <button
                                key={tag}
                                type="button"
                                className="scan-btn"
                                style={{
                                  padding: '4px 10px',
                                  fontSize: '12px',
                                  background: active ? 'var(--accent-cyan)' : 'transparent',
                                  color: active ? '#000' : '#fff',
                                  borderColor: active ? 'var(--accent-cyan)' : 'var(--border-subtle)'
                                }}
                                onClick={() => {
                                  if (active) {
                                    setFormTags(prev => prev.filter(t => t !== tag));
                                  } else {
                                    setFormTags(prev => [...prev, tag]);
                                  }
                                }}
                              >
                                {tag}
                              </button>
                            );
                          })}
                        </div>
                      </div>

                      <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', borderTop: '1px solid var(--border-subtle)', paddingTop: '12px' }}>
                        <label style={{ fontSize: '11px', textTransform: 'uppercase', color: 'var(--accent-cyan)', fontWeight: 'bold', marginBottom: '4px' }}>Included Monitoring Modules</label>
                        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(180px, 1fr))', gap: '8px', fontSize: '11px' }}>
                          {[
                            "System Specs",
                            "User Logins",
                            "AV & Firewall Check",
                            "Process Spawning",
                            "Software Audit",
                            "USB Insertion",
                            "Socket telemetry",
                            "MitM Defense"
                          ].map(f => (
                            <div key={f} style={{ display: 'flex', alignItems: 'center', gap: '6px', color: '#fff' }}>
                              <span style={{ color: 'var(--accent-cyan)', fontWeight: 'bold' }}>✓</span>
                              <span>{f}</span>
                            </div>
                          ))}
                        </div>
                      </div>

                      <div style={{ marginTop: '10px' }}>
                        {isGenerating ? (
                          <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '12px', color: 'var(--accent-cyan)' }}>
                              <span>Compiling client source binaries...</span>
                              <span>{generateProgress}%</span>
                            </div>
                            <div style={{ height: '6px', background: 'rgba(255,255,255,0.05)', borderRadius: '3px', overflow: 'hidden' }}>
                              <div style={{ height: '100%', background: 'var(--accent-cyan)', width: `${generateProgress}%`, borderRadius: '3px' }}></div>
                            </div>
                          </div>
                        ) : (
                          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                            <button type="submit" className="scan-btn" style={{ padding: '10px 18px', width: '100%', background: 'var(--accent-cyan)', color: '#000', fontWeight: 'bold', borderColor: 'var(--accent-cyan)' }}>
                              COMPILE & COMPILE STAGER EXE
                            </button>
                            {downloadedAgentInfo && (
                              <div style={{ padding: '14px', background: 'rgba(0, 255, 128, 0.08)', border: '1px solid #00ff80', borderRadius: '6px', fontSize: '12px' }}>
                                <div style={{ color: '#00ff80', fontWeight: 'bold', fontSize: '13px', marginBottom: '6px' }}>
                                  ✔ Agent is successfully downloaded.
                                </div>
                                <div style={{ color: '#fff', fontSize: '11px', marginBottom: '8px' }}>
                                  so now open terminal on agent install Path and run commands:
                                </div>
                                <div style={{ background: '#09090b', padding: '10px', borderRadius: '4px', border: '1px solid rgba(0, 255, 128, 0.3)', fontFamily: 'monospace', color: '#00ff80', display: 'flex', flexDirection: 'column', gap: '4px' }}>
                                  {downloadedAgentInfo.commands.map((cmd, idx) => (
                                    <div key={idx} style={{ userSelect: 'all' }}>{cmd}</div>
                                  ))}
                                </div>
                              </div>
                            )}
                          </div>
                        )}
                      </div>
                    </form>
                  </div>

                  {/* Right Column: Interactive Terminal Console */}
                  <div className="card hud-panel" style={{ display: 'flex', flexDirection: 'column', height: '600px' }}>
                    <div className="card-hd" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '10px' }}>
                      <div className="sec-title" style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <span className="dot" style={{ background: 'var(--accent-cyan)' }}></span>
                        Shell Session:
                        <select
                          className="finp fsel"
                          style={{ width: '160px', padding: '3px 8px', height: '28px', fontSize: '12px' }}
                          value={selectedAgentId || ''}
                          onChange={(e) => setSelectedAgentId(e.target.value || null)}
                        >
                          <option value="">-- SELECT TARGET --</option>
                          {agents.filter(a => a.status === 'online').map(a => (
                            <option key={a.id} value={a.id}>{a.hostname} ({a.ip_address})</option>
                          ))}
                        </select>
                      </div>
                      <div style={{ display: 'flex', gap: '6px' }}>
                        <button className="scan-btn" onClick={clearConsole} style={{ padding: '2px 8px', fontSize: '11px', height: '24px' }}>Clear Buffer</button>
                      </div>
                    </div>

                    {/* Monospace terminal logs */}
                    <div style={{
                      flex: 1,
                      background: '#09090b',
                      border: '1px solid var(--border-subtle)',
                      borderRadius: '4px',
                      padding: '12px',
                      fontFamily: "'JetBrains Mono', monospace",
                      fontSize: '12px',
                      overflowY: 'auto',
                      color: '#39ff14',
                      display: 'flex',
                      flexDirection: 'column',
                      gap: '8px'
                    }}>
                      {selectedAgentId ? (
                        <>
                          <div style={{ color: '#00F2FF', borderBottom: '1px solid rgba(0, 242, 255, 0.1)', paddingBottom: '6px', marginBottom: '6px' }}>
                            CONNECTED TO {agents.find(a => a.id === selectedAgentId)?.hostname.toUpperCase()} UPTIME {agents.find(a => a.id === selectedAgentId)?.uptime}
                          </div>
                          {(consoleHistory[selectedAgentId] || []).length > 0 ? (
                            (consoleHistory[selectedAgentId] || []).map((line, idx) => (
                              <div key={idx} style={{ wordBreak: 'break-all' }}>
                                {line.type === 'input' ? (
                                  <div style={{ color: '#fff' }}>
                                    <span style={{ color: '#00F2FF' }}>
                                      {(() => {
                                        const currentAgent = agents.find(a => a.id === selectedAgentId);
                                        const hostname = currentAgent ? currentAgent.hostname : 'REDEYE';
                                        const path = agentPaths[selectedAgentId] || (currentAgent?.platform === 'Windows' ? 'C:\\' : '/');
                                        return `[${hostname} ${path}]>`;
                                      })()}
                                    </span> {line.text}
                                  </div>
                                ) : line.type === 'error' ? (
                                  <div style={{ color: '#ff3b30' }}>
                                    [ERROR] {line.text}
                                  </div>
                                ) : (
                                  <pre style={{ margin: 0, whiteSpace: 'pre-wrap', fontFamily: 'inherit', color: '#a1a1aa' }}>
                                    {line.text}
                                  </pre>
                                )}
                              </div>
                            ))
                          ) : (
                            <div style={{ color: '#71717a', fontStyle: 'italic' }}>Session initialized. Type command or choose query below.</div>
                          )}
                          <div ref={consoleEndRef} />
                        </>
                      ) : (
                        <div style={{ color: '#71717a', height: '100%', display: 'flex', alignItems: 'center', justifyContent: 'center', textAlign: 'center', flexDirection: 'column', gap: '8px' }}>
                          <div>NO ACTIVE SESSIONS REGISTERED</div>
                          <div style={{ fontSize: '11px' }}>Select an online host from the dropdown to initialize a shell console interface.</div>
                        </div>
                      )}
                    </div>

                    {/* Command execution input prompt */}
                    <div style={{ display: 'flex', gap: '6px', marginTop: '10px', alignItems: 'center' }}>
                      {selectedAgentId && (
                        <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '11px', color: 'var(--accent-cyan)', whiteSpace: 'nowrap' }}>
                          {(() => {
                            const currentAgent = agents.find(a => a.id === selectedAgentId);
                            const hostname = currentAgent ? currentAgent.hostname : 'REDEYE';
                            const path = agentPaths[selectedAgentId] || (currentAgent?.platform === 'Windows' ? 'C:\\' : '/');
                            return `[${hostname} ${path}]>`;
                          })()}
                        </span>
                      )}
                      <input
                        type="text"
                        className="finp"
                        placeholder={selectedAgentId ? "Enter terminal shell command..." : "Select host session..."}
                        disabled={!selectedAgentId}
                        value={inputValue}
                        onChange={(e) => setInputValue(e.target.value)}
                        onKeyPress={handleKeyPress}
                        style={{ flex: 1, fontFamily: "'JetBrains Mono', monospace" }}
                      />
                      <button
                        className="scan-btn"
                        disabled={!selectedAgentId}
                        onClick={() => executeCommandText(inputValue)}
                        style={{ background: 'var(--accent-cyan)', color: '#000', borderColor: 'var(--accent-cyan)' }}
                      >
                        EXECUTE
                      </button>
                    </div>

                    {/* Command Dictionary quick access */}
                    {selectedAgentId && (
                      <div style={{ marginTop: '12px', borderTop: '1px solid var(--border-subtle)', paddingTop: '10px' }}>
                        <div style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '6px', fontWeight: 'bold' }}>Command Dictionary:</div>
                        <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
                          {['whoami', 'sysinfo', 'ps', 'netstat', 'arp -a', 'ipconfig'].map(cmd => (
                            <button
                              key={cmd}
                              className="scan-btn"
                              style={{ padding: '3px 8px', fontSize: '11px' }}
                              onClick={() => executeCommandText(cmd)}
                            >
                              {cmd}
                            </button>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              </div>
            )}


            {/* 9. SETTINGS VIEWPORT */}
            {/* 9. SETTINGS VIEWPORT */}
            {activeSidebarTab === 'settings' && (() => {
              const [testDbStatus, setTestDbStatus] = useState('IDLE'); // IDLE, TESTING, SUCCESS, ERROR

              const handleTestConnection = () => {
                setTestDbStatus('TESTING');
                logSql("SELECT VERSION(); -- Diagnostic db connectivity validation check");
                setTimeout(() => {
                  setTestDbStatus('SUCCESS');
                  alert("Database connection test: SUCCESS.\nResponse: PostgreSQL 15.2, compiled by Visual C++ build 1914, 64-bit");
                }, 1200);
              };

              return (
                <div className="page active" style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
                  <div className="page-title">Platform Hub Configuration</div>
                  <div className="page-sub">Global Enclave credentials, DB credentials, and core operator preferences</div>

                  <div className="two-col" style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px', alignItems: 'stretch' }}>
                    {/* Left Column: Organization & Enclave Security */}
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
                      <div className="card hud-panel">
                        <div className="card-hd">
                          <div className="sec-title">
                            <span className="dot"></span>Enclave Core Profile
                          </div>
                          <span className="badge bd-b">Global Config</span>
                        </div>

                        <div style={{ display: 'flex', flexDirection: 'column', gap: '14px', marginTop: '12px' }}>
                          <div className="fgrp" style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                            <label className="flbl" style={{ fontSize: '11px', color: '#fff', textTransform: 'uppercase', fontWeight: 'bold' }}>Organization Enclave Name</label>
                            <input className="finp" type="text" defaultValue="RedEye C2 Cyber Command" style={{ width: '100%' }} />
                          </div>

                          <div className="fgrp" style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                            <label className="flbl" style={{ fontSize: '11px', color: '#fff', textTransform: 'uppercase', fontWeight: 'bold' }}>Enclave Network ID</label>
                            <input className="finp" type="text" defaultValue="ENC-RE-9481-X-NORTH" style={{ width: '100%', fontFamily: 'var(--font-mono)' }} />
                          </div>

                          <div className="fgrp" style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                            <label className="flbl" style={{ fontSize: '11px', color: '#fff', textTransform: 'uppercase', fontWeight: 'bold' }}>Alert Dispatch Webhook</label>
                            <input className="finp" type="text" defaultValue="https://discord.com/api/webhooks/948291039841/A_x9Z" style={{ width: '100%' }} />
                          </div>

                          <div className="fgrp" style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                            <label className="flbl" style={{ fontSize: '11px', color: '#fff', textTransform: 'uppercase', fontWeight: 'bold' }}>Operator Signature Algorithm</label>
                            <select className="finp fsel" style={{ width: '100%' }}>
                              <option>RSA-4096-SHA256 (Enforced PKI)</option>
                              <option>ECDSA-P384-SHA384 (Fast ECC)</option>
                              <option>Ed25519 (Quantum-Resistant Draft)</option>
                            </select>
                          </div>

                          <button className="scan-btn" style={{ background: 'var(--accent-cyan)', color: '#000', borderColor: 'var(--accent-cyan)', fontWeight: 'bold', marginTop: '8px' }} onClick={() => alert('Enclave Core settings updated successfully!')}>
                            COMMIT CONFIG CHANGES
                          </button>
                        </div>
                      </div>

                      <div className="card hud-panel">
                        <div className="card-hd">
                          <div className="sec-title">
                            <span className="dot"></span>Session & Web Tokens
                          </div>
                          <span className="badge bd-r">Sec Policy</span>
                        </div>

                        <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', marginTop: '12px' }}>
                          <div style={{ display: 'flex', gap: '12px' }}>
                            <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: '4px' }}>
                              <label style={{ fontSize: '10px', textTransform: 'uppercase', color: '#a1a1aa' }}>Inactivity Timeout</label>
                              <select className="finp fsel" style={{ width: '100%' }}>
                                <option>30 minutes</option>
                                <option>1 hour</option>
                                <option>8 hours</option>
                              </select>
                            </div>
                            <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: '4px' }}>
                              <label style={{ fontSize: '10px', textTransform: 'uppercase', color: '#a1a1aa' }}>JWT Expiration</label>
                              <select className="finp fsel" style={{ width: '100%' }}>
                                <option>24 hours</option>
                                <option>7 days</option>
                                <option>30 days</option>
                              </select>
                            </div>
                          </div>

                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', background: 'rgba(255,255,255,0.02)', padding: '10px', borderRadius: '4px', border: '1px solid var(--border-subtle)' }}>
                            <div style={{ fontSize: '12px' }}>Two-Factor Auth Enforcement</div>
                            <span className="badge bd-g" style={{ cursor: 'pointer' }}>ENABLED</span>
                          </div>
                        </div>
                      </div>
                    </div>

                    {/* Right Column: Database Credentials & Connection Tester */}
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
                      <div className="card hud-panel" style={{ height: '100%' }}>
                        <div className="card-hd">
                          <div className="sec-title">
                            <span className="dot" style={{ background: '#2ecc71' }}></span>SQL Server Credentials
                          </div>
                          <span className="badge bd-g" style={{ background: 'rgba(46,204,113,0.15)', color: '#2ecc71', borderColor: '#2ecc71' }}>ONLINE</span>
                        </div>

                        <div style={{ display: 'flex', flexDirection: 'column', gap: '14px', marginTop: '12px' }}>
                          <div style={{ display: 'flex', gap: '10px' }}>
                            <div style={{ flex: 2, display: 'flex', flexDirection: 'column', gap: '4px' }}>
                              <label style={{ fontSize: '11px', textTransform: 'uppercase', color: '#fff', fontWeight: 'bold' }}>Server Host / IP</label>
                              <input className="finp" type="text" defaultValue="127.0.0.1" style={{ width: '100%', fontFamily: 'var(--font-mono)' }} />
                            </div>
                            <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: '4px' }}>
                              <label style={{ fontSize: '11px', textTransform: 'uppercase', color: '#fff', fontWeight: 'bold' }}>Port</label>
                              <input className="finp" type="text" defaultValue="5432" style={{ width: '100%', fontFamily: 'var(--font-mono)' }} />
                            </div>
                          </div>

                          <div className="fgrp" style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                            <label className="flbl" style={{ fontSize: '11px', color: '#fff', textTransform: 'uppercase', fontWeight: 'bold' }}>Database Name</label>
                            <input className="finp" type="text" defaultValue="redeye_prod_core" style={{ width: '100%', fontFamily: 'var(--font-mono)' }} />
                          </div>

                          <div className="fgrp" style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                            <label className="flbl" style={{ fontSize: '11px', color: '#fff', textTransform: 'uppercase', fontWeight: 'bold' }}>User Login ID</label>
                            <input className="finp" type="text" defaultValue="redeye_enclave_admin" style={{ width: '100%', fontFamily: 'var(--font-mono)' }} />
                          </div>

                          <div className="fgrp" style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                            <label className="flbl" style={{ fontSize: '11px', color: '#fff', textTransform: 'uppercase', fontWeight: 'bold' }}>Security Password Key</label>
                            <input className="finp" type="password" value="••••••••••••••••••••" readOnly style={{ width: '100%', fontFamily: 'var(--font-mono)', background: 'rgba(255,255,255,0.02)', border: '1px solid var(--border-subtle)', color: 'var(--text-muted)' }} />
                          </div>

                          <div style={{ display: 'flex', gap: '10px', marginTop: '8px' }}>
                            <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: '4px' }}>
                              <label style={{ fontSize: '10px', textTransform: 'uppercase', color: '#a1a1aa' }}>Max Conn Pool</label>
                              <input className="finp" type="number" defaultValue={32} style={{ width: '100%' }} />
                            </div>
                            <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: '4px' }}>
                              <label style={{ fontSize: '10px', textTransform: 'uppercase', color: '#a1a1aa' }}>Pool Timeout</label>
                              <select className="finp fsel" style={{ width: '100%' }}>
                                <option>5000 ms</option>
                                <option>15000 ms</option>
                                <option>30000 ms</option>
                              </select>
                            </div>
                          </div>

                          <div style={{ display: 'flex', gap: '10px', marginTop: '16px' }}>
                            <button className="scan-btn" style={{ flex: 1 }} type="button" onClick={handleTestConnection}>
                              {testDbStatus === 'TESTING' ? 'TESTING DB LINK...' : 'TEST DB LINK'}
                            </button>
                            <button className="scan-btn" style={{ flex: 1, background: '#2ecc71', color: '#000', borderColor: '#2ecc71', fontWeight: 'bold' }} type="button" onClick={() => alert('Database credentials updated!')}>
                              SAVE DB CONFIG
                            </button>
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              );
            })()}

            {inspectedApp && (
              <div style={{
                position: 'fixed',
                top: 0,
                left: 0,
                right: 0,
                bottom: 0,
                background: 'rgba(0, 0, 0, 0.85)',
                backdropFilter: 'blur(8px)',
                display: 'flex',
                justifyContent: 'center',
                alignItems: 'center',
                zIndex: 9999,
                padding: '20px'
              }}>
                <div style={{
                  background: '#0d0f17',
                  border: '1px solid rgba(0, 240, 255, 0.25)',
                  borderRadius: '12px',
                  width: '850px',
                  maxWidth: '100%',
                  maxHeight: '90vh',
                  overflowY: 'auto',
                  boxShadow: '0 20px 40px rgba(0,0,0,0.6), 0 0 25px rgba(0, 240, 255, 0.15)',
                  display: 'flex',
                  flexDirection: 'column'
                }}>
                  {/* Modal Header */}
                  <div style={{
                    padding: '18px 24px',
                    borderBottom: '1px solid rgba(255,255,255,0.08)',
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    background: 'rgba(255, 255, 255, 0.01)'
                  }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                      <ShieldAlert size={22} style={{ color: inspectedApp.threat_score >= 61 ? '#ff3b30' : '#00f0ff' }} />
                      <div>
                        <h3 style={{ margin: 0, fontSize: '18px', fontWeight: '800', color: '#fff' }}>RedEye Report</h3>
                        <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Security Analysis & Threat Diagnostics</span>
                      </div>
                    </div>
                    <button
                      onClick={() => setInspectedApp(null)}
                      style={{
                        background: 'transparent',
                        border: 'none',
                        color: 'var(--text-muted)',
                        cursor: 'pointer',
                        fontSize: '18px',
                        fontWeight: 'bold'
                      }}
                    >
                      ✕
                    </button>
                  </div>

                  {/* Modal Body */}
                  <div style={{ padding: '24px', display: 'flex', flexDirection: 'column', gap: '20px' }}>

                    {/* Threat Score & Summary Card */}
                    <div style={{
                      display: 'grid',
                      gridTemplateColumns: '1.2fr 2fr',
                      gap: '20px',
                      background: 'rgba(255, 255, 255, 0.02)',
                      borderRadius: '8px',
                      padding: '20px',
                      border: '1px solid rgba(255,255,255,0.05)'
                    }}>
                      <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', borderRight: '1px solid rgba(255,255,255,0.08)', paddingRight: '20px' }}>
                        <div style={{ fontSize: '12px', textTransform: 'uppercase', color: 'var(--text-muted)', fontWeight: 'bold', marginBottom: '8px' }}>Threat Score</div>
                        <div style={{
                          fontSize: '48px',
                          fontWeight: '900',
                          color: inspectedApp.threat_score >= 81 ? '#ff3b30' : inspectedApp.threat_score >= 61 ? '#ff9500' : inspectedApp.threat_score >= 41 ? '#ffcc00' : inspectedApp.threat_score >= 21 ? '#007aff' : '#34c759',
                          lineHeight: '1'
                        }}>{inspectedApp.threat_score || 0}</div>
                        <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '2px' }}>out of 100</div>
                        <div style={{
                          marginTop: '12px',
                          padding: '4px 12px',
                          borderRadius: '20px',
                          fontSize: '11px',
                          fontWeight: 'bold',
                          textTransform: 'uppercase',
                          background: inspectedApp.threat_score >= 81 ? 'rgba(255, 59, 48, 0.15)' : inspectedApp.threat_score >= 61 ? 'rgba(255, 149, 0, 0.15)' : inspectedApp.threat_score >= 41 ? 'rgba(255, 204, 0, 0.15)' : inspectedApp.threat_score >= 21 ? 'rgba(0, 122, 255, 0.15)' : 'rgba(52, 199, 89, 0.15)',
                          color: inspectedApp.threat_score >= 81 ? '#ff3b30' : inspectedApp.threat_score >= 61 ? '#ff9500' : inspectedApp.threat_score >= 41 ? '#ffcc00' : inspectedApp.threat_score >= 21 ? '#007aff' : '#34c759'
                        }}>
                          {inspectedApp.threat_score >= 81 ? 'Critical' : inspectedApp.threat_score >= 61 ? 'High' : inspectedApp.threat_score >= 41 ? 'Medium' : inspectedApp.threat_score >= 21 ? 'Low' : 'Safe'}
                        </div>
                      </div>

                      <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', justifyContent: 'center' }}>
                        <div>
                          <span style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 'bold' }}>Application Name</span>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap', marginTop: '2px' }}>
                            <h2 style={{ margin: 0, fontSize: '20px', color: '#fff', fontWeight: '800' }}>{inspectedApp.app_name}</h2>
                            {((inspectedApp.threat_category && inspectedApp.threat_category.includes('Confirmed Malware')) || inspectedApp.mb_listed || (() => {
                              if (!inspectedApp.vt_detection_rate || inspectedApp.vt_detection_rate === '0/0') return false;
                              const parts = inspectedApp.vt_detection_rate.split('/');
                              return parseInt(parts[0], 10) >= 1;
                            })()) && (
                                <span className="badge bd-r" style={{ fontSize: '10px', fontWeight: 'bold', padding: '2px 8px', borderRadius: '3px' }}>
                                  Malware Confirmed
                                </span>
                              )}
                          </div>
                        </div>
                        <div>
                          <span style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 'bold' }}>Package Name</span>
                          <div style={{ fontFamily: 'monospace', color: '#00f0ff', fontSize: '12px', wordBreak: 'break-all' }}>{inspectedApp.package_name}</div>
                        </div>
                        <div style={{ display: 'flex', gap: '20px', marginTop: '4px' }}>
                          <div>
                            <span style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Version</span>
                            <div style={{ fontSize: '12px', color: '#fff' }}>{inspectedApp.version_name || 'N/A'} ({inspectedApp.version_code || 0})</div>
                          </div>
                          <div>
                            <span style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Target SDK</span>
                            <div style={{ fontSize: '12px', color: '#fff' }}>API {inspectedApp.target_sdk || 'N/A'}</div>
                          </div>
                        </div>
                      </div>
                    </div>

                    {/* Threat Classification & Mitre Mapping */}
                    <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 1fr', gap: '20px' }}>
                      <div style={{ background: 'rgba(0,0,0,0.2)', padding: '16px', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.04)' }}>
                        <div style={{ fontSize: '12px', textTransform: 'uppercase', color: 'var(--text-muted)', fontWeight: 'bold', borderBottom: '1px solid rgba(255,255,255,0.08)', paddingBottom: '6px', marginBottom: '10px' }}>Threat Classification</div>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                          <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '12px' }}>
                            <span style={{ color: 'var(--text-muted)' }}>Category</span>
                            <span style={{ color: '#fff', fontWeight: '600' }}>{inspectedApp.threat_category || 'Safe / Unclassified'}</span>
                          </div>
                          <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '12px' }}>
                            <span style={{ color: 'var(--text-muted)' }}>Installer Reputation</span>
                            <span style={{
                              color: inspectedApp.installer_reputation === 'Trusted Store' ? '#34c759' : inspectedApp.installer_reputation === 'Enterprise' ? '#007aff' : '#ff9500',
                              fontWeight: '600'
                            }}>{inspectedApp.installer_reputation || 'Unknown'}</span>
                          </div>
                          <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '12px' }}>
                            <span style={{ color: 'var(--text-muted)' }}>Certificate Reputation</span>
                            <span style={{
                              color: inspectedApp.certificate_reputation === 'trusted' ? '#34c759' : inspectedApp.certificate_reputation === 'malicious' ? '#ff3b30' : '#ff9500',
                              fontWeight: '600'
                            }}>{inspectedApp.certificate_reputation || 'unknown'}</span>
                          </div>
                        </div>
                      </div>

                      <div style={{ background: 'rgba(0,0,0,0.2)', padding: '16px', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.04)' }}>
                        <div style={{ fontSize: '12px', textTransform: 'uppercase', color: 'var(--text-muted)', fontWeight: 'bold', borderBottom: '1px solid rgba(255,255,255,0.08)', paddingBottom: '6px', marginBottom: '10px' }}>MITRE ATT&CK Tactics</div>
                        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
                          {inspectedApp.mitre_tactics && inspectedApp.mitre_tactics.length > 0 ? (
                            inspectedApp.mitre_tactics.map((t, i) => (
                              <span key={i} className="badge bd-r" style={{ background: 'rgba(255, 59, 48, 0.12)', color: '#ff3b30', borderColor: 'rgba(255, 59, 48, 0.25)', fontSize: '10px' }}>{t}</span>
                            ))
                          ) : (
                            <span style={{ fontSize: '12px', color: 'var(--text-muted)', fontStyle: 'italic' }}>No adversarial tactics mapped.</span>
                          )}
                        </div>
                      </div>
                    </div>

                    {/* Threat Intel Indicators */}
                    <div style={{
                      background: 'rgba(0,0,0,0.2)',
                      padding: '16px',
                      borderRadius: '8px',
                      border: '1px solid rgba(255,255,255,0.04)'
                    }}>
                      <div style={{ fontSize: '12px', textTransform: 'uppercase', color: 'var(--text-muted)', fontWeight: 'bold', borderBottom: '1px solid rgba(255,255,255,0.08)', paddingBottom: '6px', marginBottom: '12px' }}>Threat Intelligence Signals</div>
                      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                          <div style={{
                            width: '8px',
                            height: '8px',
                            borderRadius: '50%',
                            background: inspectedApp.mb_listed ? '#ff3b30' : '#34c759'
                          }}></div>
                          <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>MalwareBazaar Registry:</span>
                          <span style={{ fontSize: '12px', fontWeight: 'bold', color: inspectedApp.mb_listed ? '#ff3b30' : '#34c759' }}>
                            {inspectedApp.mb_listed ? 'LISTED (MALICIOUS)' : 'NOT FOUND'}
                          </span>
                        </div>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                          <div style={{
                            width: '8px',
                            height: '8px',
                            borderRadius: '50%',
                            background: (inspectedApp.vt_detection_rate && inspectedApp.vt_detection_rate !== '0/0' && !inspectedApp.vt_detection_rate.startsWith('0/')) ? '#ff3b30' : '#34c759'
                          }}></div>
                          <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>VirusTotal Detection Rate:</span>
                          <span style={{ fontSize: '12px', fontWeight: 'bold', color: (inspectedApp.vt_detection_rate && inspectedApp.vt_detection_rate !== '0/0' && !inspectedApp.vt_detection_rate.startsWith('0/')) ? '#ff3b30' : '#34c759' }}>
                            {inspectedApp.vt_detection_rate || '0/0 (Clean / Unknown)'}
                          </span>
                        </div>
                      </div>
                    </div>

                    {/* Findings Diagnostics */}
                    <div style={{
                      background: 'rgba(0,0,0,0.2)',
                      padding: '16px',
                      borderRadius: '8px',
                      border: '1px solid rgba(255,255,255,0.04)'
                    }}>
                      <div style={{ fontSize: '12px', textTransform: 'uppercase', color: 'var(--text-muted)', fontWeight: 'bold', borderBottom: '1px solid rgba(255,255,255,0.08)', paddingBottom: '6px', marginBottom: '12px' }}>Security Diagnostics Checklist</div>
                      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px', fontSize: '12px' }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 8px', borderRadius: '4px', background: inspectedApp.has_accessibility ? 'rgba(255,255,255,0.02)' : '' }}>
                          <span style={{ color: 'var(--text-muted)' }}>Accessibility Service Enabled</span>
                          <span style={{ color: inspectedApp.has_accessibility ? '#ff9500' : 'var(--text-muted)' }}>{inspectedApp.has_accessibility ? '✓ Yes' : '✕ No'}</span>
                        </div>
                        <div style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 8px', borderRadius: '4px', background: inspectedApp.has_overlay ? 'rgba(255,255,255,0.02)' : '' }}>
                          <span style={{ color: 'var(--text-muted)' }}>Overlay Permission Granted</span>
                          <span style={{ color: inspectedApp.has_overlay ? '#ff9500' : 'var(--text-muted)' }}>{inspectedApp.has_overlay ? '✓ Yes' : '✕ No'}</span>
                        </div>
                        <div style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 8px', borderRadius: '4px', background: inspectedApp.has_boot_receiver ? 'rgba(255,255,255,0.02)' : '' }}>
                          <span style={{ color: 'var(--text-muted)' }}>Starts on Device Boot</span>
                          <span style={{ color: inspectedApp.has_boot_receiver ? '#ff9500' : 'var(--text-muted)' }}>{inspectedApp.has_boot_receiver ? '✓ Yes' : '✕ No'}</span>
                        </div>
                        <div style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 8px', borderRadius: '4px', background: inspectedApp.has_foreground_service ? 'rgba(255,255,255,0.02)' : '' }}>
                          <span style={{ color: 'var(--text-muted)' }}>Runs Foreground Service</span>
                          <span style={{ color: inspectedApp.has_foreground_service ? '#ff9500' : 'var(--text-muted)' }}>{inspectedApp.has_foreground_service ? '✓ Yes' : '✕ No'}</span>
                        </div>
                        <div style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 8px', borderRadius: '4px', background: inspectedApp.has_battery_exemption ? 'rgba(255,255,255,0.02)' : '' }}>
                          <span style={{ color: 'var(--text-muted)' }}>Battery Optimization Ignored</span>
                          <span style={{ color: inspectedApp.has_battery_exemption ? '#ff9500' : 'var(--text-muted)' }}>{inspectedApp.has_battery_exemption ? '✓ Yes' : '✕ No'}</span>
                        </div>
                        <div style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 8px', borderRadius: '4px', background: inspectedApp.device_admin_active ? 'rgba(255,255,255,0.02)' : '' }}>
                          <span style={{ color: 'var(--text-muted)' }}>Device Administrator Privileges</span>
                          <span style={{ color: inspectedApp.device_admin_active ? '#ff3b30' : 'var(--text-muted)', fontWeight: inspectedApp.device_admin_active ? 'bold' : '' }}>{inspectedApp.device_admin_active ? '✓ Yes' : '✕ No'}</span>
                        </div>
                        <div style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 8px', borderRadius: '4px', background: !inspectedApp.has_launcher ? 'rgba(255,255,255,0.02)' : '' }}>
                          <span style={{ color: 'var(--text-muted)' }}>Hidden Launcher Icon</span>
                          <span style={{ color: !inspectedApp.has_launcher ? '#ff9500' : 'var(--text-muted)' }}>{!inspectedApp.has_launcher ? '✓ Yes' : '✕ No'}</span>
                        </div>
                        <div style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 8px', borderRadius: '4px', background: inspectedApp.certificate_reputation === 'unknown' ? 'rgba(255,255,255,0.02)' : '' }}>
                          <span style={{ color: 'var(--text-muted)' }}>Unknown Certificate Signer</span>
                          <span style={{ color: inspectedApp.certificate_reputation === 'unknown' ? '#ff9500' : 'var(--text-muted)' }}>{inspectedApp.certificate_reputation === 'unknown' ? '✓ Yes' : '✕ No'}</span>
                        </div>
                      </div>
                    </div>

                    {/* Hashing & Credentials */}
                    <div style={{
                      background: 'rgba(0,0,0,0.2)',
                      padding: '16px',
                      borderRadius: '8px',
                      border: '1px solid rgba(255,255,255,0.04)',
                      fontSize: '12px'
                    }}>
                      <div style={{ fontSize: '12px', textTransform: 'uppercase', color: 'var(--text-muted)', fontWeight: 'bold', borderBottom: '1px solid rgba(255,255,255,0.08)', paddingBottom: '6px', marginBottom: '10px' }}>Binary Auditing Details</div>
                      <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                        <div>
                          <div style={{ color: 'var(--text-muted)', marginBottom: '2px' }}>APK SHA-256 Checksum</div>
                          <div style={{ fontFamily: 'monospace', color: '#fff', background: 'rgba(0,0,0,0.3)', padding: '6px 10px', borderRadius: '4px', border: '1px solid rgba(255,255,255,0.05)', overflowX: 'auto', whiteSpace: 'nowrap' }}>
                            {inspectedApp.apk_sha256 || 'Unknown'}
                          </div>
                        </div>
                        <div>
                          <div style={{ color: 'var(--text-muted)', marginBottom: '2px' }}>Certificate Fingerprint</div>
                          <div style={{ fontFamily: 'monospace', color: '#fff', background: 'rgba(0,0,0,0.3)', padding: '6px 10px', borderRadius: '4px', border: '1px solid rgba(255,255,255,0.05)', overflowX: 'auto', whiteSpace: 'nowrap' }}>
                            {inspectedApp.certificate || 'Unknown'}
                          </div>
                        </div>
                      </div>
                    </div>

                    {/* Permissions Split */}
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px' }}>
                      <div style={{
                        background: 'rgba(0,0,0,0.2)',
                        padding: '16px',
                        borderRadius: '8px',
                        border: '1px solid rgba(255,255,255,0.04)',
                        display: 'flex',
                        flexDirection: 'column',
                        maxHeight: '220px'
                      }}>
                        <div style={{ fontSize: '12px', textTransform: 'uppercase', color: '#34c759', fontWeight: 'bold', borderBottom: '1px solid rgba(52, 199, 89, 0.15)', paddingBottom: '6px', marginBottom: '10px' }}>
                          Granted Permissions ({inspectedApp.granted_permissions ? inspectedApp.granted_permissions.length : 0})
                        </div>
                        <div style={{ overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '6px', flex: 1 }}>
                          {inspectedApp.granted_permissions && inspectedApp.granted_permissions.length > 0 ? (
                            inspectedApp.granted_permissions.map((p, i) => (
                              <div key={i} style={{ fontFamily: 'monospace', fontSize: '11px', color: '#88e088', background: 'rgba(52, 199, 89, 0.05)', padding: '4px 8px', borderRadius: '4px' }}>
                                ✓ {p.replace('android.permission.', '')}
                              </div>
                            ))
                          ) : (
                            <span style={{ fontSize: '12px', color: 'var(--text-muted)', fontStyle: 'italic' }}>No granted permissions.</span>
                          )}
                        </div>
                      </div>

                      <div style={{
                        background: 'rgba(0,0,0,0.2)',
                        padding: '16px',
                        borderRadius: '8px',
                        border: '1px solid rgba(255,255,255,0.04)',
                        display: 'flex',
                        flexDirection: 'column',
                        maxHeight: '220px'
                      }}>
                        <div style={{ fontSize: '12px', textTransform: 'uppercase', color: '#ff9500', fontWeight: 'bold', borderBottom: '1px solid rgba(255, 149, 0, 0.15)', paddingBottom: '6px', marginBottom: '10px' }}>
                          Pending / Requested Permissions ({inspectedApp.pending_permissions ? inspectedApp.pending_permissions.length : 0})
                        </div>
                        <div style={{ overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '6px', flex: 1 }}>
                          {inspectedApp.pending_permissions && inspectedApp.pending_permissions.length > 0 ? (
                            inspectedApp.pending_permissions.map((p, i) => (
                              <div key={i} style={{ fontFamily: 'monospace', fontSize: '11px', color: '#ffcc88', background: 'rgba(255, 149, 0, 0.05)', padding: '4px 8px', borderRadius: '4px' }}>
                                ⚠ {p.replace('android.permission.', '')}
                              </div>
                            ))
                          ) : (
                            <span style={{ fontSize: '12px', color: 'var(--text-muted)', fontStyle: 'italic' }}>No pending permissions.</span>
                          )}
                        </div>
                      </div>
                    </div>

                  </div>

                  {/* Modal Footer */}
                  <div style={{
                    padding: '16px 24px',
                    borderTop: '1px solid rgba(255,255,255,0.08)',
                    display: 'flex',
                    justifyContent: 'flex-end',
                    background: 'rgba(255,255,255,0.01)',
                    borderRadius: '0 0 12px 12px'
                  }}>
                    <button
                      onClick={() => setInspectedApp(null)}
                      style={{
                        background: 'rgba(255,255,255,0.08)',
                        border: '1px solid rgba(255,255,255,0.15)',
                        borderRadius: '4px',
                        padding: '8px 20px',
                        color: '#fff',
                        fontSize: '13px',
                        cursor: 'pointer',
                        fontWeight: 'bold',
                        transition: 'background 0.2s'
                      }}
                      onMouseEnter={(e) => e.target.style.background = 'rgba(255,255,255,0.15)'}
                      onMouseLeave={(e) => e.target.style.background = 'rgba(255,255,255,0.08)'}
                    >
                      Close Report
                    </button>
                  </div>
                </div>
              </div>
            )}
          </main>
        </div>
      )}
    </div>
  );
}
