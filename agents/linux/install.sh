#!/bin/bash
set -e

echo "[*] Installing RedEye Agent..."

mkdir -p /opt/redeye
mkdir -p /etc/redeye
mkdir -p /var/lib/redeye
mkdir -p /var/log/redeye

cp redeye-agent /opt/redeye/
chmod +x /opt/redeye/redeye-agent

cat >/etc/systemd/system/redeye.service <<EOF
[Unit]
Description=RedEye Linux Agent
After=network-online.target

[Service]
Type=simple
ExecStart=/opt/redeye/redeye-agent
WorkingDirectory=/opt/redeye
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable redeye
systemctl start redeye

echo ""
echo "[+] RedEye Agent installed successfully."
