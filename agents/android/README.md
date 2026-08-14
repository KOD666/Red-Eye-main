# RedEye Android Telemetry Agent (Expo Managed)

A high-performance remote system diagnostics and telemetry reporting agent for Android devices built using **React Native** and **Expo**. Exposes deep device hardware metrics and local network interface details directly to the RedEye C2 registry.

---

## 📱 Features & Telemetry Collected

### 1. Device Profile Metrics
Exposed by `expo-device` package:
* **Device Name**: Device name (e.g. Android Emulator, Vraj's Phone).
* **Manufacturer**: Hardware brand (e.g. Google, Samsung).
* **Model Code**: Device model (e.g. SDK gphone64_arm64).
* **Android OS Version**: Release version (e.g. Android 13).
* **SDK Version**: Android API version level (e.g. API 33).
* **Secure Device ID**: Hardware-bound unique `osBuildId`.
* **Screen Resolution**: Screen bounds dimensions.
* **System Language**: Active Locale code (e.g. `en_US`).
* **System Uptime**: Time elapsed since boot (in seconds).
* **TimeZone Region**: System time zone ID (e.g. `GMT+05:30`).

### 2. Network Interface Diagnostics
Exposed by `expo-network` package:
* **Connection Type**: Active connectivity mode (`WIFI`, `CELLULAR`, `NONE`).
* **Internal IP**: Local IPv4 address.
* **Public/Publish IP**: Dynamic public IP (resolved via geolocation API).
* **MAC Address**: Dynamic sandbox fallback.
* **Wifi SSID Name**: Broadcast SSID of the connected router.
* **Wifi BSSID**: Hardware address of the connected Access Point.
* **WiFi RSSI Strength**: Signal strength (in dBm).
* **DNS Servers**: Configured Primary/Secondary DNS hosts.
* **Router Gateway**: Local subnet route gateway address.
* **VPN Tunnel Status**: Actively checks for encrypted VPN transport interfaces.

---

## 🛠️ Code Architecture

* [App.js](file:///home/kali/college/AntiGravity/RedEye/agents/android/App.js): Core user interface with a cyberpunk-style C2 Dashboard, enrollment controller, and telemetry heartbeat ping/command polling loops.
* [app.json](file:///home/kali/college/AntiGravity/RedEye/agents/android/app.json): Expo metadata configuration.
* [package.json](file:///home/kali/college/AntiGravity/RedEye/agents/android/package.json): Defines Expo project dependencies.

---

## 🚀 Running / Building the Agent

### Prerequisites
* **Node.js** (v16+)
* **Expo Go** application installed on your Android device/emulator (Genymotion).

### Installation & Run Steps
1. Navigate to the android agent folder:
   ```bash
   cd agents/android
   ```
2. Install dependencies:
   ```bash
   npm install
   ```
3. Start the Expo server:
   ```bash
   npx expo start -c
   ```
4. Press `a` in the Expo terminal output or scan the QR code to launch the application immediately inside your Genymotion emulator or physical Android phone!
