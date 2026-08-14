# 🚀 RedEye — Complete Deployment & Hosting Guide

> **Goal**: Host the RedEye C2/EDR platform entirely for **FREE** with:
> - **Frontend** → `https://redeye.desaivraj.site`
> - **Backend API** → `https://api.desaivraj.site`
> - **Desktop .exe** → Compiled Electron app pointing to `api.desaivraj.site`
> - **Database** → Free cloud PostgreSQL

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Free Services You'll Need](#2-free-services-youll-need)
3. [Step 1 — Database Setup (Free PostgreSQL)](#3-step-1--database-setup-free-postgresql)
4. [Step 2 — Backend Deployment (FastAPI on Render)](#4-step-2--backend-deployment-fastapi-on-render)
5. [Step 3 — Frontend Deployment (React on Cloudflare Pages)](#5-step-3--frontend-deployment-react-on-cloudflare-pages)
6. [Step 4 — Custom Domain Configuration](#6-step-4--custom-domain-configuration)
7. [Step 5 — Compile Desktop .exe (Electron)](#7-step-5--compile-desktop-exe-electron)
8. [Step 6 — Agent Configuration for Production](#8-step-6--agent-configuration-for-production)
9. [Code Changes Required Before Deployment](#9-code-changes-required-before-deployment)
10. [Environment Variables Reference](#10-environment-variables-reference)
11. [Troubleshooting & FAQ](#11-troubleshooting--faq)
12. [Quick Reference Cheatsheet](#12-quick-reference-cheatsheet)

---

## 1. Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                        YOUR DOMAIN: desaivraj.site                  │
│                                                                     │
│    ┌──────────────────────┐       ┌──────────────────────┐         │
│    │  redeye.desaivraj.site│       │  api.desaivraj.site  │         │
│    │  (Cloudflare Pages)   │──────▶│  (Render Free Tier)  │         │
│    │  React Frontend       │ API   │  FastAPI Backend      │         │
│    └──────────────────────┘       └──────────┬───────────┘         │
│                                               │                     │
│    ┌──────────────────────┐       ┌──────────▼───────────┐         │
│    │  Red-Eye.exe          │       │  Neon PostgreSQL     │         │
│    │  (Electron Desktop)   │──────▶│  (Free Cloud DB)     │         │
│    │  Compiled .exe         │ API   │  5 GB Free Storage   │         │
│    └──────────────────────┘       └──────────────────────┘         │
│                                                                     │
│    ┌────────────────────────────────────────────────┐               │
│    │  Agent Implants (Windows/Linux/Android)         │               │
│    │  All connect to: https://api.desaivraj.site     │               │
│    └────────────────────────────────────────────────┘               │
└─────────────────────────────────────────────────────────────────────┘
```

### Current Tech Stack

| Component | Technology | Current Config |
|---|---|---|
| Backend | Python FastAPI + Uvicorn | `backend/main.py` (3840 lines) |
| Frontend | React 18 + Vite 5 + Electron 29 | `frontend/src/App.jsx` |
| Database | PostgreSQL 18+ (SQLite fallback) | `backend/database.py` |
| ORM | SQLAlchemy 2.0 | `backend/models.py` |
| Auth | JWT tokens | `backend/auth.py` |
| Agents | Python (Win/Linux), React Native (Android) | `agents/` directory |

---

## 2. Free Services You'll Need

Create accounts on these platforms (**ALL FREE**):

| Service | Purpose | Free Tier Limits | URL |
|---|---|---|---|
| **Neon** | PostgreSQL Database | 0.5 GB storage, 1 project, auto-suspend after 5 min idle | [neon.tech](https://neon.tech) |
| **Render** | Backend API Hosting | 750 hrs/month, auto-sleep after 15 min idle, 512 MB RAM | [render.com](https://render.com) |
| **Cloudflare Pages** | Frontend Hosting | Unlimited bandwidth, 500 builds/month, instant global CDN | [pages.cloudflare.com](https://pages.cloudflare.com) |
| **GitHub** | Git Repo (for CI/CD) | Unlimited public repos | [github.com](https://github.com) |
| **Cloudflare** | DNS Management | Free DNS, free SSL | [cloudflare.com](https://cloudflare.com) |

### Alternative Free Options

| Alternative | For | Free Tier |
|---|---|---|
| **Supabase** (alt for Neon) | PostgreSQL DB | 500 MB storage, 2 projects |
| **Railway** (alt for Render) | Backend API | $5 free credit/month (~500 hrs) |
| **Vercel** (alt for Cloudflare Pages) | Frontend | 100 GB bandwidth/month |
| **Koyeb** (alt for Render) | Backend API | 1 nano instance free |

---

## 3. Step 1 — Database Setup (Free PostgreSQL)

### Option A: Neon (Recommended — Best Free PostgreSQL)

#### 3.1 Create a Neon Account
1. Go to [https://neon.tech](https://neon.tech)
2. Click **"Sign Up"** → sign in with GitHub
3. You get **1 free project** with **0.5 GB storage**

#### 3.2 Create a New Project
1. Click **"New Project"**
2. **Project Name**: `redeye-db`
3. **Region**: Choose closest to your users (e.g., `Asia Pacific (Singapore)` for India)
4. **PostgreSQL Version**: Select **16** or latest available
5. Click **"Create Project"**

#### 3.3 Get Your Connection String
After creation, Neon shows you the connection string. It looks like:

```
postgresql://neondb_owner:AbCdEf123456@ep-cool-name-123456.ap-southeast-1.aws.neon.tech/neondb?sslmode=require
```

> **⚠️ IMPORTANT**: Copy this connection string and save it securely. You'll need it for the backend `.env` file.

#### 3.4 Initialize the Database Schema

**Option 1: Via Neon SQL Editor (Easiest)**
1. In the Neon dashboard, click **"SQL Editor"** in the left sidebar
2. Copy the entire contents of your `database/schema_v2.sql` file
3. Paste it into the SQL editor
4. Click **"Run"**

**Option 2: Via psql CLI**
```bash
# Install psql if not already installed
# On Ubuntu/Debian:
sudo apt install postgresql-client

# Connect and run schema
psql "postgresql://neondb_owner:YOUR_PASSWORD@ep-cool-name-123456.ap-southeast-1.aws.neon.tech/neondb?sslmode=require" -f database/schema_v2.sql
```

**Option 3: Let FastAPI Auto-Create Tables**
- Just set the `DATABASE_URL` in your `.env` and start the backend
- SQLAlchemy's `models.Base.metadata.create_all(bind=engine)` in `backend/main.py` (line 88) auto-creates all tables

#### 3.5 Verify Database Connection
```bash
# Test connection using psql
psql "postgresql://neondb_owner:YOUR_PASSWORD@ep-cool-name-123456.ap-southeast-1.aws.neon.tech/neondb?sslmode=require"

# Once connected, run:
\dt
# You should see all your tables (agents, alerts, process_events, etc.)
```

### Option B: Supabase (Alternative)

1. Go to [https://supabase.com](https://supabase.com) → Sign Up
2. Create a new project → Region: closest to you
3. Go to **Settings → Database** → Copy the **Connection String (URI)**
4. Format: `postgresql://postgres.[ref]:[password]@aws-0-[region].pooler.supabase.com:6543/postgres`
5. Run your schema in the **SQL Editor** tab

---

## 4. Step 2 — Backend Deployment (FastAPI on Render)

### 4.1 Prepare Backend for Cloud Deployment

You need to make some changes to your project before deploying:

#### A. Create `backend/Procfile` (for Render)
Create a new file at the project root:

**File: `Procfile`** (in project root `Red-Eye/`)
```
web: uvicorn backend.main:app --host 0.0.0.0 --port $PORT
```

#### B. Update `requirements.txt`
Add these production dependencies to your existing `requirements.txt`:

```txt
fastapi>=0.110.0
uvicorn>=0.28.0
sqlalchemy>=2.0.0
psycopg2-binary>=2.9.0
pydantic>=2.6.0
python-dotenv>=1.0.0
requests>=2.31.0
python-dateutil>=2.8.2
psutil>=5.9.0
watchdog>=4.0.0
python-multipart>=0.0.9
gunicorn>=21.2.0
```

> **Note**: `gunicorn` is added for production ASGI serving on Render.

#### C. Create `render.yaml` (optional but recommended)
Create this file at the project root for Render's Blueprint deployment:

**File: `render.yaml`** (in project root `Red-Eye/`)
```yaml
services:
  - type: web
    name: redeye-api
    runtime: python
    plan: free
    buildCommand: pip install -r requirements.txt
    startCommand: uvicorn backend.main:app --host 0.0.0.0 --port $PORT
    envVars:
      - key: DATABASE_URL
        sync: false
      - key: VT_API_KEY
        sync: false
      - key: MB_API_KEY
        sync: false
      - key: OPERATOR_PASSWORD
        sync: false
      - key: PYTHON_VERSION
        value: "3.11.6"
```

### 4.2 Push Code to GitHub

```bash
# Initialize git if not already
cd Red-Eye
git init
git add .
git commit -m "Prepare for cloud deployment"

# Create a GitHub repo (public or private)
# Go to https://github.com/new → name it "Red-Eye"
git remote add origin https://github.com/YOUR_USERNAME/Red-Eye.git
git branch -M main
git push -u origin main
```

### 4.3 Deploy on Render

1. Go to [https://render.com](https://render.com) → Sign up with GitHub
2. Click **"New +"** → **"Web Service"**
3. Connect your GitHub repository (`Red-Eye`)
4. Configure the service:

| Setting | Value |
|---|---|
| **Name** | `redeye-api` |
| **Region** | Singapore (or closest) |
| **Branch** | `main` |
| **Root Directory** | *(leave empty — it's the repo root)* |
| **Runtime** | `Python 3` |
| **Build Command** | `pip install -r requirements.txt` |
| **Start Command** | `uvicorn backend.main:app --host 0.0.0.0 --port $PORT` |
| **Plan** | `Free` |

5. Add **Environment Variables** (click "Advanced" → "Add Environment Variable"):

| Key | Value |
|---|---|
| `DATABASE_URL` | `postgresql://neondb_owner:YOUR_PASSWORD@ep-xxx.aws.neon.tech/neondb?sslmode=require` |
| `VT_API_KEY` | Your VirusTotal API key |
| `MB_API_KEY` | Your MalwareBazaar API key |
| `OPERATOR_PASSWORD` | Your chosen admin password |
| `PYTHON_VERSION` | `3.11.6` |

6. Click **"Create Web Service"**
7. Wait for the build to complete (3-5 minutes)
8. Your API is now live at: `https://redeye-api.onrender.com`

### 4.4 Verify Backend Deployment
```bash
# Test the API is running
curl https://redeye-api.onrender.com/docs

# You should see the Swagger UI HTML or JSON response
```

> **⚠️ Free Tier Note**: Render's free tier spins down after 15 minutes of inactivity. First request after sleep takes ~30-50 seconds to cold-start. This is normal.

---

## 5. Step 3 — Frontend Deployment (React on Cloudflare Pages)

### 5.1 Update Frontend API Base URL

Before deploying, you **MUST** update the frontend to point to your production API URL instead of `http://192.168.1.50:8000`.

#### A. Create an Environment Configuration File

**File: `frontend/.env.production`**
```env
VITE_API_URL=https://api.desaivraj.site
```

**File: `frontend/.env.development`**
```env
VITE_API_URL=http://localhost:8000
```

#### B. Update `frontend/src/App.jsx`

Replace the hardcoded IP-based API URL. Find line ~135 where `c2BaseUrl` is defined:

```javascript
// BEFORE (around line 130-140):
const c2GatewayIp = '192.168.1.50';
const c2BaseUrl = `http://${c2GatewayIp}:8000`;

// AFTER:
const c2BaseUrl = import.meta.env.VITE_API_URL || 'http://localhost:8000';
```

Then do a **global find & replace** across the entire `App.jsx` file:

| Find | Replace With |
|---|---|
| `` `http://${c2GatewayIp}:8000` `` | `c2BaseUrl` |
| `` `http://192.168.1.50:8000` `` | `c2BaseUrl` |
| `http://192.168.1.50:8000` | `${c2BaseUrl}` |

> **⚠️ CRITICAL**: There are many hardcoded references to `http://192.168.1.50:8000` throughout `App.jsx`. You must replace **ALL** of them. Use your editor's "Replace All" function.

### 5.2 Build the Frontend for Production

```bash
cd frontend

# Install dependencies
npm install

# Build for production
npm run build

# This creates a "dist/" folder with the static files
```

### 5.3 Deploy to Cloudflare Pages

#### Method 1: Direct Upload (Easiest — No GitHub needed)

1. Go to [https://dash.cloudflare.com](https://dash.cloudflare.com) → Sign Up
2. In the left sidebar, click **"Workers & Pages"** → **"Pages"**
3. Click **"Create application"** → **"Pages"** → **"Upload assets"**
4. **Project name**: `redeye`
5. Drag and drop your `frontend/dist/` folder contents
6. Click **"Deploy site"**
7. Your site is live at: `https://redeye.pages.dev`

#### Method 2: Git Integration (Auto-deploy on push)

1. Go to [Cloudflare Dashboard](https://dash.cloudflare.com) → **Workers & Pages** → **Pages**
2. Click **"Create application"** → **"Connect to Git"**
3. Select your GitHub repo (`Red-Eye`)
4. Configure build settings:

| Setting | Value |
|---|---|
| **Production branch** | `main` |
| **Framework preset** | `None` |
| **Build command** | `cd frontend && npm install && npm run build` |
| **Build output directory** | `frontend/dist` |
| **Root directory** | `/` (project root) |

5. Add Environment Variable:
   - `VITE_API_URL` = `https://api.desaivraj.site`
   - `NODE_VERSION` = `20`

6. Click **"Save and Deploy"**
7. Every push to `main` will auto-deploy

### 5.4 Verify Frontend Deployment
- Open `https://redeye.pages.dev` in your browser
- You should see the RedEye login/dashboard page
- Try logging in with your `OPERATOR_PASSWORD`

---

## 6. Step 4 — Custom Domain Configuration

### 6.1 Prerequisites
- You own the domain `desaivraj.site`
- Your domain's nameservers are pointed to **Cloudflare** (recommended for free SSL + DNS management)

### 6.2 Transfer DNS to Cloudflare (if not already)

1. Go to [Cloudflare Dashboard](https://dash.cloudflare.com)
2. Click **"Add a Site"** → Enter `desaivraj.site`
3. Select the **Free plan**
4. Cloudflare will scan existing DNS records
5. Copy the Cloudflare nameservers (e.g., `anna.ns.cloudflare.com`, `dax.ns.cloudflare.com`)
6. Go to your domain registrar (GoDaddy, Namecheap, Hostinger, etc.)
7. Update nameservers to the Cloudflare ones
8. Wait 10-60 minutes for propagation

### 6.3 Configure `redeye.desaivraj.site` (Frontend)

**In Cloudflare Pages:**
1. Go to **Workers & Pages** → Your `redeye` project
2. Click **"Custom domains"** tab
3. Click **"Set up a custom domain"**
4. Enter: `redeye.desaivraj.site`
5. Click **"Activate domain"**
6. Cloudflare auto-creates the CNAME record and provisions SSL

**Result**: `https://redeye.desaivraj.site` → Your React frontend ✅

### 6.4 Configure `api.desaivraj.site` (Backend)

**In Render:**
1. Go to your **redeye-api** web service on Render
2. Click **"Settings"** → scroll to **"Custom Domains"**
3. Click **"Add Custom Domain"**
4. Enter: `api.desaivraj.site`
5. Render will give you a CNAME target (e.g., `redeye-api.onrender.com`)

**In Cloudflare DNS:**
1. Go to Cloudflare Dashboard → `desaivraj.site` → **DNS** → **Records**
2. Add a new record:

| Type | Name | Target | Proxy Status |
|---|---|---|---|
| `CNAME` | `api` | `redeye-api.onrender.com` | **DNS only** (grey cloud ☁️) |

> **⚠️ IMPORTANT**: Set proxy status to **"DNS only"** (grey cloud), NOT "Proxied" (orange cloud). Render needs to handle its own SSL certificate and the orange cloud proxy can interfere with that.

3. Go back to Render → Click **"Verify"** on the custom domain
4. Render will auto-provision a free SSL certificate via Let's Encrypt

**Result**: `https://api.desaivraj.site` → Your FastAPI backend ✅

### 6.5 Update CORS for Production

In `backend/main.py` (around line 152-158), update the CORS configuration:

```python
# BEFORE:
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# AFTER (recommended for production):
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://redeye.desaivraj.site",
        "https://redeye.pages.dev",
        "http://localhost:5173",         # local dev
        "http://localhost:3000",         # local dev alt
        "*",                             # keep for agent implants
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

> **Note**: You can keep `"*"` for now since your agents also need to connect from arbitrary IPs. Tighten this later if needed.

### 6.6 DNS Verification

After setting up DNS records, verify:
```bash
# Check frontend DNS
nslookup redeye.desaivraj.site

# Check backend DNS
nslookup api.desaivraj.site

# Test API endpoint
curl https://api.desaivraj.site/docs
```

---

## 7. Step 5 — Compile Desktop .exe (Electron)

### 7.1 Install Electron Builder

```bash
cd frontend

# Install electron-builder as dev dependency
npm install --save-dev electron-builder
```

### 7.2 Update `frontend/package.json` for Building

Replace your `package.json` with:

```json
{
  "name": "redeye-frontend",
  "private": true,
  "version": "1.0.0",
  "type": "module",
  "main": "main.js",
  "scripts": {
    "dev": "vite",
    "build": "vite build",
    "preview": "vite preview",
    "electron": "electron .",
    "electron:dev": "concurrently -k \"npm run dev\" \"npx wait-on http://localhost:5173 && electron .\"",
    "dist:win": "npm run build && electron-builder --win --x64",
    "dist:linux": "npm run build && electron-builder --linux",
    "dist:mac": "npm run build && electron-builder --mac"
  },
  "dependencies": {
    "lucide-react": "^0.344.0",
    "react": "^18.2.0",
    "react-dom": "^18.2.0"
  },
  "devDependencies": {
    "@types/react": "^18.2.66",
    "@types/react-dom": "^18.2.22",
    "@vitejs/plugin-react": "^4.2.1",
    "concurrently": "^8.2.2",
    "electron": "^29.4.6",
    "electron-builder": "^24.13.3",
    "vite": "^5.1.6",
    "wait-on": "^9.1.0"
  },
  "build": {
    "appId": "com.redeye.c2dashboard",
    "productName": "RedEye C2 Dashboard",
    "directories": {
      "output": "release"
    },
    "files": [
      "dist/**/*",
      "main.js",
      "public/**/*"
    ],
    "win": {
      "target": [
        {
          "target": "nsis",
          "arch": ["x64"]
        },
        {
          "target": "portable",
          "arch": ["x64"]
        }
      ],
      "icon": "public/logo.png"
    },
    "nsis": {
      "oneClick": false,
      "perMachine": true,
      "allowToChangeInstallationDirectory": true,
      "installerIcon": "public/logo.png",
      "uninstallerIcon": "public/logo.png",
      "installerHeaderIcon": "public/logo.png"
    },
    "linux": {
      "target": ["AppImage", "deb"],
      "icon": "public/logo.png"
    },
    "mac": {
      "target": ["dmg"],
      "icon": "public/logo.png"
    }
  }
}
```

### 7.3 Update `frontend/main.js` for Production API

The Electron main process needs to load the built `dist/` files in production and point to `api.desaivraj.site`:

```javascript
import { app, BrowserWindow } from 'electron';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

process.env['ELECTRON_DISABLE_SECURITY_WARNINGS'] = 'true';
app.commandLine.appendSwitch('disable-features', 'AutofillServerCommunication');

function createWindow() {
  const win = new BrowserWindow({
    width: 1400,
    height: 900,
    webPreferences: {
      nodeIntegration: true,
      contextIsolation: false,
    },
    icon: path.join(__dirname, 'public/logo.png'),
    title: 'RedEye Command & Control Dashboard',
    backgroundColor: '#070101'
  });

  const isDev = !app.isPackaged;

  if (isDev) {
    // Development: Load from Vite dev server
    win.webContents.openDevTools();
    win.loadURL('http://localhost:5173').catch(() => {
      win.loadFile(path.join(__dirname, 'dist/index.html')).catch((err) => {
        console.error("Failed to load both dev server and production package:", err);
      });
    });
  } else {
    // Production: Load from built dist/ folder
    win.loadFile(path.join(__dirname, 'dist/index.html')).catch((err) => {
      console.error("Failed to load production build:", err);
    });
  }

  // Remove default menu bar for standard UI look
  win.setMenuBarVisibility(false);
}

app.whenReady().then(() => {
  createWindow();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow();
    }
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});
```

### 7.4 Build the .exe

```powershell
cd frontend

# 1. Build the React frontend first
npm run build

# 2. Build the Windows .exe
# This creates both an installer (.exe) and a portable .exe
npm run dist:win
```

**Output Location**: `frontend/release/`
```
frontend/release/
├── RedEye C2 Dashboard Setup 1.0.0.exe    ← Installer (NSIS)
├── RedEye C2 Dashboard 1.0.0.exe          ← Portable .exe (no install needed)
└── win-unpacked/                           ← Unpacked folder
    └── RedEye C2 Dashboard.exe
```

> The **portable .exe** is what you distribute. Users just double-click to run — no installation needed.

### 7.5 Important: The .exe Connects to `api.desaivraj.site`

Since you updated the `VITE_API_URL` to `https://api.desaivraj.site` in `.env.production` and ran `npm run build` before packaging, the compiled .exe will automatically make all API calls to `https://api.desaivraj.site`.

**Verify**: After building, open the .exe → check the Network tab in DevTools (if enabled) → all API calls should go to `https://api.desaivraj.site/api/v1/...`.

---

## 8. Step 6 — Agent Configuration for Production

### 8.1 Update Windows Agent (`agents/windows/Red-Eye.py`)

```python
# BEFORE:
BASE_URL = "http://192.168.1.50:8000"

# AFTER:
BASE_URL = "https://api.desaivraj.site"
```

Then recompile the Windows agent:
```powershell
cd agents/windows

# Using PyInstaller to create the agent .exe
pip install pyinstaller
pyinstaller --onefile --noconsole --name Red-Eye Red-Eye.py
# Output: agents/windows/dist/Red-Eye.exe
```

### 8.2 Update Linux Agent (`agents/linux/agent.py`)

```python
# BEFORE:
BASE_URL = "http://192.168.1.50:8000"

# AFTER:
BASE_URL = "https://api.desaivraj.site"
```

### 8.3 Update Android Agent (`agents/android/App.js`)

```javascript
// BEFORE:
const BASE_URL = "http://192.168.1.50:8000";

// AFTER:
const BASE_URL = "https://api.desaivraj.site";
```

### 8.4 Remove IP Sync from `start.py` (Optional)

The `sync_project_ip()` function in `start.py` will try to replace IPs at every launch. For production, you may want to disable this or add a production flag:

```python
# In start.py, add this check:
if os.environ.get("PRODUCTION") != "True":
    sync_project_ip(local_ip, root_dir)
```

---

## 9. Code Changes Required Before Deployment

### Summary of ALL Code Changes

#### `frontend/src/App.jsx` — API Base URL

```diff
- const c2GatewayIp = '192.168.1.50';
- const c2BaseUrl = `http://${c2GatewayIp}:8000`;
+ const c2BaseUrl = import.meta.env.VITE_API_URL || 'http://localhost:8000';
```

Then replace all instances of hardcoded URLs:
```diff
- fetch(`http://192.168.1.50:8000/api/v1/...`)
+ fetch(`${c2BaseUrl}/api/v1/...`)
```

```diff
- fetch(`http://${c2GatewayIp}:8000/api/v1/...`)
+ fetch(`${c2BaseUrl}/api/v1/...`)
```

#### `frontend/.env.production` — New File

```env
VITE_API_URL=https://api.desaivraj.site
```

#### `frontend/.env.development` — New File

```env
VITE_API_URL=http://localhost:8000
```

#### `backend/main.py` — CORS Update (line ~152)

```diff
  app.add_middleware(
      CORSMiddleware,
-     allow_origins=["*"],
-     allow_credentials=False,
+     allow_origins=[
+         "https://redeye.desaivraj.site",
+         "https://redeye.pages.dev",
+         "http://localhost:5173",
+         "*",
+     ],
+     allow_credentials=True,
      allow_methods=["*"],
      allow_headers=["*"],
  )
```

#### `Procfile` — New File (project root)

```
web: uvicorn backend.main:app --host 0.0.0.0 --port $PORT
```

#### `.env` — Update for Production

```env
DATABASE_URL=postgresql://neondb_owner:YOUR_PASSWORD@ep-xxx.aws.neon.tech/neondb?sslmode=require
VT_API_KEY=your_virustotal_api_key
MB_API_KEY=your_malwarebazaar_api_key
OPERATOR_PASSWORD=your_secure_password
```

---

## 10. Environment Variables Reference

### Backend (Render) Environment Variables

| Variable | Required | Value | Notes |
|---|---|---|---|
| `DATABASE_URL` | ✅ Yes | Neon PostgreSQL connection string | Must include `?sslmode=require` for Neon |
| `VT_API_KEY` | ✅ Yes | VirusTotal API key | Free tier: 4 requests/min |
| `MB_API_KEY` | ❌ Optional | MalwareBazaar API key | For additional threat intel |
| `OPERATOR_PASSWORD` | ✅ Yes | Admin login password | For dashboard authentication |
| `PYTHON_VERSION` | ✅ Yes | `3.11.6` | Render Python version |
| `JWT_SECRET_KEY` | ❌ Optional | Auto-generated | Backend auto-generates if not set |
| `DISABLE_RATE_LIMITER` | ❌ Optional | `True`/`False` | Set `True` to disable IP rate limits |

### Frontend (Cloudflare Pages) Environment Variables

| Variable | Required | Value |
|---|---|---|
| `VITE_API_URL` | ✅ Yes | `https://api.desaivraj.site` |
| `NODE_VERSION` | ✅ Yes | `20` |

---

## 11. Troubleshooting & FAQ

### ❌ "CORS policy: No 'Access-Control-Allow-Origin' header"
**Fix**: Make sure `backend/main.py` has `allow_origins=["*"]` or includes your frontend domain. Redeploy after changes.

### ❌ Backend takes 30-50 seconds to respond
**Cause**: Render free tier spins down after 15 minutes of inactivity.
**Fix**: This is normal on free tier. Options:
1. Use [UptimeRobot](https://uptimerobot.com) (free) to ping `https://api.desaivraj.site/docs` every 10 minutes to keep it awake
2. Accept the cold start delay

### ❌ "SSL: CERTIFICATE_VERIFY_FAILED" from agents
**Fix**: Ensure agent HTTP clients verify SSL. For Python requests:
```python
import requests
response = requests.get("https://api.desaivraj.site/api/v1/...", verify=True)
```

### ❌ Database connection failed on Render
**Fix**: 
1. Verify `DATABASE_URL` env var on Render dashboard
2. Ensure the connection string ends with `?sslmode=require` for Neon
3. Check Neon dashboard → your project is not paused

### ❌ Electron .exe shows blank screen
**Fix**: 
1. Make sure you ran `npm run build` before `npm run dist:win`
2. Check that `dist/index.html` exists in the `frontend/` folder
3. In `main.js`, ensure production path loads from `dist/index.html`

### ❌ "Cannot find module" when building .exe
**Fix**: Run `npm install` in the `frontend/` directory first.

### ❌ Neon database auto-suspends (query timeout)
**Cause**: Neon free tier suspends compute after 5 minutes of idle.
**Fix**: First query after wake-up may take 2-3 seconds. The app handles reconnection automatically via SQLAlchemy's `pool_pre_ping=True`.

### ❌ Frontend doesn't update after re-deploy
**Fix**: Cloudflare caches aggressively. Clear cache:
1. Cloudflare Dashboard → your zone → **Caching** → **Purge Everything**
2. Or add cache-busting headers in your Vite config

### ❌ How to keep Render backend alive (free)?
Use [UptimeRobot](https://uptimerobot.com):
1. Sign up (free)
2. Add new monitor → HTTP(s)
3. URL: `https://api.desaivraj.site/docs`
4. Interval: **every 10 minutes**
5. This pings your backend regularly, preventing it from sleeping

---

## 12. Quick Reference Cheatsheet

### Deployment Commands (Copy-Paste)

```bash
# ─── 1. DATABASE: Create on Neon ───
# Go to https://neon.tech → Create project → Copy connection string

# ─── 2. BACKEND: Deploy to Render ───
# Push to GitHub first
git add .
git commit -m "Deploy to production"
git push origin main
# Then go to https://render.com → New Web Service → Connect repo → Deploy

# ─── 3. FRONTEND: Build and deploy ───
cd frontend
echo "VITE_API_URL=https://api.desaivraj.site" > .env.production
npm install
npm run build
# Upload frontend/dist/ to Cloudflare Pages

# ─── 4. COMPILE .EXE ───
cd frontend
npm install --save-dev electron-builder
npm run build
npm run dist:win
# Output: frontend/release/RedEye C2 Dashboard 1.0.0.exe

# ─── 5. DNS RECORDS (in Cloudflare DNS) ───
# Type: CNAME | Name: redeye | Target: redeye.pages.dev         | Proxy: ON
# Type: CNAME | Name: api    | Target: redeye-api.onrender.com  | Proxy: OFF

# ─── 6. VERIFY ───
curl https://api.desaivraj.site/docs
curl https://redeye.desaivraj.site
```

### Final URLs

| Service | URL |
|---|---|
| **Frontend (Web)** | `https://redeye.desaivraj.site` |
| **Backend API** | `https://api.desaivraj.site` |
| **API Docs (Swagger)** | `https://api.desaivraj.site/docs` |
| **Desktop App** | `frontend/release/RedEye C2 Dashboard 1.0.0.exe` |
| **Database** | Neon Dashboard at `https://console.neon.tech` |

### Cost Summary

| Service | Monthly Cost |
|---|---|
| Neon PostgreSQL | **$0** (0.5 GB free) |
| Render Backend | **$0** (750 hrs free) |
| Cloudflare Pages | **$0** (unlimited bandwidth) |
| Cloudflare DNS + SSL | **$0** |
| UptimeRobot | **$0** (50 monitors free) |
| **Total** | **$0/month** |

---

> **💡 Pro Tip**: Once you outgrow the free tier, the easiest upgrade path is:
> - **Render Starter** ($7/mo) — no more cold starts, always-on
> - **Neon Launch** ($19/mo) — more storage, no auto-suspend
> - Or self-host on a **VPS** (Oracle Cloud free tier gives 4 ARM cores + 24 GB RAM **forever free**)
