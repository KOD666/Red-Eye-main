# Free Backend Hosting & Database Setup Guide (`host.md`)

This guide explains step-by-step how to host your Python FastAPI backend (`RedEye C2 / EDR Server`) for free on **Render**, set up a free **PostgreSQL Database**, configure environment variables, and manage file downloads (such as agent binaries and scripts).

---

## 1. Overview of Free Hosting Architecture

To host a Python FastAPI server with a PostgreSQL database and static file downloads for free:

| Component | Free Hosting Provider | Description |
| :--- | :--- | :--- |
| **Python FastAPI Backend** | **Render** (Web Service Free Tier) | Runs `uvicorn` / FastAPI server with HTTPS automatically enabled. |
| **PostgreSQL Database** | **Render PostgreSQL** / **Neon.tech** / **Supabase** | Free managed PostgreSQL database instance. |
| **Static File / Agent Downloads** | Render Static Mounts / Cloudflare R2 / GitHub Releases | Serves static agent binaries (`Red-Eye-new.exe`, `redeye-agent`, `RedEye.apk`). |

---

## 2. Step 1: Free PostgreSQL Database Setup

You have two primary options for a free PostgreSQL database:

### Option A: Render PostgreSQL (Easiest Integration)
1. Sign up / Log in to [Render Console](https://dashboard.render.com/).
2. Click **New +** → Select **PostgreSQL**.
3. Fill in details:
   - **Name**: `redeye-db`
   - **Database**: `redeyedb`
   - **User**: `redeye_user`
   - **Region**: Choose the region closest to you (e.g. Frankfurt, Singapore, Oregon).
   - **Instance Type**: Select **Free**.
4. Click **Create Database**.
5. Once created, copy the **Internal Database URL** (for Render services) or **External Database URL** (for local testing/connections).
   - Example: `postgres://redeye_user:password@dpg-xxxx-a.render.com/redeyedb`

### Option B: Neon.tech (Recommended for 24/7 Serverless DB)
1. Sign up at [Neon.tech](https://neon.tech/).
2. Create a new project named `redeye-db`.
3. Copy the pooled connection string:
   - Example: `postgresql://neondb_owner:password@ep-xyz.tech/neondb?sslmode=require`

---

## 3. Step 2: Preparing Your Repository for Render

Render needs specific configuration files in your repository to know how to install dependencies and run your Python application.

### A. Requirements File (`requirements.txt`)
Ensure you have a `requirements.txt` in your root or backend directory containing:
```text
fastapi>=0.100.0
uvicorn[standard]>=0.22.0
psycopg2-binary>=2.9.6
sqlalchemy>=2.0.0
requests>=2.31.0
python-jose[cryptography]>=3.3.0
passlib[bcrypt]>=1.7.4
python-multipart>=0.0.6
gunicorn>=21.2.0
```

### B. Procurement of Port and Environment Variables in Code
Your FastAPI app must bind to the dynamic `$PORT` environment variable provided by Render.

In `backend/server-main.py` / `backend/main.py`:
```python
import os
import uvicorn

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("backend.server-main:app", host="0.0.0.0", port=port)
```

---

## 4. Step 3: Deploying the Backend on Render

1. Push your latest code to your **GitHub** / **GitLab** repository.
2. Go to [Render Dashboard](https://dashboard.render.com/) → Click **New +** → Select **Web Service**.
3. Connect your GitHub repository.
4. Configure Web Service details:
   - **Name**: `redeye-backend` (Will generate URL: `https://redeye-backend.onrender.com` or custom domain `api.desaivraj.site`)
   - **Region**: Select same region as your DB.
   - **Branch**: `main` or `master`
   - **Root Directory**: `.` (leave blank or specify repository root)
   - **Runtime**: `Python 3`
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `gunicorn -w 4 -k uvicorn.workers.UvicornWorker backend.server-main:app` or `uvicorn backend.server-main:app --host 0.0.0.0 --port $PORT`
   - **Instance Type**: **Free**

5. Scroll down to **Environment Variables** and add:
   | Key | Value |
   | :--- | :--- |
   | `DATABASE_URL` | Your PostgreSQL Connection URL |
   | `SECRET_KEY` | Your random secret string for JWT auth |
   | `DISABLE_RATE_LIMITER` | `False` |

6. Click **Create Web Service**. Render will automatically build and deploy your app.

---

## 5. Step 4: How Render Handles Files & Agent Downloads

### Can Render serve agent files (like `.exe`, `.apk`, binary `redeye-agent`)?
**YES**, Render can serve static files. However, you must understand how Render's filesystem works:

### A. Ephemeral Filesystem vs Git Tracked Binaries
- **Git-Tracked Agent Binaries (Free & Included)**:
  - If your agent binaries (`agents/windows/dist/Red-Eye-new.exe`, `agents/linux/redeye-agent`, `agents/android/RedEye.apk`) are committed to your Git repository, Render includes them during deployment.
  - Your FastAPI code serves them statically via:
    ```python
    from fastapi.staticfiles import StaticFiles

    agents_dir = os.path.join(os.path.dirname(__file__), "..", "agents")
    if os.path.exists(agents_dir):
        app.mount("/agents", StaticFiles(directory=agents_dir), name="agents")
    ```
  - Users can download them directly at:
    - `https://api.desaivraj.site/agents/windows/dist/Red-Eye-new.exe`
    - `https://api.desaivraj.site/agents/linux/redeye-agent`
    - `https://api.desaivraj.site/agents/android/RedEye.apk`
    - `https://api.desaivraj.site/api/v1/operator/agent/download?format=exe&platform_type=Windows`

- **Render Ephemeral Disk Warning**:
  - The free tier of Render uses an **ephemeral disk**. This means any files created or dynamically compiled by the server *at runtime* (outside of git commits) will be deleted whenever Render restarts or re-deploys.
  - **Solution for persistent dynamic uploads**:
    - **Option 1**: Commit pre-compiled binaries into your Git repository under `agents/` directory before pushing to Render.
    - **Option 2**: Attach a **Render Persistent Disk** (Available on paid tiers).
    - **Option 3**: Store binaries on free cloud storage (e.g. **Cloudflare R2** 10GB free tier, **Supabase Storage**, or **GitHub Releases**) and redirect download links to those storage URLs.

---

## 6. Step 5: Setting Up Custom Domain & SSL (`api.desaivraj.site`)

To point your custom domain `api.desaivraj.site` to Render:

1. Open your Web Service settings in Render → Go to **Settings** → Scroll to **Custom Domains**.
2. Click **Add Custom Domain** → Enter `api.desaivraj.site`.
3. Render will give you a target CNAME value (e.g. `redeye-backend.onrender.com`).
4. Go to your DNS Manager (Cloudflare, Namecheap, GoDaddy, Hostinger):
   - Type: `CNAME`
   - Name/Host: `api`
   - Target/Value: `redeye-backend.onrender.com`
   - TTL: Automatic
5. Render automatically issues and renews a free TLS/SSL certificate (HTTPS) within 5–10 minutes.

---

## 7. Step-by-Step Deployment Checklists

- [x] Database URL updated in `config.py` / Environment Variables
- [x] Pre-compiled binaries (`Red-Eye-new.exe`, `redeye-agent`, `RedEye.apk`) committed in `agents/` folder
- [x] `requirements.txt` pushed to root
- [x] Web Service created on Render with start command `gunicorn -w 4 -k uvicorn.workers.UvicornWorker backend.server-main:app`
- [x] Custom domain `api.desaivraj.site` CNAME configured in DNS
- [x] HTTPS verified for agent downloads (`https://api.desaivraj.site/agents/linux/redeye-agent`)
