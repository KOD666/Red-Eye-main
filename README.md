# RedEye C2 and EDR Platform

RedEye is a centralized Endpoint Detection and Response (EDR) and Command and Control (C2) fleet monitoring platform designed for host telemetry collection, process monitoring, and threat scanning. The application coordinates a FastAPI backend server for telemetry ingestion, an Electron/React operator console for command dispatching, and agent implants running on Linux, Windows, and Android.

## Features

- Centralized Endpoint Detection and Response (EDR) command and control (C2) server.
- Interactive operator dashboard built using React, Vite, and Electron.
- Multi-platform implants for monitoring Android, Linux, and Windows hosts.
- Concurrent and rate-limited threat intelligence scanning utilizing VirusTotal and MalwareBazaar.
- Real-time telemetry ingestion pipeline and command dispatching queues.
- Local hash whitelisting and dynamic tracking of detected high-risk packages.

## Project Structure

```
.
├── start.py                # Orchestrator script to concurrently launch C2 backend, Electron UI, and scan daemon
├── requirements.txt         # Python dependencies for the FastAPI server and scanning utilities
├── malware_free.json       # Local whitelisted safe SHA-256 hashes generated from VirusTotal scans
├── malware.json            # Persistent confirmed malware SHA-256 hashes shared across Android, Linux and Windows agents
├── detected.json           # Local JSON file tracking detected high-risk Android applications
├── suspicious.json         # Local JSON file tracking suspicious (yellow) Android applications
├── vt_results.json         # VirusTotal scan query results
├── test.db                 # Local fallback SQLite database file
├── .env.example            # Environment configuration template for API keys and database credentials
├── .gitignore              # Files and directories ignored by Git version control
├── backend/                # FastAPI Gateway source code handling API requests, telemetry, and agent commands
│   ├── main.py             # FastAPI server application containing endpoints, routing, and ingestion logic
│   ├── database.py         # SQLAlchemy DB session setup with automatic SQLite fallback logic
│   ├── models.py           # SQLAlchemy database model definitions (agents, heartbeats, process events, etc.)
│   ├── schemas.py          # Pydantic schemas for request and response validation
│   ├── auth.py             # JWT token utilities, authentication helper functions, and encryption
│   └── test_auth_flow.py   # Test suite for authentication and token validation logic
├── database/               # Relational database schema definitions and SQL scripts
│   ├── schema_v2.sql       # Current PostgreSQL 18+ schema (tables, constraints, indices, references)
│   ├── schema.sql          # Legacy version of database schema script
│   └── pg.log              # Log files for local database configuration
├── frontend/               # React and Electron source code for the operator control dashboard
│   ├── main.js             # Electron main process entrypoint and window lifecycle manager
│   ├── index.html          # HTML entry shell for the Vite bundler
│   ├── vite.config.js      # Vite bundler and dev server configuration
│   ├── package.json        # Frontend Node.js dependencies and script definitions
│   └── src/
│       └── App.jsx         # Main React application component for operator dashboard and EDR views
└── agents/                 # Implant source code for target host monitoring and telemetry extraction
    ├── linux/
    │   ├── agent.py        # Linux host telemetry python daemon
    │   ├── install.sh      # Service installer script for Linux agent daemon
    │   └── agent_config.json # Configuration file for local agent settings
    ├── windows/
    │   ├── Red-Eye.py      # Windows telemetry collector implant code (processes, sockets, login events)
    │   └── Red-Eye.exe     # Compiled Windows implant executable
    └── android/
        ├── App.js          # React Native / Expo agent app for background monitoring
        ├── app.json        # Expo framework configuration metadata
        └── package.json    # Expo dependencies and scripts
```

## Getting Started

Follow these steps in order to set up and run the platform on your machine.

### 1. Clone the repository
```bash
git clone https://github.com/KOD666/Red-Eye.git
cd Red-Eye
```

### 2. Create and activate a virtual environment

#### Linux / macOS:
```bash
python3 -m venv .venv
source .venv/bin/activate
```

#### Windows:
Create the virtual environment:
```powershell
python -m venv .venv
```

Activate the virtual environment:

- **PowerShell:**
  ```powershell
  .\.venv\Scripts\Activate.ps1
  ```

- **Command Prompt (cmd):**
  ```cmd
  .venv\Scripts\activate.bat
  ```

#### Troubleshooting: `ensurepip is not available` / `python3-pip has no installation candidate` (Ubuntu/Debian)

If you see errors like these when creating the virtual environment or installing pip:

```
The virtual environment was not created successfully because ensurepip is not available.
```
```
E: Package 'python3-pip' has no installation candidate
```

Follow these steps **in order** to fix it:

```bash
# 1. Update your package lists first (this is usually the root cause)
sudo apt update

# 2. Install the venv module for your specific Python version
#    Check your Python version first:
python3 --version

#    Then install the matching python3.X-venv package:
#    For Python 3.8:
sudo apt install python3.8-venv
#    For Python 3.10:
sudo apt install python3.10-venv
#    For Python 3.12:
sudo apt install python3.12-venv

#    Or install the generic package (works on most systems):
sudo apt install python3-venv

# 3. Install pip (after apt update, this should now work)
sudo apt install python3-pip

# 4. Delete the broken .venv and recreate it
rm -rf .venv
python3 -m venv .venv
source .venv/bin/activate
```

> **Why does this happen?** Fresh Ubuntu/Debian servers often ship with a minimal Python that lacks the `venv` and `pip` modules. Running `sudo apt update` first refreshes the package index so `apt install` can find the correct packages.

### 3. Install dependencies
Install the required packages for both the backend Python environment and the frontend Electron application:

- **Backend Python dependencies**:
  After activation, use:
  ```bash
  python -m pip install -r requirements.txt
  ```
  or
  ```bash
  py -m pip install -r requirements.txt
  ```
  *Using `python -m pip` is preferred because it always uses the pip associated with that specific Python installation.*

- **Frontend Electron/React dependencies**:
  ```bash
  cd frontend
  npm install
  cd ..
  ```

### 4. Set up environment variables
Copy the environment template file:
```bash
cp .env.example .env
```
Fill in the configuration keys inside `.env`. Here is a breakdown of all environment variables used by the system:

| Variable | Mandatory | Default | Description |
| :--- | :--- | :--- | :--- |
| `DATABASE_URL` | **Yes** (for Postgres) | *None* | Connection URI for the database. Example: `postgresql://postgres:password%40123@localhost:5432/Demo_RE`. **Note**: If your password contains special characters (like `@` in `password@123`), you *must* URL-encode them (e.g., `@` becomes `%40`). |
| `OPERATOR_PASSWORD` | **Yes** | *None* | Plaintext administrative password for logging into the dashboard (used for user `admin`). |
| `VT_API_KEY` | **Yes** (for scanning) | *None* | API key for VirusTotal scans. If missing/invalid, the `scan_detected.py` daemon will print an error and exit immediately. |
| `JWT_SECRET_KEY` | No | *Auto-generated* | The signing secret for JWT tokens. If left unset, the backend will auto-generate a secure random 256-bit key at startup and save it in `backend/.jwt_secret`. |
| `MB_API_KEY` | No | `""` | Optional API key for MalwareBazaar integration. |
| `LATEST_AGENT_VERSION`| No | `"2.0.0"` | The expected agent version. Triggers update prompts for agents running older versions. |
| `DISABLE_RATE_LIMITER`| No | `False` | Disables IP rate limits on API endpoints when set to `True`. |
| `TESTING` | No | `False` | Enables test mode behaviors, bypasses rate limiting, and configures mock contexts when set to `True`. |

### 5. Set up the Database (PostgreSQL)
RedEye is built to run on **PostgreSQL 18+** but features an **automatic SQLite fallback** (`test.db`) if a PostgreSQL connection fails. Follow these instructions to set up PostgreSQL:

#### A. Install and start PostgreSQL
- **On Linux (Ubuntu/Debian)**:
  ```bash
  sudo apt update
  sudo apt install postgresql postgresql-contrib
  sudo systemctl start postgresql
  sudo systemctl enable postgresql
  ```
- **On Windows**: Ensure PostgreSQL 18+ is installed and running. Start the service via the Windows Services management console (name: `postgresql-x64-18`) or run:
  ```cmd
  net start postgresql-x64-18
  ```

#### B. Create the database and user
Log into the PostgreSQL terminal as the superuser:
```bash
sudo -u postgres psql
```
Execute the following SQL queries to create the database and set the password:
```sql
-- Create the RedEye database
CREATE DATABASE "Demo_RE";

-- Set password for the postgres user (match the password in your .env DATABASE_URL)
ALTER USER postgres PASSWORD 'password@123';
```
Type `\q` and press Enter to exit.

#### C. Run migrations & initialize the schema
- **Automatic Setup**: No manual table migration execution is needed. The FastAPI server automatically initializes and applies all tables on startup using SQLAlchemy's `models.Base.metadata.create_all(bind=engine)`.
- **Manual Schema Execution (Optional)**: If you prefer to seed the database structure manually using raw SQL before launching:
  ```bash
  sudo -u postgres psql -d Demo_RE -f database/schema_v2.sql
  ```

#### D. Seed initial data
There is no separate manual seeding command. The backend automatically inserts default and dynamic mock data (alerts, policies, heartbeats, etc.) on startup if it detects the database tables are empty.

#### E. SQLite Fallback
If PostgreSQL is not installed or the connection fails, the FastAPI backend automatically falls back to a local SQLite database file (`test.db`) at `./test.db`.

### 6. Run the application
Start the orchestrator script to concurrently launch the FastAPI C2 gateway, the Electron UI console, and the background threat scan daemon:
```bash
python3 start.py
```
*(On launch, the script will prompt you for your Local IP address to synchronize connection configurations across the dashboard and client implants).*

### 7. Verify it worked
Ensure all services are running properly by checking:
- **FastAPI OpenAPI Interactive Swagger Docs**: Open `http://<IP>:8000/docs` in your web browser (replace `<IP>` with the address selected during startup, or use `localhost`).
- **FastAPI API Health Response**: Verify basic routing responds by running:
  ```bash
  curl http://localhost:8000/
  ```
  It should return `{"detail":"Not Found"}` (confirming the gateway is active).
- **Vite Dev Server**: Open `http://localhost:5173` in your browser. Note that a standalone Electron desktop operator GUI window should automatically launch when running `start.py`.

## Live App

### Live Demo
[Live Demo Link](https://example.com/404-not-yet-deployed)

*Note: The real deployment link will be added here once the staging environment is deployed.*

## Credits & Contributors

- **Primary Developer**: [desaivraj8740](https://github.com/desaivraj8740) (Major creator of this project)
- **Contributor**: [KOD666](https://github.com/KOD666)
