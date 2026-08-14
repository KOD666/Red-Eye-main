import os
import sys
import json
import time
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from dotenv import load_dotenv

# Load env variables from .env in workspace root
load_dotenv()

API_KEY = os.environ.get("VT_API_KEY", "")
HEADERS = {
    "x-apikey": API_KEY
}

INPUT_FILE = "suspicious.json"
OUTPUT_FILE = "vt_results.json"
WHITELIST_FILE = "malware_free.json"
MALWARE_FILE = "malware.json"

# Make sure we can import the backend package
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

try:
    from backend.database import SessionLocal
    from backend.models import AndroidApp
except ImportError as e:
    print(f"[!] Could not import backend database modules: {e}")
    SessionLocal = None


def query_vt(file_hash, max_retries=3):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    retries = 0
    backoff = 2
    
    while retries < max_retries:
        try:
            response = requests.get(url, headers=HEADERS, timeout=10)
            if response.status_code == 200:
                data = response.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                return {
                    "status": "found",
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "undetected": stats.get("undetected", 0),
                    "harmless": stats.get("harmless", 0),
                    "total": sum(stats.values())
                }
            elif response.status_code == 404:
                return {
                    "status": "not_found"
                }
            elif response.status_code == 429:
                print(f"[!] VT Rate limit exceeded (429) for hash {file_hash}. Retrying in {backoff}s...")
                time.sleep(backoff)
                retries += 1
                backoff *= 2
            else:
                return {
                    "status": f"error_{response.status_code}"
                }
        except Exception as e:
            print(f"[!] Exception querying VT for hash {file_hash}: {e}")
            retries += 1
            time.sleep(backoff)
            backoff *= 2
            
    return {
        "status": "failed_after_retries",
        "malicious": 0,
        "suspicious": 0,
        "undetected": 0,
        "harmless": 0,
        "total": 0
    }


def is_yellow_suspicious_app(app):
    # Check if app is red/detected
    vt_malicious = 0
    if app.vt_detection_rate and app.vt_detection_rate != "0/0":
        try:
            vt_malicious = int(app.vt_detection_rate.split("/")[0])
        except Exception:
            pass
            
    is_malware = (
        app.mb_listed or 
        vt_malicious >= 1 or 
        (app.threat_category and "Confirmed Malware" in app.threat_category)
    )
    score = app.threat_score or 0
    is_red = is_malware or score >= 61 or app.risk_level == "red"
    if is_red:
        return False
        
    return score >= 30 or app.risk_level == "yellow"


def sync_suspicious_apps_file():
    """
    Reads the database for all current suspicious (yellow) apps.
    Saves/updates the suspicious.json file.
    """
    if not SessionLocal:
        print("[!] Database session not available. Skipping sync.")
        return []
        
    db = SessionLocal()
    try:
        db_apps = db.query(AndroidApp).filter(
            AndroidApp.apk_sha256 != "Unknown",
            AndroidApp.apk_sha256 != None,
            AndroidApp.apk_sha256 != ""
        ).all()
        
        current_suspicious = []
        for app in db_apps:
            if is_yellow_suspicious_app(app):
                current_suspicious.append({
                    "app_name": app.app_name,
                    "package": app.package_name,
                    "version": app.version_name or "",
                    "sha256": app.apk_sha256
                })
                
        # De-duplicate by sha256
        seen_hashes = set()
        unique_suspicious = []
        for app in current_suspicious:
            if app["sha256"] not in seen_hashes:
                seen_hashes.add(app["sha256"])
                unique_suspicious.append(app)
                
        with open(INPUT_FILE, "w") as f:
            json.dump(unique_suspicious, f, indent=4)
            
        print(f"[{time.strftime('%X')}] Synced {INPUT_FILE} - {len(unique_suspicious)} suspicious apps currently listed.")
        return unique_suspicious
    except Exception as e:
        print(f"[!] Error syncing suspicious apps: {e}")
        return []
    finally:
        db.close()


def update_db_results(results):
    if not SessionLocal:
        print("[!] Database session not available. Skipping DB update.")
        return
        
    db = SessionLocal()
    try:
        # Load local whitelist and confirmed malware list
        whitelist = []
        confirmed_malware_set = set()
        if os.path.exists(WHITELIST_FILE):
            try:
                with open(WHITELIST_FILE, "r") as _wf:
                    whitelist = json.load(_wf)
            except Exception:
                pass
        if os.path.exists(MALWARE_FILE):
            try:
                with open(MALWARE_FILE, "r") as _mf:
                    confirmed_malware_set = set(h.strip().lower() for h in json.load(_mf))
            except Exception:
                pass
                
        whitelist_updated = False
        malware_updated = False
        
        for r in results:
            sha256 = r["sha256"]
            normalized_hash = sha256.strip().replace(":", "").lower()
            vt = r["virustotal"]
            
            # Skip errors
            if vt.get("status") not in ["found", "not_found"]:
                continue
                
            apps = db.query(AndroidApp).filter(AndroidApp.apk_sha256 == sha256).all()
            if not apps:
                continue
                
            if vt["status"] == "found":
                malicious = vt["malicious"]
                total = vt["total"]
                vt_rate = f"{malicious}/{total}"
            else:
                vt_rate = "0/0"
                malicious = 0
                total = 0
                
            for app in apps:
                app.vt_detection_rate = vt_rate
                
                if malicious >= 1:
                    app.threat_score = 100
                    app.threat_category = "Confirmed Malware (Threat Intel)"
                    app.risk_level = "red"
                    app.mitre_tactics = ["Persistence", "Collection", "Credential Access", "Defense Evasion"]
                    print(f"[-] Escalated to RED (Malware): {app.app_name} ({app.package_name}) - VT: {vt_rate}")
                    # Persist to malware.json so this status survives reconnects
                    if normalized_hash and normalized_hash not in confirmed_malware_set:
                        confirmed_malware_set.add(normalized_hash)
                        malware_updated = True
                elif vt["status"] == "found" and malicious == 0 and total > 0:
                    app.threat_score = 0
                    app.threat_category = "Safe / Trusted App (VT Confirmed Clean)"
                    app.risk_level = "green"
                    app.mitre_tactics = []
                    
                    if normalized_hash and normalized_hash not in whitelist:
                        whitelist.append(normalized_hash)
                        whitelist_updated = True
                    print(f"[+] Downgraded to GREEN (Safe): {app.app_name} ({app.package_name})")
                    
        if whitelist_updated:
            try:
                with open(WHITELIST_FILE, "w") as _wf2:
                    json.dump(whitelist, _wf2, indent=4)
                print(f"[+] Updated whitelist file: {WHITELIST_FILE}")
            except Exception as e:
                print(f"[!] Failed to write whitelist: {e}")

        if malware_updated:
            try:
                with open(MALWARE_FILE, "w") as _mf2:
                    json.dump(sorted(list(confirmed_malware_set)), _mf2, indent=4)
                print(f"[+] Updated malware.json: {len(confirmed_malware_set)} confirmed hashes.")
            except Exception as e:
                print(f"[!] Failed to write malware.json: {e}")
                
        db.commit()
        print("[+] Database updated successfully.")
    except Exception as e:
        db.rollback()
        print(f"[!] Error updating database: {e}")
    finally:
        db.close()


def scan_batch(apps):
    if not apps:
        return

    # 1. Load local whitelist (malware_free.json)
    whitelist = set()
    if os.path.exists(WHITELIST_FILE):
        try:
            with open(WHITELIST_FILE, "r") as wf:
                whitelist = set(h.strip().replace(":", "").lower() for h in json.load(wf))
        except Exception:
            pass

    # 2. Load existing results cache (vt_results.json)
    cached_results = {}
    if os.path.exists(OUTPUT_FILE):
        try:
            with open(OUTPUT_FILE, "r") as f:
                for r in json.load(f):
                    if "sha256" in r and "virustotal" in r:
                        norm = r["sha256"].strip().replace(":", "").lower()
                        cached_results[norm] = r["virustotal"]
        except Exception:
            pass

    results = []
    apps_to_scan = []

    for app in apps:
        sha256 = app.get("sha256", "")
        if not sha256 or sha256 == "Unknown":
            continue
        norm_sha = sha256.strip().replace(":", "").lower()

        # Check whitelist first
        if norm_sha in whitelist:
            print(f"[+] Hash {sha256[:12]}... found in local whitelist ({WHITELIST_FILE}). Skipping API call.")
            results.append({
                "app_name": app["app_name"],
                "package": app["package"],
                "version": app["version"],
                "sha256": app["sha256"],
                "virustotal": {"status": "found", "malicious": 0, "suspicious": 0, "undetected": 70, "harmless": 70, "total": 70}
            })
        # Check VT results cache second
        elif norm_sha in cached_results:
            print(f"[+] Hash {sha256[:12]}... found in local VT results cache. Skipping API call.")
            results.append({
                "app_name": app["app_name"],
                "package": app["package"],
                "version": app["version"],
                "sha256": app["sha256"],
                "virustotal": cached_results[norm_sha]
            })
        else:
            apps_to_scan.append(app)

    if apps_to_scan:
        print(f"[*] Starting concurrent check of {len(apps_to_scan)} uncached suspicious app hashes...")
        # Batch size limit set to max 3 or 4 to stay strictly within rate limits
        MAX_WORKERS = min(3, len(apps_to_scan))
        
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            future_to_app = {
                executor.submit(query_vt, app["sha256"]): app 
                for app in apps_to_scan
            }
            
            for future in as_completed(future_to_app):
                app = future_to_app[future]
                try:
                    vt_result = future.result()
                    print(f"[✓] Scanned {app['app_name']} ({app['package']}) - Status: {vt_result['status']}")
                    
                    results.append({
                        "app_name": app["app_name"],
                        "package": app["package"],
                        "version": app["version"],
                        "sha256": app["sha256"],
                        "virustotal": vt_result
                    })
                except Exception as exc:
                    print(f"[!] App {app['app_name']} generated an exception: {exc}")
                
    try:
        # Load existing results to merge/append
        existing_results = []
        if os.path.exists(OUTPUT_FILE):
            try:
                with open(OUTPUT_FILE, "r") as f:
                    existing_results = json.load(f)
            except Exception:
                pass
                
        # Merge new results
        results_map = {res["sha256"]: res for res in existing_results}
        for res in results:
            results_map[res["sha256"]] = res
            
        with open(OUTPUT_FILE, "w") as f:
            json.dump(list(results_map.values()), f, indent=4)
        print(f"[+] Results saved/updated to {OUTPUT_FILE}")
    except Exception as e:
        print(f"[!] Error writing results to {OUTPUT_FILE}: {e}")
    
    # Update DB based on scan results
    print("[*] Updating database...")
    update_db_results(results)


def main():
    if not API_KEY or API_KEY == "YOUR_VIRUSTOTAL_API_KEY":
        print("[!] ERROR: Please set the VT_API_KEY environment variable in your .env file.")
        return

    print("[*] Starting continuous scan_suspicious daemon (updating every 2 minutes)...")
    
    try:
        while True:
            # 1. Sync current suspicious (yellow) apps list from DB
            suspicious_apps = sync_suspicious_apps_file()
            
            # 2. Filter out apps that already have valid scan results in our output results
            unscanned_apps = []
            scanned_hashes = set()
            
            if os.path.exists(OUTPUT_FILE):
                try:
                    with open(OUTPUT_FILE, "r") as f:
                        scanned_data = json.load(f)
                        for item in scanned_data:
                            vt_status = item.get("virustotal", {}).get("status")
                            if vt_status in ["found", "not_found"]:
                                scanned_hashes.add(item["sha256"])
                except Exception:
                    pass
            
            for app in suspicious_apps:
                if app["sha256"] not in scanned_hashes:
                    unscanned_apps.append(app)
            
            if unscanned_apps:
                print(f"[*] Found {len(unscanned_apps)} new/unscanned suspicious apps. Scanning...")
                scan_batch(unscanned_apps)
                sync_suspicious_apps_file()
            else:
                print(f"[*] No new suspicious apps to scan.")
                
            print("[*] Sleeping for 2 minutes before next check...")
            time.sleep(120)
            
    except KeyboardInterrupt:
        print("\n[*] Stopped daemon.")

if __name__ == "__main__":
    main()
