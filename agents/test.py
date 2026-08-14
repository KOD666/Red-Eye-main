from concurrent.futures import ThreadPoolExecutor
import requests

API_KEY = "102721bda13f74bc1204ed8d3b234d93b1f7a97c720184139c96fb8041563564"

hashes = [
    "BEA719D051CA9486DCBFBD960A8A58A8657202DE6D01B42A672EFCAD76CB3070",
    "AE09CDF34608CEC818E6D6E37B82E5FDC828060056CD0B223AB49A5899E40318",
    "53EE31898F7D3A86FCC5D49E0D721506707D99FF5BF3AC591008570AFDEC7B12",
]

headers = {"x-apikey": API_KEY}

def check_hash(file_hash):
    r = requests.get(
        f"https://www.virustotal.com/api/v3/files/{file_hash}",
        headers=headers,
        timeout=15
    )

    if r.status_code == 200:
        data = r.json()["data"]["attributes"]["last_analysis_stats"]
        return {
            "hash": file_hash,
            "malicious": data["malicious"],
            "suspicious": data["suspicious"],
            "undetected": data["undetected"],
        }

    return {
        "hash": file_hash,
        "error": f"{r.status_code}: {r.text}"
    }

with ThreadPoolExecutor(max_workers=4) as executor:
    results = list(executor.map(check_hash, hashes))

for r in results:
    print(r)
