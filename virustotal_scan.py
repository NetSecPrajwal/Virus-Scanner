import requests
import hashlib
from config import load_api_key, save_api_key

VT_URL = "https://www.virustotal.com/api/v3/"

def scan_file_virustotal(file_path):
    """ Scans a file using VirusTotal API """
    api_key = load_api_key()
    if not api_key:
        print("[-] No API key found! Run the tool again and set your API key.")
        return

    try:
        with open(file_path, "rb") as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()

        headers = {"x-apikey": api_key}
        response = requests.get(VT_URL + f"files/{file_hash}", headers=headers)

        if response.status_code == 200:
            report = response.json()
            stats = report["data"]["attributes"]["last_analysis_stats"]
            print(f"\n🔍 **Scan Results:**\n")
            print(f"  🟢 Clean: {stats['harmless']}")
            print(f"  🟡 Suspicious: {stats['suspicious']}")
            print(f"  🔴 Malicious: {stats['malicious']}")
            print(f"\n[+] View full report: https://www.virustotal.com/gui/file/{file_hash}")
        else:
            print("[-] File not found in VirusTotal. Uploading for analysis...")
            with open(file_path, "rb") as f:
                files = {"file": (file_path, f)}
                upload_response = requests.post(VT_URL + "files", headers=headers, files=files)

            if upload_response.status_code == 200:
                print("[+] File uploaded successfully! Check VirusTotal for results.")
            else:
                print("[-] Error:", upload_response.json())

    except FileNotFoundError:
        print("[-] Error: File not found. Please enter a valid file path.")

def scan_url_virustotal(url):
    """ Scans a URL using VirusTotal API """
    api_key = load_api_key()
    if not api_key:
        print("[-] No API key found! Run the tool again and set your API key.")
        return

    headers = {"x-apikey": api_key, "Content-Type": "application/json"}
    data = {"url": url}
    
    response = requests.post(VT_URL + "urls", headers=headers, json=data)

    if response.status_code == 200:
        analysis_id = response.json()["data"]["id"]
        print(f"[+] URL submitted for scanning. Check results: https://www.virustotal.com/gui/url/{analysis_id}")
    else:
        print("[-] Error:", response.json())

def setup_api_key():
    """ Prompts user to enter VirusTotal API key """
    api_key = input("Enter your VirusTotal API Key: ").strip()
    save_api_key(api_key)
    print("[+] API Key saved!")
