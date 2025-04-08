import os

def scan_file_offline(file_path):
    """ Scans a file using ClamAV """
    print("[*] Scanning file with ClamAV...")
    result = os.popen(f"clamscan --no-summary {file_path}").read()
    print(result)
