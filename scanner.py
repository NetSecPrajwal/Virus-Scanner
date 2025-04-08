from virustotal_scan import scan_file_virustotal, scan_url_virustotal, setup_api_key
from clamav_scan import scan_file_offline
from config import load_api_key
import validators  # For URL validation

def main():
    print("\n🔍 Virus Scanner (Online & Offline)\n")
    print("1 Offline Scan (ClamAV)")
    print("2 Online Scan (VirusTotal API)")

    choice = input("\nChoose an option (1 or 2): ").strip()

    if choice == "1":
        file_path = input("Enter the file path to scan: ").strip()
        scan_file_offline(file_path)
    
    elif choice == "2":
        if not load_api_key():
            setup_api_key()

        input_value = input("Enter the file path or URL to scan: ").strip()

        if validators.url(input_value):  
            scan_url_virustotal(input_value)  # Scan URL if valid
        else:
            scan_file_virustotal(input_value)  # Otherwise, scan file

    else:
        print("[-] Invalid choice. Exiting...")

if __name__ == "__main__":
    main()
