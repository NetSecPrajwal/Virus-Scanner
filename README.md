# 🛡️ Virus Scanner

A lightweight and beginner-friendly **Python-based Virus Scanner** that scans files in a directory and checks them against a list of known malicious file hashes.

## 🔍 Features

- 📂 Scans files in a specified directory
- 🔐 Generates SHA256 hashes of files
- ⚠️ Compares hashes with a known malware list
- 🖥️ Simple and fast command-line interface
- 🛠️ Easy to customize and extend

---

## 📦 Requirements

- Python 3.6+
- `requests` (for future VirusTotal API support)
- `PySimpleGUI` (for optional GUI)

Install dependencies:

```bash
pip install -r requirements.txt
```

🚀 Usage
```
python virus_scanner.py --path /path/to/scan
```
#Example
```
python virus_scanner.py --path ./downloads
```
🧪 How It Works
      Reads all files from the given directory.
      Generates a SHA256 hash of each file.
      Compares the hash with a list of known malicious hashes in malicious_hashes.txt.
      Displays a clean/infected result for each file.

🧠 Upcoming Features
      * ✅ Recursive directory scanning
      * ✅ Quarantine detected files
      * ✅ VirusTotal API integration
      * ✅ Scan report generation
      * ✅ GUI interface using PySimpleGUI
      * ✅ Support for MD5, SHA1, and other hash types

🤝 Contributing
Feel free to fork this repo, suggest features, or raise issues!
We welcome contributions from anyone interested in Python and cybersecurity.

📜 License
This project is for educational purposes only. Use responsibly.

🔗 Connect
Made with ❤️ by NetSecPrajwal
#Python #CyberSecurity #VirusScanner #OpenSource #MalwareDetection
