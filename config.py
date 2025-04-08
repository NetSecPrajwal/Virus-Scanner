import json
import os

CONFIG_FILE = "config.json"

def save_api_key(api_key):
    """ Saves the VirusTotal API key """
    with open(CONFIG_FILE, "w") as f:
        json.dump({"api_key": api_key}, f)

def load_api_key():
    """ Loads the VirusTotal API key """
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "r") as f:
            data = json.load(f)
            return data.get("api_key", "")
    return ""
