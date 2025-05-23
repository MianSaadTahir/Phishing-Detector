import requests
import os
from dotenv import load_dotenv

load_dotenv()

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")


def check_url_virustotal(url):
    """Check if a URL is malicious using VirusTotal API"""
    api_url = "https://www.virustotal.com/api/v3/urls"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    data = {"url": url}

    response = requests.post(api_url, headers=headers, data=data)

    if response.status_code == 200:
        scan_id = response.json().get("data", {}).get("id")
        return get_url_report(scan_id)

    return "Error scanning URL"


def get_url_report(scan_id):
    """Retrieve URL scan report from VirusTotal"""
    report_url = f"https://www.virustotal.com/api/v3/analyses/{scan_id}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    response = requests.get(report_url, headers=headers)

    if response.status_code == 200:
        report = response.json()
        stats = report["data"]["attributes"]["stats"]
        return f"Malicious: {stats['malicious']}, Suspicious: {stats['suspicious']}"

    return "Error retrieving report"


def check_file_virustotal(file):
    """Check if a file is malicious using VirusTotal API"""
    api_url = "https://www.virustotal.com/api/v3/files"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    file.seek(0)  # Reset file pointer
    files = {"file": (file.filename, file.read())}

    response = requests.post(api_url, headers=headers, files=files)

    if response.status_code == 200:
        scan_id = response.json().get("data", {}).get("id")
        return get_file_report(scan_id)

    return f"Error scanning file: {response.text}"


def get_file_report(scan_id):
    """Retrieve file scan report from VirusTotal"""
    report_url = f"https://www.virustotal.com/api/v3/analyses/{scan_id}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    response = requests.get(report_url, headers=headers)

    if response.status_code == 200:
        report = response.json()
        stats = report["data"]["attributes"]["stats"]
        return f"Malicious: {stats['malicious']}, Suspicious: {stats['suspicious']}"

    return "Error retrieving report"
