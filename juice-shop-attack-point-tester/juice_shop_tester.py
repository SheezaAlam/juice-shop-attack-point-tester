import requests
from datetime import datetime
from urllib.parse import urlparse
from pathlib import Path

TIMEOUT = 5
REPORT_DIR = Path("reports")
REPORT_DIR.mkdir(exist_ok=True)
findings_count = 0
results = []

def record_result(test_name, status, details):
    results.append({"test": test_name, "status": status, "details": details})
    print(f"RESULT: {status}")
    print(f"Details: {details}")

def is_valid_url(url):
    try:
        parsed = urlparse(url)
        return parsed.scheme in ("http", "https") and bool(parsed.hostname) and not any(c.isspace() for c in url)
    except ValueError:
        return False

def test_directory_listing(base_url):
    global findings_count
    print("\n[TEST 1] Directory Listing Check")
    url = base_url + "/ftp/"
    try:
        response = requests.get(url, timeout=TIMEOUT)
        print("Requested:", url)
        print("HTTP status:", response.status_code)
        page = response.text.lower()
        indicators = ["index of /ftp", "directory listing for /ftp", "acquisitions.md", "incident-support.kdbx"]
        found = [item for item in indicators if item in page]
        if response.status_code == 200 and found:
            findings_count += 1
            record_result("Directory listing", "POTENTIAL FINDING", "Directory indicators found: " + ", ".join(found))
            print("Recommendation: Review directory access and exposed files.")
        elif response.status_code == 200:
            record_result("Directory listing", "NOT DETECTED", "No configured directory-listing indicators were found.")
        else:
            record_result("Directory listing", "INCONCLUSIVE", f"Received HTTP {response.status_code}.")
    except requests.exceptions.RequestException as error:
        record_result("Directory listing", "TEST ERROR", str(error))

def test_public_file(base_url):
    global findings_count
    print("\n[TEST 2] Public File Access Check")
    url = base_url + "/ftp/acquisitions.md"
    try:
        response = requests.get(url, timeout=TIMEOUT)
        print("Requested:", url)
        print("HTTP status:", response.status_code)
        if response.status_code == 200:
            findings_count += 1
            content_type = response.headers.get("Content-Type", "Not provided")
            record_result("Public file access", "REVIEW REQUIRED", f"File returned HTTP 200; content type: {content_type}.")
            print("Recommendation: Review the file contents and access policy.")
        elif response.status_code in (401, 403):
            record_result("Public file access", "ACCESS RESTRICTED", f"Server returned HTTP {response.status_code}.")
        elif response.status_code == 404:
            record_result("Public file access", "NOT FOUND", "The requested file returned HTTP 404.")
        else:
            record_result("Public file access", "INCONCLUSIVE", f"Received HTTP {response.status_code}.")
    except requests.exceptions.RequestException as error:
        record_result("Public file access", "TEST ERROR", str(error))

def test_security_headers(base_url):
    global findings_count
    print("\n[TEST 3] Security Headers Check")
    expected_headers = ["X-Content-Type-Options", "X-Frame-Options", "Content-Security-Policy"]
    try:
        response = requests.get(base_url, timeout=TIMEOUT)
        print("Requested:", base_url)
        print("HTTP status:", response.status_code)
        missing = []
        for header in expected_headers:
            value = response.headers.get(header)
            if value:
                print(f"[PRESENT] {header}: {value}")
            else:
                print(f"[MISSING] {header}")
                missing.append(header)
        if missing:
            findings_count += 1
            record_result("Security headers", "REVIEW REQUIRED", "Missing headers: " + ", ".join(missing))
            print("Recommendation: Review which headers are appropriate.")
        else:
            record_result("Security headers", "NO MISSING CHECKED HEADERS", "All configured headers were present.")
        if urlparse(base_url).scheme == "https":
            if response.headers.get("Strict-Transport-Security"):
                print("[PRESENT] Strict-Transport-Security")
            else:
                print("[MISSING] Strict-Transport-Security")
                print("Recommendation: Review HTTPS and HSTS configuration.")
        else:
            print("[SKIPPED] HSTS assessment: target URL uses HTTP, so absence of HSTS is not counted as a finding.")
    except requests.exceptions.RequestException as error:
        record_result("Security headers", "TEST ERROR", str(error))

def save_report(target_url):
    timestamp = datetime.now().astimezone().isoformat(timespec="seconds")
    filename = REPORT_DIR / ("juice_shop_report_" + datetime.now().strftime("%Y%m%d_%H%M%S") + ".txt")
    with filename.open("w", encoding="utf-8") as report:
        report.write("OWASP JUICE SHOP SECURITY TEST REPORT\n")
        report.write("=" * 45 + "\n")
        report.write(f"Date/time: {timestamp}\nTarget: {target_url}\nScope: Three configured, non-destructive checks\n\n")
        for item in results:
            report.write(f"Test: {item['test']}\nStatus: {item['status']}\nDetails: {item['details']}\n\n")
        report.write("=" * 45 + "\n")
        report.write(f"Checks attempted: {len(results)}\nItems flagged for review: {findings_count}\n")
        report.write("Note: Automated results require manual verification.\n")
    print("\nReport saved to:", filename)

def main():
    print("=" * 45)
    print(" OWASP Juice Shop Security Tester")
    print("=" * 45)
    target_url = input("Enter your authorized lab URL: ").strip().rstrip("/")
    if not target_url:
        print("ERROR: URL cannot be empty.")
        return
    if not is_valid_url(target_url):
        print("ERROR: Enter a valid URL starting with http:// or https://")
        return
    print("\nTarget:", target_url)
    print("Starting non-destructive checks...")
    test_directory_listing(target_url)
    test_public_file(target_url)
    test_security_headers(target_url)
    print("\n" + "=" * 45)
    print("TEST RUN SUMMARY")
    print("=" * 45)
    print("Checks attempted:", len(results))
    print("Items flagged for review:", findings_count)
    print("Note: Flags are not confirmed vulnerabilities.")
    save_report(target_url)

if __name__ == "__main__":
    main()
