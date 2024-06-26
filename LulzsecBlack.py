import requests
from bs4 import BeautifulSoup
import pyfiglet  # Import the pyfiglet library

def display_banner():
    banner_text = pyfiglet.figlet_format("Lulzsec Black scan")
    print(banner_text)

def read_paths_from_txt(txt_file):
    with open(txt_file, 'r') as file:
        paths = file.readlines()
    # Remove whitespace characters like `\n` at the end of each line
    paths = [path.strip() for path in paths if path.strip()]
    return paths

def check_path_existence(url, path):
    full_url = f"{url}/{path}"
    response = requests.head(full_url)
    return response.status_code

def scan(url):
    print("Scan started for:", url)

    # IDOR Vulnerability Check
    idor_paths = read_paths_from_txt('idor.txt')
    for path in idor_paths:
        status_code = check_path_existence(url, path)
        if status_code == 200:
            print(f"Potential IDOR vulnerability detected with path: {path}")
        elif status_code == 404:
            print(f"IDOR path not found: {path}")

    # XXE Vulnerability Check
    xxe_paths = read_paths_from_txt('xxe.txt')
    for path in xxe_paths:
        status_code = check_path_existence(url, path)
        if status_code == 200:
            print(f"Potential XXE vulnerability detected with path: {path}")
        elif status_code == 404:
            print(f"XXE path not found: {path}")

    # WebDAV Vulnerability Check
    webdav_paths = read_paths_from_txt('webdav.txt')
    for path in webdav_paths:
        status_code = check_path_existence(url, path)
        if status_code == 200:
            print(f"Potential WebDAV vulnerability detected with path: {path}")
        elif status_code == 404:
            print(f"WebDAV path not found: {path}")

    # XSS Vulnerability Check
    xss_paths = read_paths_from_txt('xss.txt')
    for path in xss_paths:
        status_code = check_path_existence(url, path)
        if status_code == 200:
            print(f"Potential XSS vulnerability detected with path: {path}")
        elif status_code == 404:
            print(f"XSS path not found: {path}")

    # SQL Injection Vulnerability Check
    sql_paths = read_paths_from_txt('sql_injection.txt')
    for path in sql_paths:
        status_code = check_path_existence(url, path)
        if status_code == 200:
            print(f"Potential SQL Injection vulnerability detected with path: {path}")
        elif status_code == 404:
            print(f"SQL Injection path not found: {path}")

    # RCE Vulnerability Check
    rce_paths = read_paths_from_txt('rce.txt')
    for path in rce_paths:
        status_code = check_path_existence(url, path)
        if status_code == 200:
            print(f"Potential RCE vulnerability detected with path: {path}")
        elif status_code == 404:
            print(f"RCE path not found: {path}")

# Example usage
if __name__ == '__main__':
    display_banner()  # Display the banner
    website_url = input("Enter website URL to scan: ")
    scan(website_url)
