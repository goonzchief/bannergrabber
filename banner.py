import socket
import ssl
import argparse
import random
import re
import requests
from datetime import datetime

# List of User-Agent strings for randomization
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.121 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36",
    "Mozilla/5.0 (Linux; Android 10; SM-A515F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.127 Mobile Safari/537.36",
]

# List of common subdomains to brute-force
COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "webmail", "ns1", "ns2", "blog", "localhost", "cpanel", "shop",
    "dev", "api", "test", "forum", "vpn", "beta", "admin", "cdn", "imap", "smtp"
]

def random_user_agent():
    return random.choice(USER_AGENTS)

def detect_os(banner):
    """ Simple OS detection based on banner content """
    os_keywords = {
        "Windows": ["Windows NT", "Win32", "Win64"],
        "Linux": ["Linux", "Debian", "Ubuntu", "Fedora"],
        "Mac OS": ["Mac OS", "Darwin"],
        "FreeBSD": ["FreeBSD"],
        "Solaris": ["SunOS", "Solaris"],
        "Unknown": []
    }
    
    for os_name, keywords in os_keywords.items():
        if any(keyword in banner for keyword in keywords):
            return os_name
    return "Unknown"

def grab_http_banner(host, port=80):
    """ Grabs the HTTP banner by making a simple GET request """
    try:
        conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn.connect((host, port))
        conn.sendall(b"GET / HTTP/1.1\r\nHost: " + host.encode() + b"\r\n\r\n")
        banner = conn.recv(1024).decode('utf-8', errors='ignore')
        conn.close()
        return banner
    except Exception as e:
        return f"Error grabbing HTTP banner: {str(e)}"

def grab_https_banner(host, port=443):
    """ Grabs the HTTPS banner by making a simple request over SSL """
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port)) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                ssock.sendall(b"GET / HTTP/1.1\r\nHost: " + host.encode() + b"\r\n\r\n")
                banner = ssock.recv(1024).decode('utf-8', errors='ignore')
        return banner
    except Exception as e:
        return f"Error grabbing HTTPS banner: {str(e)}"

def grab_ftp_banner(host, port=21):
    """ Grabs the FTP banner """
    try:
        conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn.connect((host, port))
        banner = conn.recv(1024).decode('utf-8', errors='ignore')
        conn.close()
        return banner
    except Exception as e:
        return f"Error grabbing FTP banner: {str(e)}"

def grab_smtp_banner(host, port=25):
    """ Grabs the SMTP banner """
    try:
        conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn.connect((host, port))
        banner = conn.recv(1024).decode('utf-8', errors='ignore')
        conn.close()
        return banner
    except Exception as e:
        return f"Error grabbing SMTP banner: {str(e)}"

def grab_ssh_banner(host, port=22):
    """ Grabs the SSH banner """
    try:
        conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn.connect((host, port))
        banner = conn.recv(1024).decode('utf-8', errors='ignore')
        conn.close()
        return banner
    except Exception as e:
        return f"Error grabbing SSH banner: {str(e)}"

def check_wordpress(host, output_file):
    """ Check if the target is a WordPress site and gather info """
    try:
        response = requests.get(f"http://{host}", headers={"User-Agent": random_user_agent()}, timeout=5)
        if "wp-content" in response.text:
            print("[*] WordPress detected!")
            write_output(output_file, "[*] WordPress detected!")

            version = re.search(r'content="WordPress ([0-9.]+)"', response.text)
            if version:
                version_info = f"[WordPress Version] {version.group(1)}"
                print(version_info)
                write_output(output_file, version_info)
            else:
                print("[WordPress Version] Could not determine version.")
                write_output(output_file, "[WordPress Version] Could not determine version.")
            
            # Check for common plugins
            plugins = ["/wp-content/plugins/akismet/akismet.php", "/wp-content/plugins/elementor/frontend.min.css"]
            for plugin in plugins:
                plugin_url = f"http://{host}{plugin}"
                plugin_response = requests.get(plugin_url, headers={"User-Agent": random_user_agent()}, timeout=5)
                if plugin_response.status_code == 200:
                    plugin_info = f"[Plugin Found] {plugin}"
                    print(plugin_info)
                    write_output(output_file, plugin_info)

            # Check for common themes
            themes = ["/wp-content/themes/twentytwentyone/style.css", "/wp-content/themes/twentytwentytwo/style.css"]
            for theme in themes:
                theme_url = f"http://{host}{theme}"
                theme_response = requests.get(theme_url, headers={"User-Agent": random_user_agent()}, timeout=5)
                if theme_response.status_code == 200:
                    theme_info = f"[Theme Found] {theme}"
                    print(theme_info)
                    write_output(output_file, theme_info)

            # List users
            list_wordpress_users(host, output_file)

    except Exception as e:
        error_msg = f"Error checking WordPress: {str(e)}"
        print(error_msg)
        write_output(output_file, error_msg)

def list_wordpress_users(host, output_file):
    """ List WordPress users and analyze their roles """
    try:
        response = requests.get(f"http://{host}/wp-json/wp/v2/users", headers={"User-Agent": random_user_agent()}, timeout=5)
        if response.status_code == 200:
            users = response.json()
            print("[*] WordPress Users:")
            write_output(output_file, "[*] WordPress Users:")

            for user in users:
                user_roles = ', '.join(user.get('roles', ['N/A']))
                email = user.get('email', 'N/A')
                user_info = f" - {user['name']} (ID: {user['id']}), Email: {email}, Roles: {user_roles}"
                print(user_info)
                write_output(output_file, user_info)
        else:
            print(f"[*] Could not enumerate users. Status code: {response.status_code}")
            write_output(output_file, f"[*] Could not enumerate users. Status code: {response.status_code}")

    except Exception as e:
        error_msg = f"Error listing WordPress users: {str(e)}"
        print(error_msg)
        write_output(output_file, error_msg)

def advanced_banner_grab(host, output_file):
    """ Advanced banner grab that uses multiple protocols """
    banners = {}
    
    # HTTP Banner
    print("[*] Grabbing HTTP banner...")
    write_output(output_file, "[*] Grabbing HTTP banner...")
    http_banner = grab_http_banner(host)
    banners["HTTP"] = http_banner
    
    # HTTPS Banner
    print("[*] Grabbing HTTPS banner...")
    write_output(output_file, "[*] Grabbing HTTPS banner...")
    https_banner = grab_https_banner(host)
    banners["HTTPS"] = https_banner
    
    # FTP Banner
    print("[*] Grabbing FTP banner...")
    write_output(output_file, "[*] Grabbing FTP banner...")
    ftp_banner = grab_ftp_banner(host)
    banners["FTP"] = ftp_banner
    
    # SMTP Banner
    print("[*] Grabbing SMTP banner...")
    write_output(output_file, "[*] Grabbing SMTP banner...")
    smtp_banner = grab_smtp_banner(host)
    banners["SMTP"] = smtp_banner
    
    # SSH Banner
    print("[*] Grabbing SSH banner...")
    write_output(output_file, "[*] Grabbing SSH banner...")
    ssh_banner = grab_ssh_banner(host)
    banners["SSH"] = ssh_banner
    
    return banners

def find_subdomains(host, output_file):
    """ Brute-force common subdomains """
    print("[*] Starting subdomain search...")
    write_output(output_file, "[*] Starting subdomain search...")
    
    found_subdomains = []
    for subdomain in COMMON_SUBDOMAINS:
        subdomain_host = f"{subdomain}.{host}"
        try:
            socket.gethostbyname(subdomain_host)
            found_subdomains.append(subdomain_host)
            subdomain_info = f" - Found subdomain: {subdomain_host}"
            print(subdomain_info)
            write_output(output_file, subdomain_info)
        except socket.gaierror:
            pass  # Ignore subdomains that cannot be resolved
    
    if not found_subdomains:
        print("[*] No common subdomains found.")
        write_output(output_file, "[*] No common subdomains found.")

def write_output(output_file, text):
    """ Write output to a file using utf-8 encoding """
    with open(output_file, "a", encoding="utf-8") as f:
        f.write(f"{text}\n")


def main():
    parser = argparse.ArgumentParser(description="Advanced Banner Grabbing Tool with WPScan Features and Subdomain Finder")
    parser.add_argument('target', help="Domain or IP address to grab banners from")
    args = parser.parse_args()

    target = args.target

    # Generate the output filename based on the target
    output_file = f"{target}-output.txt"

    # Clear previous output and write header with timestamp
    with open(output_file, "w") as f:
        f.write(f"Banner Grabbing Results for {target} - {datetime.now()}\n")
        f.write("="*60 + "\n")
    
    print(f"[*] Starting banner grabbing for: {target}")
    write_output(output_file, f"[*] Starting banner grabbing for: {target}")

    banners = advanced_banner_grab(target, output_file)
    
    for service, banner in banners.items():
        print(f"\n{service} Banner:\n{'-'*40}\n{banner}\n{'-'*40}")
        write_output(output_file, f"\n{service} Banner:\n{'-'*40}\n{banner}\n{'-'*40}")
        
        if service in ["HTTP", "HTTPS", "FTP", "SMTP"]:
            os_info = detect_os(banner)
            print(f"[OS Detected] {os_info}")
            write_output(output_file, f"[OS Detected] {os_info}")

    check_wordpress(target, output_file)  # Check for WordPress features

    # Find subdomains
    find_subdomains(target, output_file)

if __name__ == "__main__":
    main()
