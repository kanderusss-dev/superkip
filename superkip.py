from concurrent.futures import ThreadPoolExecutor
import ipaddress
import socket
import time

import requests as req
import colorama

colorama.init()

def get_whois(query_target: str) -> dict:
    try:
        try:
            ipaddress.ip_address(query_target)
            url = f"https://rdap.org/ip/{query_target}"
        except ValueError:
            url = f"https://rdap.org/domain/{query_target}"

        resp = req.get(url, timeout=5)
        if resp.status_code == 200:
            return resp.json()
        return {"error": f"HTTP {resp.status_code}", "url": url}
    except Exception as e:
        return {"error": str(e)}


def get_ports(host: str, raw_domain: str, ports: list, query: str):
    opened_ports = []
    info_ports = {}

    def get_port(port):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1.5)
            if s.connect_ex((host, port)) == 0:
                res_info = None
                if query:
                    try:
                        payload = f"{query} / HTTP/1.1\r\nHost: {raw_domain}\r\nConnection: close\r\n\r\n".encode("utf-8")
                        s.sendall(payload)
                        res = s.recv(1024).decode("utf-8", errors="ignore")
                        if res:
                            res_info = res
                    except Exception as e:
                        res_info = f"[{type(e).__name__}: {e}]"
                return (port, True, res_info)
        return (port, False, None)

    with ThreadPoolExecutor() as executor:
        results = executor.map(get_port, ports)

    for port, is_open, info in results:
        if is_open:
            opened_ports.append(port)
            if info:
                info_ports[port] = info

    return opened_ports, info_ports

h = colorama.Fore.GREEN + "hi!" + colorama.Fore.RED

print(colorama.Fore.RED + f"""
super  ▄▀▀▄ █  ▄▀▀█▀▄ {h}▄▀▀▄▀▀▀▄ {colorama.Fore.GREEN + "(entertainment purposes ONLY!)" + colorama.Fore.RED}
super █  █ ▄▀ █   █  █  █   █{h}█ {colorama.Fore.GREEN + "(read 'readme.txt' before using superkip)" + colorama.Fore.RED}
super ▐  █▀▄  ▐{h}█  ▐  ▐  █▀▀▀▀
super   █{h}█     █   {h}  █
super ▄▀   █   ▄▀▀▀▀▀▄   ▄▀
super █{h} ▐  █  {h}  █ █  {h}
super ▐   {h} ▐       ▐ ▐       {h}
""" + colorama.Style.RESET_ALL)

while True:
    try:
        print("=" * 40)

        # Getting starting information...

        raw_domain = input("Enter host: ").strip()
        if not raw_domain:
            print("Host is not optional")
            continue

        host = socket.gethostbyname(raw_domain)
        hostex = socket.gethostbyname_ex(raw_domain)

        domain_display = raw_domain
        try:
            ptr = socket.gethostbyaddr(host)[0]
            domain_display = f"{ptr} ({raw_domain})"
        except Exception:
            pass

        raw_ports = input("Enter ports (optional, e.g. 21 443): ").strip()
        ports = []
        if raw_ports:
            for p in raw_ports.replace(",", " ").split():
                if p.strip().isdigit():
                    ports.append(int(p.strip()))
                else:
                    print(f"Skipping invalid port: '{p}'")

        query = input("Enter an output query (optional, e.g. GET or HEAD): ").strip().upper()

        # Getting information from IP...

        print("\nIt might take some time to get information...")
        starttime = time.time()

        opened_ports = []
        info_ports = {}

        if ports:
            print("DEBUG: Getting open ports / with response...")
            opened_ports, info_ports = get_ports(host, raw_domain, ports, query)

        print("DEBUG: Getting info from IP (ipinfo.io)...")
        respiijs = None
        try:
            respii = req.get(f"https://ipinfo.io/{host}/json", timeout=5)
            respii.raise_for_status()
            respiijs = respii.json()
        except Exception as e:
            respiijs = {"error": f"[{type(e).__name__}: {e}]"}

        print("DEBUG: Getting info from IP (api.ipapi.is)...")
        respiajs = None
        try:
            respia = req.get(f"https://api.ipapi.is/?q={host}", timeout=5)
            respia.raise_for_status()
            respiajs = respia.json()
        except Exception as e:
            respiajs = {"error": f"[{type(e).__name__}: {e}]"}

        print("DEBUG: Getting WHOIS data...")
        whois_data = get_whois(raw_domain)

        elapsed = round(time.time() - starttime, 2)

        # Printing information to user
        print(f"\nIt took {elapsed} seconds to get information.")

        started_at = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(starttime))
        all_ips = ", ".join(hostex[2]) if hostex[2] else "None"
        aliases = ", ".join(hostex[1]) if hostex[1] else "None"

        print("\nStart info:")
        print(f"\tScan started: {started_at}")
        print(f"\tDomain: {domain_display}")
        print(f"\tPrimary IP: {host}")
        print(f"\tEvery IP found: {all_ips}")
        print(f"\tAliases: {aliases}")
        if ports:
            print(f"\tPorts: {', '.join(str(p) for p in ports)}")
        if query:
            print(f"\tQuery: {query} / HTTP/1.1")

        print("\nIP info (from ipinfo.io):")
        for k, v in respiijs.items():
            print(f"\t{k}: {v}")

        print("\nIP info (from api.ipapi.is):")
        for k, v in respiajs.items():
            print(f"\t{k}: {v}")

        print("\nWHOIS info:")
        if whois_data:
            for k, v in whois_data.items():
                print(f"\t{k}: {v}")
        else:
            print("\tNo WHOIS data found")

        if opened_ports:
            print("\nOpened ports:")
            for port in opened_ports:
                print(f"\t{port}")

        if info_ports:
            print("\nPorts with response:")
            for k, v in info_ports.items():
                print(f"--- Port {k} ---\n{v}")

    except KeyboardInterrupt:
        print("\nBye!")
        break
    except Exception as e:
        print(f"{type(e).__name__}: {str(e)}")