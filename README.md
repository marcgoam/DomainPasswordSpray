# DomainPasswordSpray.py
[![Python 3.8+](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python&logoColor=yellow)](https://www.python.org/downloads/) [![License: BSD 3-Clause](https://img.shields.io/badge/License-BSD%203--Clause-blue.svg)](https://opensource.org/license/bsd-3-clause/) [![LDAP3](https://img.shields.io/badge/ldap3-2.9%2B-green)](https://pypi.org/project/ldap3/)

> **Python port of [dafthack/DomainPasswordSpray](https://github.com/dafthack/DomainPasswordSpray)** - Native Linux implementation for Active Directory password spraying

Performs **password spray attacks** against Active Directory domains from **Linux** (Kali, Ubuntu, etc.) through VPN connections. Perfect **drop-in replacement** for the original PowerShell version.

## Installation

### Quick Start (Kali/Debian)
```bash
# Clone repository
git clone https://github.com/[YOUR_USERNAME]/DomainPasswordSpray.py.git
cd DomainPasswordSpray.py

# Install dependencies
pip3 install -r requirements.txt

# Make executable
chmod +x DomainPasswordSpray.py
```

## Basic Usage

### Password Spraying: One Password → All Users

Tests **1 common password** against **ALL domain users** simultaneously.

```bash
python3 DomainPasswordSpray.py -Domain corp.local -Password Spring2026
```

Perfect for:

- Common passwords: Password123, Winter2026, Summer2024
- Seasonal passwords: Q1_2026, Verano2026
- Default passwords from company policy
- Safety: Only 1 attempt per user = zero lockout risk

### Username-as-Password: Username = Password

Tests each username as its own password.

```bash
python3 DomainPasswordSpray.py -Domain corp.local -UsernameAsPassword -OutFile username_creds.txt
```

```
user1 → Password: "user1"
user2 → Password: "user2"  
admin → Password: "admin"
svc_web → Password: "svc_web"
```

Perfect for:

- Lazy users who use username as password
- Service accounts with simple naming
- Default configurations
- Safety: Still only 1 attempt per user

### Multiple Passwords (PasswordList)

Tests multiple passwords → one at a time with observation window delays.

```bash
echo -e "Password123\nSpring2026\nWelcome1" > passwords.txt
python3 DomainPasswordSpray.py -Domain corp.local -PasswordList passwords.txt -OutFile creds.txt
```

```
Round 1: Password123 → ALL users → Wait 30min (observation window)
Round 2: Spring2026 → ALL users → Wait 30min  
Round 3: Welcome1 → ALL users → ✅ Complete!
```

## Complete Parameter Reference

|Parameter | Use Case | Example |
|----------|----------|-------- |
| -Password	| Single common password | Winter2026
| -PasswordList | Multiple passwords sequentially | passwords.txt
| -UsernameAsPassword |	Hunt lazy users | -
| -UserList | Custom target list | targets.txt
| -OutFile | Save valid credentials | creds.txt
| -dc | Manual input DC ip | -

<div align="center">

**⭐ Star if useful! ⭐**

[![GitHub stars](https://img.shields.io/github/stars/marcgoam/DomainPasswordSpray?style=social)](https://github.com/marcgoam/DomainPasswordSpray/stargazers/)

![GitHub](https://img.shields.io/github/license/marcgoam/DomainPasswordSpray)
![GitHub last commit](https://img.shields.io/github/last-commit/marcgoam/DomainPasswordSpray)

</div>
