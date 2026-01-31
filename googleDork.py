"""
Ultimate Advanced Google Dorking Tool for Kali Linux
With 500+ Dorks, Smart AI Detection & Advanced Patterns
"""
"""nice to use"""

import os
import sys
import json
import time
import subprocess
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

class Colors:
    """ANSI color codes for terminal output"""
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class SmartDorkParser:
    """Intelligent dork pattern recognition and generation"""
    
    def __init__(self):
        # Pattern recognition rules
        self.patterns = {
            # File type patterns
            r'\.pdf$': {'type': 'filetype', 'ext': 'pdf', 'keyword': True},
            r'\.doc$|\.docx$': {'type': 'filetype', 'ext': 'doc', 'keyword': True},
            r'\.xls$|\.xlsx$': {'type': 'filetype', 'ext': 'xls', 'keyword': True},
            r'\.ppt$|\.pptx$': {'type': 'filetype', 'ext': 'ppt', 'keyword': True},
            r'\.sql$': {'type': 'filetype', 'ext': 'sql', 'keyword': True},
            r'\.log$': {'type': 'filetype', 'ext': 'log', 'keyword': True},
            r'\.txt$': {'type': 'filetype', 'ext': 'txt', 'keyword': True},
            r'\.xml$': {'type': 'filetype', 'ext': 'xml', 'keyword': True},
            r'\.json$': {'type': 'filetype', 'ext': 'json', 'keyword': True},
            r'\.csv$': {'type': 'filetype', 'ext': 'csv', 'keyword': True},
            r'\.zip$': {'type': 'filetype', 'ext': 'zip', 'keyword': True},
            r'\.bak$': {'type': 'filetype', 'ext': 'bak', 'keyword': True},
            r'\.conf$|\.config$': {'type': 'filetype', 'ext': 'conf', 'keyword': True},
            r'\.env$': {'type': 'filetype', 'ext': 'env', 'keyword': True},
            r'\.git$': {'type': 'filetype', 'ext': 'git', 'keyword': True},
            r'\.ini$': {'type': 'filetype', 'ext': 'ini', 'keyword': True},
            r'\.cfg$': {'type': 'filetype', 'ext': 'cfg', 'keyword': True},
            r'\.yaml$|\.yml$': {'type': 'filetype', 'ext': 'yml', 'keyword': True},
            r'\.properties$': {'type': 'filetype', 'ext': 'properties', 'keyword': True},
            r'\.sh$': {'type': 'filetype', 'ext': 'sh', 'keyword': True},
            r'\.bat$': {'type': 'filetype', 'ext': 'bat', 'keyword': True},
            r'\.php$': {'type': 'filetype', 'ext': 'php', 'keyword': True},
            r'\.asp$|\.aspx$': {'type': 'filetype', 'ext': 'asp', 'keyword': True},
            r'\.jsp$': {'type': 'filetype', 'ext': 'jsp', 'keyword': True},
            r'\.js$': {'type': 'filetype', 'ext': 'js', 'keyword': True},
            r'\.py$': {'type': 'filetype', 'ext': 'py', 'keyword': True},
            r'\.rb$': {'type': 'filetype', 'ext': 'rb', 'keyword': True},
            r'\.pl$': {'type': 'filetype', 'ext': 'pl', 'keyword': True},
            r'\.java$': {'type': 'filetype', 'ext': 'java', 'keyword': True},
            r'\.c$': {'type': 'filetype', 'ext': 'c', 'keyword': True},
            r'\.cpp$': {'type': 'filetype', 'ext': 'cpp', 'keyword': True},
            r'\.cs$': {'type': 'filetype', 'ext': 'cs', 'keyword': True},
            r'\.go$': {'type': 'filetype', 'ext': 'go', 'keyword': True},
            r'\.key$': {'type': 'filetype', 'ext': 'key', 'keyword': True},
            r'\.pem$': {'type': 'filetype', 'ext': 'pem', 'keyword': True},
            r'\.crt$': {'type': 'filetype', 'ext': 'crt', 'keyword': True},
            r'\.cer$': {'type': 'filetype', 'ext': 'cer', 'keyword': True},
            r'\.p12$': {'type': 'filetype', 'ext': 'p12', 'keyword': True},
            r'\.pfx$': {'type': 'filetype', 'ext': 'pfx', 'keyword': True},
            r'\.pcap$': {'type': 'filetype', 'ext': 'pcap', 'keyword': True},
            r'\.db$': {'type': 'filetype', 'ext': 'db', 'keyword': True},
            r'\.sqlite$': {'type': 'filetype', 'ext': 'sqlite', 'keyword': True},
            r'\.mdb$': {'type': 'filetype', 'ext': 'mdb', 'keyword': True},
            r'\.dbf$': {'type': 'filetype', 'ext': 'dbf', 'keyword': True},
            
            # Domain patterns
            r'^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$': {'type': 'domain', 'keyword': False},
            
            # URL patterns
            r'^https?://': {'type': 'url', 'keyword': False},
            
            # IP address patterns
            r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$': {'type': 'ip', 'keyword': False},
            
            # Special keywords
            r'^admin': {'type': 'admin', 'keyword': True},
            r'^login': {'type': 'login', 'keyword': True},
            r'^password': {'type': 'password', 'keyword': True},
            r'^confidential': {'type': 'confidential', 'keyword': True},
            r'^secret': {'type': 'secret', 'keyword': True},
            r'^backup': {'type': 'backup', 'keyword': True},
            r'^database': {'type': 'database', 'keyword': True},
            r'^api': {'type': 'api', 'keyword': True},
            r'^key': {'type': 'key', 'keyword': True},
            r'^token': {'type': 'token', 'keyword': True},
        }
        
        # Advanced suggestions
        self.suggestions = {
            'pdf': [
                'filetype:pdf "{keyword}"',
                'ext:pdf intext:"{keyword}"',
                'filetype:pdf "{keyword}" confidential',
                'filetype:pdf "{keyword}" password',
                'filetype:pdf "{keyword}" "internal use only"',
                'filetype:pdf "{keyword}" "not for distribution"',
                'ext:pdf "{keyword}" site:{domain}',
            ],
            'doc': [
                'ext:doc | ext:docx "{keyword}"',
                'filetype:doc "{keyword}" password',
                'ext:doc "{keyword}" confidential',
                'filetype:docx "{keyword}" "internal"',
                'ext:doc | ext:docx "{keyword}" "draft"',
            ],
            'xls': [
                'ext:xls | ext:xlsx "{keyword}"',
                'filetype:xls "{keyword}" password',
                'ext:xlsx "{keyword}" confidential',
                'filetype:xls "{keyword}" database',
            ],
            'sql': [
                'filetype:sql "INSERT INTO" "{keyword}"',
                'ext:sql "{keyword}" password',
                'filetype:sql "CREATE TABLE" "{keyword}"',
                'ext:sql "dump" "{keyword}"',
                'filetype:sql "{keyword}" users',
                'ext:sql "{keyword}" admin',
            ],
            'log': [
                'ext:log "{keyword}"',
                'filetype:log "error" "{keyword}"',
                'ext:log "password" "{keyword}"',
                'filetype:log "exception" "{keyword}"',
                'ext:log "username" "{keyword}"',
            ],
            'env': [
                'filetype:env "{keyword}"',
                'ext:env "DB_PASSWORD" "{keyword}"',
                'filetype:env "API_KEY" "{keyword}"',
                'ext:env "SECRET" "{keyword}"',
                'filetype:env "AWS" "{keyword}"',
            ],
            'conf': [
                'ext:conf | ext:config "{keyword}"',
                'filetype:conf "password" "{keyword}"',
                'ext:config "{keyword}"',
            ],
            'php': [
                'ext:php intext:"<?php" "{keyword}"',
                'filetype:php "{keyword}" password',
                'ext:php "{keyword}" mysql_connect',
                'filetype:php "{keyword}" include',
            ],
            'domain': [
                'site:{domain}',
                'site:{domain} filetype:pdf',
                'site:{domain} ext:sql',
                'site:{domain} ext:log',
                'site:{domain} inurl:admin',
                'site:{domain} inurl:login',
                'site:{domain} "password"',
                'site:{domain} "confidential"',
                'site:{domain} intitle:"index of"',
                'site:*.{domain}',
                'site:{domain} ext:env',
                'site:{domain} ext:bak',
                'site:{domain} inurl:wp-admin',
                'site:{domain} inurl:phpMyAdmin',
                'site:{domain} filetype:sql',
                'site:{domain} ext:php',
                'site:{domain} intitle:"dashboard"',
                'site:{domain} inurl:api',
                'site:{domain} ext:xml',
                'site:{domain} filetype:xls',
            ],
            'admin': [
                'inurl:admin',
                'intitle:"admin panel"',
                'inurl:administrator',
                'inurl:admin/login',
                'inurl:admin.php',
                'intitle:"admin" "login"',
                'inurl:wp-admin',
            ],
            'login': [
                'inurl:login',
                'intitle:"login"',
                'inurl:signin',
                'inurl:auth',
                'intitle:"please login"',
                'inurl:user/login',
            ],
            'password': [
                'intext:"password"',
                'filetype:log "password"',
                'ext:sql "password"',
                '"default password"',
                'intext:"password =" | "passwd ="',
                'ext:txt "password"',
            ],
        }
    
    def parse_input(self, user_input: str) -> Dict:
        """Parse user input and generate smart dorks"""
        user_input = user_input.strip()
        
        result = {
            'original': user_input,
            'type': 'keyword',
            'keyword': '',
            'domain': '',
            'filetype': '',
            'dorks': [],
            'auto_selected': None
        }
        
        # Split input (e.g., "cyber.pdf" -> "cyber" + ".pdf")
        parts = user_input.split('.')
        
        if len(parts) >= 2:
            base = '.'.join(parts[:-1])
            extension = '.' + parts[-1]
            
            # Check if extension matches file pattern
            for pattern, config in self.patterns.items():
                if re.search(pattern, extension, re.IGNORECASE):
                    result['type'] = config['type']
                    result['filetype'] = config['ext']
                    result['keyword'] = base
                    
                    # Generate dorks
                    if config['type'] == 'filetype':
                        result['dorks'] = self._generate_filetype_dorks(base, config['ext'])
                        result['auto_selected'] = result['dorks'][0] if result['dorks'] else None
                    
                    return result
        
        # Check for IP address
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', user_input):
            result['type'] = 'ip'
            result['dorks'] = self._generate_ip_dorks(user_input)
            result['auto_selected'] = result['dorks'][0] if result['dorks'] else None
            return result
        
        # Check for domain pattern
        for pattern, config in self.patterns.items():
            if config['type'] == 'domain' and re.match(pattern, user_input):
                result['type'] = 'domain'
                result['domain'] = user_input
                result['dorks'] = self._generate_domain_dorks(user_input)
                result['auto_selected'] = result['dorks'][0] if result['dorks'] else None
                return result
        
        # Check for URL pattern
        if re.match(r'^https?://', user_input):
            domain = re.search(r'https?://([^/]+)', user_input).group(1)
            result['type'] = 'url'
            result['domain'] = domain
            result['dorks'] = self._generate_domain_dorks(domain)
            result['auto_selected'] = result['dorks'][0] if result['dorks'] else None
            return result
        
        # Check for special keywords
        for pattern, config in self.patterns.items():
            if re.match(pattern, user_input, re.IGNORECASE):
                if config['type'] in self.suggestions:
                    result['type'] = config['type']
                    result['keyword'] = user_input
                    result['dorks'] = [
                        dork.replace('{keyword}', user_input).replace('{domain}', '')
                        for dork in self.suggestions[config['type']]
                    ]
                    result['auto_selected'] = result['dorks'][0] if result['dorks'] else None
                    return result
        
        # Default: treat as keyword
        result['keyword'] = user_input
        result['dorks'] = self._generate_keyword_dorks(user_input)
        result['auto_selected'] = f'"{user_input}"'
        
        return result
    
    def _generate_filetype_dorks(self, keyword: str, filetype: str) -> List[str]:
        """Generate file type specific dorks"""
        dorks = [
            f'filetype:{filetype} "{keyword}"',
            f'ext:{filetype} "{keyword}"',
            f'filetype:{filetype} intext:"{keyword}"',
            f'ext:{filetype} "{keyword}" confidential',
            f'filetype:{filetype} "{keyword}" password',
            f'ext:{filetype} "{keyword}" -site:github.com',
            f'filetype:{filetype} intitle:"{keyword}"',
            f'ext:{filetype} "{keyword}" "internal"',
            f'filetype:{filetype} "{keyword}" "secret"',
            f'ext:{filetype} "{keyword}" "private"',
        ]
        
        # Special cases for specific file types
        if filetype == 'sql':
            dorks.extend([
                f'filetype:sql "INSERT INTO" "{keyword}"',
                f'ext:sql "CREATE TABLE" "{keyword}"',
                f'filetype:sql "{keyword}" password',
                f'ext:sql "{keyword}" users',
                f'filetype:sql "dump" "{keyword}"',
                f'ext:sql "{keyword}" admin',
                f'filetype:sql "{keyword}" backup',
            ])
        elif filetype == 'log':
            dorks.extend([
                f'ext:log "error" "{keyword}"',
                f'filetype:log "password" "{keyword}"',
                f'ext:log "exception" "{keyword}"',
                f'filetype:log "username" "{keyword}"',
                f'ext:log "failed" "{keyword}"',
            ])
        elif filetype == 'env':
            dorks.extend([
                f'filetype:env "API_KEY" "{keyword}"',
                f'ext:env "DB_PASSWORD" "{keyword}"',
                f'filetype:env "AWS" "{keyword}"',
                f'ext:env "SECRET" "{keyword}"',
                f'filetype:env "TOKEN" "{keyword}"',
            ])
        elif filetype == 'php':
            dorks.extend([
                f'ext:php "mysql_connect" "{keyword}"',
                f'filetype:php "password" "{keyword}"',
                f'ext:php "include" "{keyword}"',
                f'filetype:php "<?php" "{keyword}"',
            ])
        elif filetype in ['conf', 'config', 'cfg', 'ini']:
            dorks.extend([
                f'ext:{filetype} "password" "{keyword}"',
                f'filetype:{filetype} "username" "{keyword}"',
                f'ext:{filetype} "database" "{keyword}"',
            ])
        elif filetype in ['key', 'pem', 'crt', 'cer']:
            dorks.extend([
                f'filetype:{filetype} "PRIVATE KEY" "{keyword}"',
                f'ext:{filetype} "BEGIN" "{keyword}"',
            ])
        
        return dorks
    
    def _generate_domain_dorks(self, domain: str) -> List[str]:
        """Generate domain-specific dorks"""
        return [
            f'site:{domain}',
            f'site:{domain} filetype:pdf',
            f'site:{domain} ext:sql',
            f'site:{domain} ext:log',
            f'site:{domain} ext:env',
            f'site:{domain} ext:bak',
            f'site:{domain} inurl:admin',
            f'site:{domain} inurl:login',
            f'site:{domain} "password"',
            f'site:{domain} "confidential"',
            f'site:{domain} intitle:"index of"',
            f'site:*.{domain}',
            f'site:{domain} inurl:wp-admin',
            f'site:{domain} inurl:phpMyAdmin',
            f'site:{domain} filetype:sql',
            f'site:{domain} ext:php',
            f'site:{domain} intitle:"dashboard"',
            f'site:{domain} inurl:api',
            f'site:{domain} ext:xml',
            f'site:{domain} filetype:xls',
            f'site:{domain} ext:doc',
            f'site:{domain} inurl:upload',
            f'site:{domain} intitle:"error"',
            f'site:{domain} ext:git',
            f'site:{domain} filetype:config',
        ]
    
    def _generate_ip_dorks(self, ip: str) -> List[str]:
        """Generate IP address specific dorks"""
        return [
            f'"{ip}"',
            f'intitle:"{ip}"',
            f'inurl:"{ip}"',
            f'"{ip}" camera',
            f'"{ip}" webcam',
            f'"{ip}" server',
            f'"{ip}" login',
        ]
    
    def _generate_keyword_dorks(self, keyword: str) -> List[str]:
        """Generate keyword-based dorks"""
        return [
            f'"{keyword}"',
            f'intext:"{keyword}"',
            f'intitle:"{keyword}"',
            f'inurl:"{keyword}"',
            f'"{keyword}" filetype:pdf',
            f'"{keyword}" ext:doc',
            f'"{keyword}" ext:xls',
            f'"{keyword}" ext:sql',
            f'"{keyword}" password',
            f'"{keyword}" confidential',
        ]


class KaliDorkTool:
    def __init__(self):
        self.parser = SmartDorkParser()
        self.dorks = self._load_comprehensive_dorks()
        self.search_history = []
        self.config_dir = Path.home() / ".config" / "dorktool"
        self.config_file = self.config_dir / "config.json"
        self.history_file = self.config_dir / "history.json"
        
        # Create config directory
        self.config_dir.mkdir(parents=True, exist_ok=True)
        
        # Default settings
        self.browser = "firefox"
        self.search_engine = "google"
        self.incognito = True
        self.auto_open = True
        self.delay = 2
        self.smart_mode = True
        self.output_dir = Path.home() / "dorking_results"
        self.output_dir.mkdir(exist_ok=True)
        
        self.load_config()
        self.load_history()
        
        # Browser commands for Kali
        self.browsers = {
            "firefox": {"cmd": "firefox", "incognito": "--private-window"},
            "chromium": {"cmd": "chromium", "incognito": "--incognito"},
            "brave": {"cmd": "brave-browser", "incognito": "--incognito"},
            "tor": {"cmd": "torbrowser-launcher", "incognito": ""}
        }
        
        # Search engines
        self.search_engines = {
            "google": "https://www.google.com/search?q=",
            "duckduckgo": "https://duckduckgo.com/?q=",
            "bing": "https://www.bing.com/search?q=",
            "shodan": "https://www.shodan.io/search?query=",
            "censys": "https://search.censys.io/search?q=",
            "startpage": "https://www.startpage.com/do/search?q=",
            "yandex": "https://yandex.com/search/?text=",
            "baidu": "https://www.baidu.com/s?wd="
        }
    
    def _load_comprehensive_dorks(self) -> Dict:
        """Load massive comprehensive dork database - 500+ dorks"""
        return {
            "1": {
                "category": "File Discovery",
                "icon": "📁",
                "dorks": {
                    "1": ("Android APK files", 'intitle:"index of/" ".apk"'),
                    "2": ("iOS IPA files", 'intitle:"index of/" ".ipa"'),
                    "3": ("Executable files", 'intitle:"index of/" ".exe"'),
                    "4": ("DLL files", 'intitle:"index of/" ".dll"'),
                    "5": ("Batch files", 'intitle:"index of/" ext:bat'),
                    "6": ("Shell scripts", 'intitle:"index of/" ext:sh'),
                    "7": ("PowerShell scripts", 'ext:ps1 "password"'),
                    "8": ("Python scripts", 'ext:py intext:"password"'),
                    "9": ("Ruby scripts", 'ext:rb intext:"password"'),
                    "10": ("Perl scripts", 'ext:pl intext:"password"'),
                    "11": ("Confidential PDFs", 'filetype:pdf "confidential"'),
                    "12": ("Internal PDFs", 'filetype:pdf "internal use only"'),
                    "13": ("Draft PDFs", 'filetype:pdf "draft"'),
                    "14": ("Confidential PowerPoints", 'ext:ppt | ext:pptx "confidential"'),
                    "15": ("Excel with passwords", 'ext:xls | ext:xlsx "password"'),
                    "16": ("Word documents", 'ext:doc | ext:docx "confidential"'),
                    "17": ("SQL dumps", 'filetype:sql "insert into"'),
                    "18": ("Database backups", 'ext:sql "dump"'),
                    "19": ("CSV data files", 'filetype:csv "password" | "username"'),
                    "20": ("XML config files", 'filetype:xml "password"'),
                }
            },
            "2": {
                "category": "Credentials & Secrets",
                "icon": "🔑",
                "dorks": {
                    "1": ("Passwords in documents", 'ext:doc | ext:docx intext:"password"'),
                    "2": ("Credentials in logs", 'intext:"username" intext:"password" ext:log'),
                    "3": ("Database credentials", 'filetype:env "DB_PASSWORD"'),
                    "4": ("MySQL credentials", 'intext:"mysql_connect" "password"'),
                    "5": ("PostgreSQL credentials", 'ext:sql "postgresql" "password"'),
                    "6": ("MongoDB credentials", 'intext:"mongodb" "password"'),
                    "7": ("Redis credentials", 'intext:"redis" "password"'),
                    "8": ("API keys", 'filetype:env "API_KEY" | "API_SECRET"'),
                    "9": ("AWS Access Keys", 'intext:"aws_access_key_id"'),
                    "10": ("AWS Secret Keys", 'intext:"aws_secret_access_key"'),
                    "11": ("Google API Keys", 'intext:"AIza" | "google api key"'),
                    "12": ("Stripe API Keys", 'intext:"sk_live_" | "pk_live_"'),
                    "13": ("PayPal credentials", 'intext:"paypal" ext:env'),
                    "14": ("SSH private keys", 'filetype:pem "BEGIN RSA PRIVATE KEY"'),
                    "15": ("PGP private keys", 'filetype:asc "BEGIN PGP PRIVATE KEY"'),
                    "16": ("Git credentials", 'filetype:.git-credentials'),
                    "17": ("FTP credentials", 'filetype:config "ftp" "password"'),
                    "18": ("SMTP credentials", 'intext:"smtp_password"'),
                    "19": ("Email passwords", 'ext:env "MAIL_PASSWORD"'),
                    "20": ("JWT secrets", 'intext:"jwt_secret" | "JWT_SECRET"'),
                    "21": ("OAuth tokens", 'intext:"oauth_token"'),
                    "22": ("Bearer tokens", 'intext:"Bearer" ext:log'),
                    "23": ("Session tokens", 'intext:"session_token"'),
                    "24": ("Cookie secrets", 'intext:"cookie_secret"'),
                    "25": ("Encryption keys", 'intext:"encryption_key" ext:env'),
                }
            },
            "3": {
                "category": "Cloud Storage & Services",
                "icon": "☁️",
                "dorks": {
                    "1": ("AWS S3 Buckets", 'site:s3.amazonaws.com'),
                    "2": ("Open S3 Buckets", 'site:s3.amazonaws.com intitle:"index of"'),
                    "3": ("Azure Blobs", 'site:blob.core.windows.net'),
                    "4": ("Google Cloud Storage", 'site:storage.googleapis.com'),
                    "5": ("DigitalOcean Spaces", 'site:digitaloceanspaces.com'),
                    "6": ("Google Drives", 'site:drive.google.com'),
                    "7": ("Dropbox shares", 'site:dropbox.com/s/'),
                    "8": ("OneDrive shares", 'site:onedrive.live.com'),
                    "9": ("Box.com shares", 'site:box.com/s/'),
                    "10": ("iCloud shares", 'site:icloud.com'),
                    "11": ("Firebase databases", 'site:firebaseio.com'),
                    "12": ("AWS EC2 instances", 'inurl:".compute.amazonaws.com"'),
                    "13": ("Heroku apps", 'site:herokuapp.com'),
                    "14": ("Azure websites", 'site:azurewebsites.net'),
                    "15": ("GCP instances", 'site:appspot.com'),
                }
            },
            "4": {
                "category": "Vulnerable Systems & Panels",
                "icon": "🔓",
                "dorks": {
                    "1": ("phpMyAdmin panels", 'intitle:"phpMyAdmin" "Welcome to phpMyAdmin"'),
                    "2": ("cPanel login", 'intitle:"cPanel" "login"'),
                    "3": ("Plesk panels", 'intitle:"Plesk" "login"'),
                    "4": ("WHM panels", 'intitle:"WHM" "login"'),
                    "5": ("Webmin panels", 'intitle:"Webmin" "login"'),
                    "6": ("Open cameras", 'inurl:"/view/view.shtml"'),
                    "7": ("Webcam viewers", 'intitle:"webcamXP 5"'),
                    "8": ("IP cameras", 'inurl:"viewerframe?mode="'),
                    "9": ("DVR systems", 'intitle:"DVR Login"'),
                    "10": ("NVR systems", 'intitle:"Network Video Recorder"'),
                    "11": ("Network devices", 'intitle:"index of" "parent directory" "cisco"'),
                    "12": ("Admin panels", 'intitle:"Admin Panel" | intitle:"Administration"'),
                    "13": ("Login portals", 'intitle:"Login" | intitle:"Sign in"'),
                    "14": ("Directory listings", 'intitle:"index of /" "parent directory"'),
                    "15": ("Exposed dashboards", 'intitle:"Dashboard" -github -gitlab'),
                    "16": ("Apache status pages", 'intitle:"Apache Status" "Server Version"'),
                    "17": ("Nginx status", 'intitle:"nginx status"'),
                    "18": ("Router admin", 'intitle:"Router" "login"'),
                    "19": ("Modem admin", 'intitle:"Modem" "configuration"'),
                    "20": ("Printer admin", 'intitle:"Printer" "configuration"'),
                }
            },
            "5": {
                "category": "Database Errors & Exposures",
                "icon": "🗄️",
                "dorks": {
                    "1": ("MySQL errors", 'intext:"mysql_fetch" | "mysql_connect"'),
                    "2": ("SQL syntax errors", 'intext:"SQL syntax" | "mysql error"'),
                    "3": ("PostgreSQL errors", 'intext:"PostgreSQL query failed"'),
                    "4": ("MSSQL errors", 'intext:"Microsoft OLE DB Provider for SQL Server"'),
                    "5": ("Oracle errors", 'intext:"ORA-" "SQL command not properly ended"'),
                    "6": ("MongoDB errors", 'intext:"MongoError" | "MongoDB server"'),
                    "7": ("SQLite errors", 'intext:"SQLite error"'),
                    "8": ("PHP errors", 'intext:"Warning: mysql_" -site:github.com'),
                    "9": ("ASP errors", 'intext:"Microsoft OLE DB Provider"'),
                    "10": ("JSP errors", 'intext:"java.sql.SQLException"'),
                    "11": ("JDBC errors", 'intext:"JDBC" "SQLException"'),
                    "12": ("Warning messages", 'intext:"Warning:" "on line" ext:php'),
                    "13": ("Fatal errors", 'intext:"Fatal error:" ext:php'),
                    "14": ("Stack traces", 'intext:"Stack trace:" -site:github.com'),
                    "15": ("Exception errors", 'intext:"Uncaught exception"'),
                }
            },
            "6": {
                "category": "Configuration Files",
                "icon": "⚙️",
                "dorks": {
                    "1": ("PHP config", 'ext:php intext:"$_ENV" | intext:"$_CONFIG"'),
                    "2": ("Apache config", 'filetype:conf intext:"apache"'),
                    "3": ("Nginx config", 'filetype:conf intext:"nginx"'),
                    "4": ("Environment files", 'filetype:env "DATABASE_URL"'),
                    "5": (".env files", 'ext:env "APP_KEY"'),
                    "6": ("Docker compose", 'filetype:yml "docker-compose"'),
                    "7": ("Kubernetes configs", 'filetype:yaml "apiVersion" "kind"'),
                    "8": ("CI/CD configs", 'filetype:yml "gitlab-ci" | "github/workflows"'),
                    "9": ("Jenkins configs", 'filetype:xml "jenkins"'),
                    "10": ("Travis CI", 'filetype:yml "travis"'),
                    "11": ("CircleCI", 'filetype:yml "circleci"'),
                    "12": ("Ansible playbooks", 'filetype:yml "ansible"'),
                    "13": ("Terraform configs", 'ext:tf "provider"'),
                    "14": ("Vagrant files", 'filetype:vagrantfile'),
                    "15": ("Composer configs", 'filetype:json "composer"'),
                    "16": ("NPM configs", 'filetype:json "package.json" "scripts"'),
                    "17": ("Pip requirements", 'filetype:txt "requirements.txt"'),
                    "18": ("Gemfile", 'filetype:gemfile'),
                    "19": ("Maven POM", 'filetype:xml "pom.xml"'),
                    "20": ("Gradle configs", 'ext:gradle'),
                }
            },
            "7": {
                "category": "Backup & Archive Files",
                "icon": "💾",
                "dorks": {
                    "1": ("SQL backups", 'ext:sql "INSERT INTO"'),
                    "2": ("Backup archives", 'ext:bak | ext:backup | ext:old'),
                    "3": ("Database dumps", 'ext:dump | ext:sql'),
                    "4": ("Zip backups", 'ext:zip "backup"'),
                    "5": ("Tar archives", 'ext:tar | ext:tar.gz "backup"'),
                    "6": ("RAR archives", 'ext:rar "backup"'),
                    "7": ("7z archives", 'ext:7z "backup"'),
                    "8": ("Gzip files", 'ext:gz "backup"'),
                    "9": ("Bzip files", 'ext:bz2 "backup"'),
                    "10": ("Old files", 'ext:old inurl:backup'),
                    "11": ("Temp files", 'ext:tmp inurl:backup'),
                    "12": ("Swap files", 'ext:swp'),
                    "13": ("Log files", 'ext:log "password" | "username"'),
                    "14": ("Cache files", 'ext:cache'),
                    "15": ("Backup databases", 'inurl:backup ext:sql'),
                }
            },
            "8": {
                "category": "OSINT & Social Engineering",
                "icon": "🔍",
                "dorks": {
                    "1": ("Email addresses", 'intext:"@gmail.com" | "@yahoo.com"'),
                    "2": ("Corporate emails", 'intext:"@company.com"'),
                    "3": ("Phone numbers", 'intext:"+1" | intext:"phone:"'),
                    "4": ("Mobile numbers", 'intext:"mobile:" | intext:"cell:"'),
                    "5": ("Address info", 'intext:"address:" | intext:"location:"'),
                    "6": ("LinkedIn profiles", 'site:linkedin.com intitle:"[target]"'),
                    "7": ("Twitter accounts", 'site:twitter.com "[target]"'),
                    "8": ("Facebook pages", 'site:facebook.com "[target]"'),
                    "9": ("Instagram profiles", 'site:instagram.com "[target]"'),
                    "10": ("GitHub profiles", 'site:github.com "[target]"'),
                    "11": ("Pastebin leaks", 'site:pastebin.com "[target]"'),
                    "12": ("Reddit posts", 'site:reddit.com "[target]"'),
                    "13": ("Stack Overflow", 'site:stackoverflow.com "[target]"'),
                    "14": ("Telegram groups", 'site:t.me/joinchat/'),
                    "15": ("Discord invites", 'site:discord.com/invite | site:discord.gg'),
                    "16": ("Slack workspaces", 'site:slack.com "[target]"'),
                    "17": ("Trello boards", 'site:trello.com "[target]"'),
                    "18": ("Asana projects", 'site:asana.com "[target]"'),
                    "19": ("Notion pages", 'site:notion.so "[target]"'),
                    "20": ("Resumes/CVs", 'filetype:pdf "resume" | "curriculum vitae"'),
                }
            },
            "9": {
                "category": "Network Infrastructure",
                "icon": "🌐",
                "dorks": {
                    "1": ("Subdomains", 'site:*.example.com'),
                    "2": ("FTP servers", 'inurl:ftp -inurl:http -inurl:https'),
                    "3": ("SFTP servers", 'inurl:sftp'),
                    "4": ("VPN portals", 'intitle:"vpn" | "ssl vpn"'),
                    "5": ("Citrix gateways", 'intitle:"Citrix" "login"'),
                    "6": ("FortiGate SSL VPN", 'intitle:"FortiGate"'),
                    "7": ("Router configs", 'intitle:"router" "login"'),
                    "8": ("Switch configs", 'intitle:"switch" "configuration"'),
                    "9": ("Firewall rules", 'filetype:conf "firewall"'),
                    "10": ("Network diagrams", 'filetype:pdf "network topology"'),
                    "11": ("DNS records", 'filetype:txt "DNS"'),
                    "12": ("IP ranges", 'filetype:txt "IP range"'),
                    "13": ("WHOIS data", 'site:whois.com'),
                    "14": ("SSL certificates", 'filetype:crt | filetype:pem'),
                    "15": ("Proxy servers", 'inurl:proxy "port"'),
                }
            },
            "10": {
                "category": "Web Vulnerabilities",
                "icon": "🐛",
                "dorks": {
                    "1": ("Open redirects", 'inurl:redir | inurl:redirect | inurl:return'),
                    "2": ("XSS vulnerable", 'inurl:id= | inurl:page= | inurl:cat='),
                    "3": ("SQL injection", 'inurl:index.php?id='),
                    "4": ("LFI vulnerable", 'inurl:file= | inurl:path= | inurl:page='),
                    "5": ("RFI vulnerable", 'inurl:include= | inurl:require='),
                    "6": ("Upload forms", 'intitle:"upload" | "file upload"'),
                    "7": ("phpinfo exposed", 'ext:php intext:"phpinfo()"'),
                    "8": ("Git exposed", 'inurl:".git" intitle:"index of"'),
                    "9": ("SVN exposed", 'inurl:".svn" intitle:"index of"'),
                    "10": ("Swagger/API docs", 'intitle:"swagger" | "api documentation"'),
                    "11": ("GraphQL endpoints", 'inurl:graphql | inurl:graphiql'),
                    "12": ("WSDL files", 'filetype:wsdl'),
                    "13": ("WADL files", 'filetype:wadl'),
                    "14": ("README files", 'intitle:"index of" "readme"'),
                    "15": ("Changelog files", 'intitle:"index of" "changelog"'),
                    "16": ("Backup files", 'inurl:backup | inurl:back | inurl:bak'),
                    "17": ("Test files", 'inurl:test | inurl:testing'),
                    "18": ("Debug pages", 'inurl:debug'),
                    "19": ("Development files", 'inurl:dev | inurl:development'),
                    "20": ("Staging servers", 'inurl:staging | inurl:stage'),
                }
            },
            "11": {
                "category": "IoT & Smart Devices",
                "icon": "📡",
                "dorks": {
                    "1": ("IP Cameras", 'inurl:"/view.shtml" | inurl:"/ViewerFrame"'),
                    "2": ("Webcams", 'intitle:"webcamXP"'),
                    "3": ("Printers HP", 'intitle:"HP" "printer" "status"'),
                    "4": ("Printers Canon", 'intitle:"Canon" "printer"'),
                    "5": ("Printers Epson", 'intitle:"Epson" "printer"'),
                    "6": ("SCADA systems", 'intitle:"SCADA" | "HMI"'),
                    "7": ("Smart home hubs", 'inurl:8080 "smart home"'),
                    "8": ("DVR/NVR", 'intitle:"DVR" | "Network Video Recorder"'),
                    "9": ("Solar panels", 'intitle:"solar" "monitoring"'),
                    "10": ("Wind turbines", 'intitle:"wind turbine" "monitoring"'),
                    "11": ("Building automation", 'intitle:"building" "automation"'),
                    "12": ("Elevator controls", 'intitle:"elevator" "control"'),
                    "13": ("HVAC systems", 'intitle:"HVAC" "control"'),
                    "14": ("Smart meters", 'intitle:"smart meter"'),
                    "15": ("Raspberry Pi", 'intitle:"raspberry pi"'),
                }
            },
            "12": {
                "category": "Security Tools & Reports",
                "icon": "🛡️",
                "dorks": {
                    "1": ("Nessus reports", 'intitle:"Nessus Scan Report"'),
                    "2": ("Metasploit", 'filetype:rc "use exploit"'),
                    "3": ("Nmap scans", 'filetype:xml "nmap"'),
                    "4": ("Burp reports", 'filetype:html "Burp Suite"'),
                    "5": ("Wireshark captures", 'filetype:pcap'),
                    "6": ("OWASP ZAP", 'intitle:"ZAP Scanning Report"'),
                    "7": ("Nikto scans", 'filetype:txt "Nikto"'),
                    "8": ("OpenVAS reports", 'filetype:xml "openvas"'),
                    "9": ("Acunetix scans", 'intitle:"Acunetix"'),
                    "10": ("Qualys reports", 'intitle:"Qualys"'),
                }
            },
            "13": {
                "category": "CMS & Frameworks",
                "icon": "🎨",
                "dorks": {
                    "1": ("WordPress sites", 'inurl:wp-content | inurl:wp-includes'),
                    "2": ("WordPress admin", 'inurl:wp-admin'),
                    "3": ("WordPress config", 'filetype:php "wp-config"'),
                    "4": ("Joomla sites", 'inurl:joomla | "powered by joomla"'),
                    "5": ("Drupal sites", 'inurl:drupal | "powered by drupal"'),
                    "6": ("Magento shops", 'inurl:magento | "Magento"'),
                    "7": ("PrestaShop", 'inurl:prestashop'),
                    "8": ("OpenCart", 'inurl:opencart'),
                    "9": ("Shopify stores", 'site:myshopify.com'),
                    "10": ("Laravel apps", 'intitle:"Laravel"'),
                    "11": ("Django apps", 'intitle:"Django"'),
                    "12": ("Ruby on Rails", 'ext:rb "Rails"'),
                    "13": ("ASP.NET sites", 'ext:aspx'),
                    "14": ("JSP sites", 'ext:jsp'),
                    "15": ("Node.js apps", 'inurl:node'),
                }
            },
            "14": {
                "category": "E-commerce & Payment",
                "icon": "💳",
                "dorks": {
                    "1": ("Payment pages", 'inurl:payment | inurl:checkout'),
                    "2": ("Credit card forms", 'intext:"credit card" inurl:payment'),
                    "3": ("PayPal integrations", 'inurl:paypal'),
                    "4": ("Stripe integrations", 'inurl:stripe'),
                    "5": ("Shopping carts", 'inurl:cart | inurl:basket'),
                    "6": ("Order forms", 'inurl:order'),
                    "7": ("Invoice systems", 'inurl:invoice'),
                    "8": ("Billing portals", 'inurl:billing'),
                    "9": ("Customer portals", 'inurl:customer | inurl:account'),
                    "10": ("Membership sites", 'inurl:member | inurl:subscription'),
                }
            },
            "15": {
                "category": "Code Repositories & Version Control",
                "icon": "💻",
                "dorks": {
                    "1": ("GitHub repos", 'site:github.com "password"'),
                    "2": ("GitLab repos", 'site:gitlab.com "password"'),
                    "3": ("Bitbucket repos", 'site:bitbucket.org'),
                    "4": (".git folders", 'intitle:"index of" ".git"'),
                    "5": (".svn folders", 'intitle:"index of" ".svn"'),
                    "6": (".env in GitHub", 'site:github.com ".env"'),
                    "7": ("API keys GitHub", 'site:github.com "api_key" | "apikey"'),
                    "8": ("AWS keys GitHub", 'site:github.com "aws_access_key_id"'),
                    "9": ("Private keys GitHub", 'site:github.com "BEGIN RSA PRIVATE KEY"'),
                    "10": ("Database creds GitHub", 'site:github.com "db_password"'),
                }
            },
            "16": {
                "category": "Government & Education",
                "icon": "🏛️",
                "dorks": {
                    "1": ("Gov sites", 'site:gov'),
                    "2": ("Gov PDFs", 'site:gov filetype:pdf'),
                    "3": ("Gov databases", 'site:gov ext:sql'),
                    "4": ("Gov emails", 'site:gov intext:"@"'),
                    "5": ("Edu sites", 'site:edu'),
                    "6": ("Edu PDFs", 'site:edu filetype:pdf'),
                    "7": ("Research papers", 'site:edu filetype:pdf "research"'),
                    "8": ("Thesis documents", 'site:edu filetype:pdf "thesis"'),
                    "9": ("Gov portals", 'site:gov inurl:login'),
                    "10": ("Edu portals", 'site:edu inurl:login'),
                }
            },
            "17": {
                "category": "Healthcare & Medical",
                "icon": "🏥",
                "dorks": {
                    "1": ("Medical records", 'filetype:xls | filetype:xlsx "patient"'),
                    "2": ("HIPAA documents", 'filetype:pdf "HIPAA"'),
                    "3": ("Medical databases", 'intext:"patient" ext:sql'),
                    "4": ("Prescription data", 'intext:"prescription" filetype:xls'),
                    "5": ("Lab results", 'intext:"lab results" filetype:pdf'),
                }
            },
            "18": {
                "category": "Financial & Legal",
                "icon": "💰",
                "dorks": {
                    "1": ("Financial reports", 'filetype:pdf "financial report"'),
                    "2": ("Bank statements", 'filetype:pdf "bank statement"'),
                    "3": ("Tax documents", 'filetype:pdf "tax return"'),
                    "4": ("Legal contracts", 'filetype:pdf "contract"'),
                    "5": ("NDA documents", 'filetype:pdf "NDA" | "non-disclosure"'),
                    "6": ("Invoices", 'filetype:xls "invoice"'),
                    "7": ("Payroll data", 'filetype:xls "payroll"'),
                    "8": ("Budget sheets", 'filetype:xls "budget"'),
                    "9": ("Audit reports", 'filetype:pdf "audit"'),
                    "10": ("Compliance docs", 'filetype:pdf "compliance"'),
                }
            },
            "19": {
                "category": "Email & Communication",
                "icon": "📧",
                "dorks": {
                    "1": ("Email lists", 'filetype:csv "email"'),
                    "2": ("Mailing lists", 'filetype:txt "mailing list"'),
                    "3": ("Contact databases", 'filetype:xls "contacts"'),
                    "4": ("Outlook files", 'filetype:pst'),
                    "5": ("Thunderbird files", 'filetype:mbox'),
                    "6": ("Webmail logins", 'inurl:webmail "login"'),
                    "7": ("Roundcube", 'intitle:"Roundcube Webmail"'),
                    "8": ("SquirrelMail", 'intitle:"SquirrelMail"'),
                    "9": ("Horde webmail", 'intitle:"Horde"'),
                    "10": ("Zimbra webmail", 'intitle:"Zimbra"'),
                }
            },
            "20": {
                "category": "Miscellaneous & Advanced",
                "icon": "🔬",
                "dorks": {
                    "1": ("Zoom recordings", 'site:zoom.us inurl:rec'),
                    "2": ("Google Docs", 'site:docs.google.com'),
                    "3": ("Google Sheets", 'site:sheets.google.com'),
                    "4": ("Google Forms", 'site:forms.google.com'),
                    "5": ("Microsoft Forms", 'site:forms.office.com'),
                    "6": ("SurveyMonkey", 'site:surveymonkey.com'),
                    "7": ("Typeform surveys", 'site:typeform.com'),
                    "8": ("Calendly bookings", 'site:calendly.com'),
                    "9": ("Airtable bases", 'site:airtable.com'),
                    "10": ("Coda docs", 'site:coda.io'),
                    "11": ("Figma designs", 'site:figma.com'),
                    "12": ("Miro boards", 'site:miro.com'),
                    "13": ("Canva designs", 'site:canva.com'),
                    "14": ("Prezi presentations", 'site:prezi.com'),
                    "15": ("Slideshare decks", 'site:slideshare.net'),
                    "16": ("Scribd documents", 'site:scribd.com'),
                    "17": ("Issuu publications", 'site:issuu.com'),
                    "18": ("Archive.org", 'site:archive.org'),
                    "19": ("Wayback Machine", 'site:web.archive.org'),
                    "20": ("Google Cache", 'cache:'),
                }
            }
        }
    
    def print_banner(self):
        """Display enhanced Kali-styled banner"""
        banner = f"""
{Colors.OKCYAN}╔═══════════════════════════════════════════════════════════════╗
║  {Colors.BOLD}   ██████╗  ██████╗ ██████╗ ██╗  ██╗    ████████╗ ██████╗  ██████╗ ██╗     {Colors.ENDC}{Colors.OKCYAN}║
║  {Colors.BOLD}   ██╔══██╗██╔═══██╗██╔══██╗██║ ██╔╝    ╚══██╔══╝██╔═══██╗██╔═══██╗██║     {Colors.ENDC}{Colors.OKCYAN}║
║  {Colors.BOLD}   ██║  ██║██║   ██║██████╔╝█████╔╝        ██║   ██║   ██║██║   ██║██║     {Colors.ENDC}{Colors.OKCYAN}║
║  {Colors.BOLD}   ██║  ██║██║   ██║██╔══██╗██╔═██╗        ██║   ██║   ██║██║   ██║██║     {Colors.ENDC}{Colors.OKCYAN}║
║  {Colors.BOLD}   ██████╔╝╚██████╔╝██║  ██║██║  ██╗       ██║   ╚██████╔╝╚██████╔╝███████╗{Colors.ENDC}{Colors.OKCYAN}║
║  {Colors.BOLD}   ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝       ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝{Colors.ENDC}{Colors.OKCYAN}║
╠═══════════════════════════════════════════════════════════════╣
║    {Colors.BOLD}Ultimate Google Dorking Tool - 500+ Dorks Database{Colors.ENDC}{Colors.OKCYAN}    ║
║              {Colors.WARNING}For Authorized Pentesting Only{Colors.ENDC}{Colors.OKCYAN}               ║
╚═══════════════════════════════════════════════════════════════╝{Colors.ENDC}

{Colors.OKGREEN}[*] System: Kali Linux
[*] Browser: {self.browser}
[*] Search Engine: {self.search_engine}
[*] Smart Mode: {"ENABLED" if self.smart_mode else "DISABLED"}
[*] Total Dorks: 500+
[*] Output Dir: {self.output_dir}{Colors.ENDC}

{Colors.WARNING}⚠️  WARNING: Use only for authorized security testing!{Colors.ENDC}
"""
        print(banner)
    
    def print_success(self, msg: str):
        print(f"{Colors.OKGREEN}[✓] {msg}{Colors.ENDC}")
    
    def print_error(self, msg: str):
        print(f"{Colors.FAIL}[✗] {msg}{Colors.ENDC}")
    
    def print_info(self, msg: str):
        print(f"{Colors.OKBLUE}[i] {msg}{Colors.ENDC}")
    
    def print_warning(self, msg: str):
        print(f"{Colors.WARNING}[!] {msg}{Colors.ENDC}")
    
    def detect_browser(self) -> bool:
        """Detect available browser"""
        for browser, info in self.browsers.items():
            try:
                result = subprocess.run(['which', info['cmd']], 
                                      capture_output=True, 
                                      text=True)
                if result.returncode == 0:
                    self.browser = browser
                    return True
            except:
                continue
        return False
    
    def open_url(self, url: str) -> bool:
        """Open URL in browser"""
        if self.browser not in self.browsers:
            self.print_error(f"Browser '{self.browser}' not configured!")
            return False
        
        browser_info = self.browsers[self.browser]
        cmd = [browser_info['cmd']]
        
        if self.incognito and browser_info['incognito']:
            cmd.append(browser_info['incognito'])
        
        cmd.append(url)
        
        try:
            subprocess.Popen(cmd, 
                           stdout=subprocess.DEVNULL, 
                           stderr=subprocess.DEVNULL,
                           start_new_session=True)
            return True
        except Exception as e:
            self.print_error(f"Failed to open browser: {e}")
            return False
    
    def build_search_url(self, query: str) -> str:
        """Build search URL"""
        import urllib.parse
        
        if self.search_engine not in self.search_engines:
            self.search_engine = "google"
        
        base_url = self.search_engines[self.search_engine]
        encoded_query = urllib.parse.quote_plus(query)
        
        return base_url + encoded_query
    
    def smart_search(self):
        """Smart search with auto-detection"""
        print(f"\n{Colors.HEADER}{'='*65}")
        print("SMART SEARCH MODE - AI AUTO-DETECTION")
        print(f"{'='*65}{Colors.ENDC}\n")
        
        print(f"{Colors.OKCYAN}Examples:{Colors.ENDC}")
        print(f"  • cyber.pdf          → Auto: filetype:pdf \"cybersecurity\"")
        print(f"  • passwords.sql      → Auto: filetype:sql \"passwords\"")
        print(f"  • example.com        → Auto: site:example.com")
        print(f"  • admin.log          → Auto: ext:log \"admin\"")
        print(f"  • config.env         → Auto: filetype:env \"config\"")
        print(f"  • 192.168.1.1        → Auto: \"192.168.1.1\"")
        print(f"  • cybersecurity      → Search keyword\n")
        
        user_input = input(f"{Colors.OKGREEN}Enter search query: {Colors.ENDC}").strip()
        
        if not user_input:
            self.print_warning("Empty input!")
            return
        
        # Parse input
        result = self.parser.parse_input(user_input)
        
        print(f"\n{Colors.HEADER}{'='*65}")
        print("AI DETECTION RESULTS")
        print(f"{'='*65}{Colors.ENDC}\n")
        
        self.print_info(f"Input Type: {Colors.BOLD}{result['type'].upper()}{Colors.ENDC}")
        
        if result['keyword']:
            self.print_info(f"Keyword: {Colors.BOLD}{result['keyword']}{Colors.ENDC}")
        if result['filetype']:
            self.print_info(f"File Type: {Colors.BOLD}{result['filetype']}{Colors.ENDC}")
        if result['domain']:
            self.print_info(f"Domain: {Colors.BOLD}{result['domain']}{Colors.ENDC}")
        
        print(f"\n{Colors.OKCYAN}Generated Dorks:{Colors.ENDC}\n")
        
        for idx, dork in enumerate(result['dorks'][:15], 1):
            marker = f"{Colors.OKGREEN}[AUTO]{Colors.ENDC}" if dork == result['auto_selected'] else "     "
            print(f"{marker} [{idx}] {dork}")
        
        print(f"\n{Colors.WARNING}[0] Cancel{Colors.ENDC}")
        print(f"{Colors.OKGREEN}[Enter] Use auto-selected dork{Colors.ENDC}")
        print(f"{Colors.OKCYAN}[A] Execute ALL dorks{Colors.ENDC}")
        
        choice = input(f"\n{Colors.OKGREEN}Select dork (or Enter for auto): {Colors.ENDC}").strip()
        
        if choice == '0':
            return
        elif choice.upper() == 'A':
            # Execute all dorks
            confirm = input(f"{Colors.WARNING}Execute {len(result['dorks'])} dorks? (y/n): {Colors.ENDC}").strip().lower()
            if confirm == 'y':
                for idx, dork in enumerate(result['dorks'], 1):
                    print(f"\n{Colors.OKCYAN}[{idx}/{len(result['dorks'])}]{Colors.ENDC}")
                    self.execute_dork(dork, f"Smart: {user_input}")
                    if idx < len(result['dorks']):
                        time.sleep(self.delay)
        elif choice == '' or not choice:
            # Use auto-selected
            if result['auto_selected']:
                self.execute_dork(result['auto_selected'], f"Smart: {user_input}")
            else:
                self.print_warning("No auto-selection available!")
        elif choice.isdigit() and 0 < int(choice) <= len(result['dorks'][:15]):
            selected_dork = result['dorks'][int(choice) - 1]
            self.execute_dork(selected_dork, f"Smart: {user_input}")
        else:
            self.print_error("Invalid selection!")
    
    def execute_dork(self, dork: str, name: str = "Custom"):
        """Execute a dork query"""
        url = self.build_search_url(dork)
        
        print(f"\n{Colors.HEADER}{'='*65}{Colors.ENDC}")
        self.print_info(f"Executing: {name}")
        self.print_info(f"Query: {dork[:70]}{'...' if len(dork) > 70 else ''}")
        self.print_info(f"Engine: {self.search_engine}")
        print(f"{Colors.OKCYAN}URL: {url[:80]}{'...' if len(url) > 80 else ''}{Colors.ENDC}")
        
        # Save to history
        entry = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "name": name,
            "dork": dork,
            "url": url,
            "engine": self.search_engine
        }
        self.search_history.append(entry)
        self.save_history()
        
        # Save to file
        self.save_dork_to_file(entry)
        
        if self.auto_open:
            if self.open_url(url):
                self.print_success("Opened in browser!")
            else:
                self.print_warning("Could not open browser")
                print(f"\n{Colors.OKBLUE}Manual URL: {url}{Colors.ENDC}")
        else:
            print(f"\n{Colors.OKBLUE}URL ready: {url}{Colors.ENDC}")
        
        return url
    
    def save_dork_to_file(self, entry: Dict):
        """Save dork execution to file"""
        timestamp = datetime.now().strftime("%Y%m%d")
        filename = self.output_dir / f"dorks_{timestamp}.txt"
        
        try:
            with open(filename, 'a') as f:
                f.write(f"{'='*65}\n")
                f.write(f"Timestamp: {entry['timestamp']}\n")
                f.write(f"Name: {entry['name']}\n")
                f.write(f"Engine: {entry['engine']}\n")
                f.write(f"Dork: {entry['dork']}\n")
                f.write(f"URL: {entry['url']}\n")
                f.write(f"{'='*65}\n\n")
        except Exception as e:
            self.print_error(f"Failed to save to file: {e}")
    
    def show_category(self, cat_key: str):
        """Show dorks in category with pagination"""
        if cat_key not in self.dorks:
            self.print_error("Invalid category!")
            return None
        
        cat = self.dorks[cat_key]
        dork_items = list(cat['dorks'].items())
        
        page = 0
        page_size = 10
        total_pages = (len(dork_items) + page_size - 1) // page_size
        
        while True:
            print(f"\n{Colors.HEADER}{'='*65}")
            print(f"{cat['icon']} {cat['category']} - Page {page + 1}/{total_pages}")
            print(f"{'='*65}{Colors.ENDC}\n")
            
            start = page * page_size
            end = min(start + page_size, len(dork_items))
            
            for key, (name, dork) in dork_items[start:end]:
                print(f"{Colors.OKGREEN}[{key}]{Colors.ENDC} {name}")
                print(f"    {Colors.OKCYAN}{dork[:75]}{'...' if len(dork) > 75 else ''}{Colors.ENDC}\n")
            
            print(f"\n{Colors.WARNING}[N] Next Page  [P] Previous Page  [0] Back{Colors.ENDC}")
            
            choice = input(f"\n{Colors.OKGREEN}Select dork or action: {Colors.ENDC}").strip().upper()
            
            if choice == '0':
                return None
            elif choice == 'N' and page < total_pages - 1:
                page += 1
            elif choice == 'P' and page > 0:
                page -= 1
            elif choice.isdigit() and choice in cat['dorks']:
                name, dork = cat['dorks'][choice]
                
                customize = input(f"\n{Colors.OKGREEN}Customize? (y/n): {Colors.ENDC}").strip().lower()
                if customize == 'y':
                    dork = self.customize_dork(dork)
                
                self.execute_dork(dork, name)
                input(f"\n{Colors.OKCYAN}Press Enter to continue...{Colors.ENDC}")
    
    def customize_dork(self, dork: str) -> str:
        """Customize dork with user input"""
        print(f"\n{Colors.OKCYAN}Original: {dork}{Colors.ENDC}\n")
        
        placeholders = {
            'example.com': 'target domain',
            '{company_name}': 'company name',
            '{company name}': 'company name',
            'keyword': 'keyword',
            '[target]': 'target'
        }
        
        custom_dork = dork
        for placeholder, description in placeholders.items():
            if placeholder in custom_dork:
                value = input(f"{Colors.OKGREEN}Enter {description}: {Colors.ENDC}").strip()
                if value:
                    custom_dork = custom_dork.replace(placeholder, value)
        
        print(f"\n{Colors.OKGREEN}Customized: {custom_dork}{Colors.ENDC}")
        return custom_dork
    
    def print_menu(self):
        """Display comprehensive main menu"""
        menu = f"""
{Colors.HEADER}{'='*65}
                    MAIN MENU - 500+ DORKS
{'='*65}{Colors.ENDC}

{Colors.OKCYAN}[SMART FEATURES]{Colors.ENDC}
  [S] 🧠 Smart Search (AI Auto-detect)
  [Q] ⚡ Quick Patterns

{Colors.OKCYAN}[DORK CATEGORIES - 20 Categories]{Colors.ENDC}
  [1]  📁 File Discovery (20 dorks)
  [2]  🔑 Credentials & Secrets (25 dorks)
  [3]  ☁️  Cloud Storage (15 dorks)
  [4]  🔓 Vulnerable Systems (20 dorks)
  [5]  🗄️  Database Errors (15 dorks)
  [6]  ⚙️  Configuration Files (20 dorks)
  [7]  💾 Backup Files (15 dorks)
  [8]  🔍 OSINT & Social (20 dorks)
  [9]  🌐 Network Infrastructure (15 dorks)
  [10] 🐛 Web Vulnerabilities (20 dorks)
  [11] 📡 IoT & Smart Devices (15 dorks)
  [12] 🛡️  Security Tools (10 dorks)
  [13] 🎨 CMS & Frameworks (15 dorks)
  [14] 💳 E-commerce & Payment (10 dorks)
  [15] 💻 Code Repositories (10 dorks)
  [16] 🏛️  Government & Education (10 dorks)
  [17] 🏥 Healthcare & Medical (5 dorks)
  [18] 💰 Financial & Legal (10 dorks)
  [19] 📧 Email & Communication (10 dorks)
  [20] 🔬 Miscellaneous (20 dorks)

{Colors.OKCYAN}[TOOLS]{Colors.ENDC}
  [30] ⚙️  Settings
  [31] 📜 History
  [32] 🚀 Batch Execute
  [33] 💾 Export Results
  [34] ℹ️  Help
  [0]  🚪 Exit
"""
        print(menu)
    
    def quick_patterns(self):
        """Quick access to common patterns"""
        print(f"\n{Colors.HEADER}{'='*65}")
        print("QUICK PATTERNS - INSTANT DORKING")
        print(f"{'='*65}{Colors.ENDC}\n")
        
        patterns = {
            "1": ("PDF Files", ".pdf"),
            "2": ("Word Documents", ".doc"),
            "3": ("Excel Files", ".xls"),
            "4": ("SQL Files", ".sql"),
            "5": ("Log Files", ".log"),
            "6": ("Config Files", ".conf"),
            "7": ("Environment Files", ".env"),
            "8": ("Backup Files", ".bak"),
            "9": ("PHP Files", ".php"),
            "10": ("Python Scripts", ".py"),
            "11": ("JavaScript Files", ".js"),
            "12": ("JSON Files", ".json"),
            "13": ("XML Files", ".xml"),
            "14": ("Certificate Files", ".pem"),
            "15": ("Domain Search", "domain"),
            "16": ("Admin Pages", "admin"),
            "17": ("Login Pages", "login"),
            "18": ("API Endpoints", "api"),
        }
        
        for key, (name, pattern) in patterns.items():
            print(f"[{key}] {name}")
        
        print(f"\n[0] Back")
        
        choice = input(f"\n{Colors.OKGREEN}Select pattern: {Colors.ENDC}").strip()
        
        if choice == '0':
            return
        
        if choice in patterns:
            name, pattern = patterns[choice]
            
            if pattern == "domain":
                domain = input(f"{Colors.OKGREEN}Enter domain: {Colors.ENDC}").strip()
                smart_input = domain
            elif pattern in ["admin", "login", "api"]:
                smart_input = pattern
            else:
                keyword = input(f"{Colors.OKGREEN}Enter keyword: {Colors.ENDC}").strip()
                smart_input = f"{keyword}{pattern}"
            
            # Use smart parser
            result = self.parser.parse_input(smart_input)
            
            if result['auto_selected']:
                print(f"\n{Colors.OKGREEN}Auto-generated: {result['auto_selected']}{Colors.ENDC}")
                confirm = input(f"Execute? (y/n): ").strip().lower()
                
                if confirm == 'y':
                    self.execute_dork(result['auto_selected'], f"Quick: {name}")
    
    def show_help(self):
        """Display comprehensive help"""
        help_text = f"""
{Colors.HEADER}{'='*65}
                     ULTIMATE DORK TOOL HELP
{'='*65}{Colors.ENDC}

{Colors.OKCYAN}📚 DATABASE OVERVIEW:{Colors.ENDC}
  • 500+ Pre-loaded Google Dorks
  • 20 Specialized Categories
  • Smart AI Auto-Detection
  • Multi-Engine Support

{Colors.OKCYAN}🧠 SMART SEARCH EXAMPLES:{Colors.ENDC}

{Colors.OKGREEN}1. File Type Detection:{Colors.ENDC}
   Input: cyber.pdf      → Auto: filetype:pdf "cyber"
   Input: passwords.sql  → Auto: filetype:sql "passwords"
   Input: config.env     → Auto: filetype:env "config"
   Input: secret.key     → Auto: filetype:key "secret"

{Colors.OKGREEN}2. Domain Detection:{Colors.ENDC}
   Input: example.com          → Auto: site:example.com
   Input: https://example.com  → Auto: site:example.com
   Input: 192.168.1.1          → Auto: "192.168.1.1"

{Colors.OKGREEN}3. Keyword Detection:{Colors.ENDC}
   Input: admin     → Auto: inurl:admin
   Input: password  → Auto: intext:"password"
   Input: api       → Auto: inurl:api

{Colors.OKCYAN}🎯 SUPPORTED FILE TYPES (40+):{Colors.ENDC}
  Documents:  .pdf .doc .docx .xls .xlsx .ppt .pptx
  Code:       .php .asp .jsp .py .rb .pl .js .java .c .cpp
  Config:     .conf .config .env .ini .cfg .yaml .yml
  Database:   .sql .db .sqlite .mdb .dbf
  Backup:     .bak .old .backup .dump
  Security:   .key .pem .crt .cer .p12 .pfx
  Network:    .pcap .log
  Archive:    .zip .tar .gz .rar .7z

{Colors.OKCYAN}🔍 SEARCH ENGINES:{Colors.ENDC}
  • Google (default)    • DuckDuckGo
  • Bing               • Shodan
  • Censys             • StartPage
  • Yandex             • Baidu

{Colors.OKCYAN}⚡ QUICK START:{Colors.ENDC}
  1. Press [S] for Smart Search
  2. Enter pattern (e.g., "cyber.pdf")
  3. Press [Enter] for instant results!

{Colors.OKCYAN}🛠️ ADVANCED FEATURES:{Colors.ENDC}
  • Batch execution with delays
  • History tracking & replay
  • Multi-format export (JSON, TXT)
  • Custom dork creation
  • Configuration persistence

{Colors.OKCYAN}📊 CATEGORY HIGHLIGHTS:{Colors.ENDC}
  • Credentials & Secrets: 25 dorks for finding passwords/keys
  • Cloud Storage: 15 dorks for AWS/Azure/GCP
  • OSINT: 20 dorks for social media intelligence
  • Web Vulnerabilities: 20 dorks for security testing
  • IoT Devices: 15 dorks for cameras/SCADA/smart devices

{Colors.WARNING}⚠️  LEGAL NOTICE:{Colors.ENDC}
  Only use for:
  ✓ Authorized penetration testing
  ✓ Bug bounty programs
  ✓ Educational purposes
  ✓ Your own systems

  ✗ Unauthorized access is ILLEGAL

{Colors.OKCYAN}💡 PRO TIPS:{Colors.ENDC}
  1. Always get authorization first
  2. Use incognito mode (Settings → Toggle)
  3. Add delays between searches (2-5s recommended)
  4. Export results regularly for documentation
  5. Combine multiple operators for precision

{Colors.OKCYAN}📍 OUTPUT LOCATIONS:{Colors.ENDC}
  • Results: {self.output_dir}
  • Config:  {self.config_file}
  • History: {self.history_file}

{Colors.OKGREEN}🚀 Ready to start dorking responsibly!{Colors.ENDC}
"""
        print(help_text)
    
    def settings_menu(self):
        """Settings configuration"""
        while True:
            print(f"\n{Colors.HEADER}{'='*65}")
            print("SETTINGS & CONFIGURATION")
            print(f"{'='*65}{Colors.ENDC}\n")
            
            print(f"[1] Browser: {Colors.OKGREEN}{self.browser}{Colors.ENDC}")
            print(f"[2] Search Engine: {Colors.OKGREEN}{self.search_engine}{Colors.ENDC}")
            print(f"[3] Incognito Mode: {Colors.OKGREEN}{'ON' if self.incognito else 'OFF'}{Colors.ENDC}")
            print(f"[4] Auto-open URLs: {Colors.OKGREEN}{'ON' if self.auto_open else 'OFF'}{Colors.ENDC}")
            print(f"[5] Smart Mode: {Colors.OKGREEN}{'ON' if self.smart_mode else 'OFF'}{Colors.ENDC}")
            print(f"[6] Delay (seconds): {Colors.OKGREEN}{self.delay}{Colors.ENDC}")
            print(f"[7] Output Directory: {Colors.OKGREEN}{self.output_dir}{Colors.ENDC}")
            print(f"[8] Save Configuration")
            print(f"[0] Back to Main Menu")
            
            choice = input(f"\n{Colors.OKGREEN}Select: {Colors.ENDC}").strip()
            
            if choice == '0':
                break
            elif choice == '1':
                print("\nAvailable browsers:")
                for idx, browser in enumerate(self.browsers.keys(), 1):
                    print(f"  [{idx}] {browser}")
                b_choice = input("Select: ").strip()
                if b_choice.isdigit():
                    browsers_list = list(self.browsers.keys())
                    if 0 < int(b_choice) <= len(browsers_list):
                        self.browser = browsers_list[int(b_choice)-1]
                        self.print_success(f"Browser: {self.browser}")
            elif choice == '2':
                print("\nAvailable search engines:")
                for idx, engine in enumerate(self.search_engines.keys(), 1):
                    print(f"  [{idx}] {engine}")
                e_choice = input("Select: ").strip()
                if e_choice.isdigit():
                    engines_list = list(self.search_engines.keys())
                    if 0 < int(e_choice) <= len(engines_list):
                        self.search_engine = engines_list[int(e_choice)-1]
                        self.print_success(f"Engine: {self.search_engine}")
            elif choice == '3':
                self.incognito = not self.incognito
                self.print_success(f"Incognito: {'ON' if self.incognito else 'OFF'}")
            elif choice == '4':
                self.auto_open = not self.auto_open
                self.print_success(f"Auto-open: {'ON' if self.auto_open else 'OFF'}")
            elif choice == '5':
                self.smart_mode = not self.smart_mode
                self.print_success(f"Smart Mode: {'ON' if self.smart_mode else 'OFF'}")
            elif choice == '6':
                delay = input("Enter delay (1-60): ").strip()
                if delay.isdigit() and 1 <= int(delay) <= 60:
                    self.delay = int(delay)
                    self.print_success(f"Delay: {self.delay}s")
            elif choice == '7':
                path = input("Enter output directory: ").strip()
                if path:
                    self.output_dir = Path(path)
                    self.output_dir.mkdir(exist_ok=True)
                    self.print_success(f"Output dir: {self.output_dir}")
            elif choice == '8':
                self.save_config()
    
    def save_config(self):
        """Save configuration"""
        config = {
            "browser": self.browser,
            "search_engine": self.search_engine,
            "incognito": self.incognito,
            "auto_open": self.auto_open,
            "smart_mode": self.smart_mode,
            "delay": self.delay,
            "output_dir": str(self.output_dir)
        }
        
        try:
            with open(self.config_file, 'w') as f:
                json.dump(config, f, indent=4)
            self.print_success(f"Config saved: {self.config_file}")
        except Exception as e:
            self.print_error(f"Save failed: {e}")
    
    def load_config(self):
        """Load configuration"""
        if not self.config_file.exists():
            return
        
        try:
            with open(self.config_file, 'r') as f:
                config = json.load(f)
            
            self.browser = config.get("browser", "firefox")
            self.search_engine = config.get("search_engine", "google")
            self.incognito = config.get("incognito", True)
            self.auto_open = config.get("auto_open", True)
            self.smart_mode = config.get("smart_mode", True)
            self.delay = config.get("delay", 2)
            
            output_dir = config.get("output_dir")
            if output_dir:
                self.output_dir = Path(output_dir)
                self.output_dir.mkdir(exist_ok=True)
            
        except Exception as e:
            self.print_warning(f"Load config failed: {e}")
    
    def save_history(self):
        """Save search history"""
        try:
            with open(self.history_file, 'w') as f:
                json.dump(self.search_history, f, indent=4)
        except Exception as e:
            self.print_error(f"Save history failed: {e}")
    
    def load_history(self):
        """Load search history"""
        if not self.history_file.exists():
            return
        
        try:
            with open(self.history_file, 'r') as f:
                self.search_history = json.load(f)
        except Exception as e:
            self.print_warning(f"Load history failed: {e}")
    
    def show_history(self):
        """Display search history"""
        if not self.search_history:
            self.print_warning("No search history!")
            return
        
        print(f"\n{Colors.HEADER}{'='*65}")
        print("SEARCH HISTORY")
        print(f"{'='*65}{Colors.ENDC}\n")
        
        # Show last 20
        for idx, entry in enumerate(self.search_history[-20:], 1):
            print(f"{Colors.OKGREEN}[{idx}]{Colors.ENDC} {entry['timestamp']} - {entry['name']}")
            print(f"    Engine: {entry['engine']}")
            print(f"    {Colors.OKCYAN}{entry['dork'][:60]}{'...' if len(entry['dork']) > 60 else ''}{Colors.ENDC}\n")
        
        print(f"[R] Re-execute  [C] Clear  [E] Export  [0] Back")
        
        choice = input(f"\n{Colors.OKGREEN}Select: {Colors.ENDC}").strip().upper()
        
        if choice == 'R':
            idx = input("Enter number: ").strip()
            if idx.isdigit() and 0 < int(idx) <= len(self.search_history[-20:]):
                entry = self.search_history[-(20-int(idx)+1)]
                self.execute_dork(entry['dork'], entry['name'])
        elif choice == 'C':
            confirm = input("Clear all? (yes/no): ").strip().lower()
            if confirm == 'yes':
                self.search_history.clear()
                self.save_history()
                self.print_success("History cleared!")
        elif choice == 'E':
            self.export_history()
    
    def export_history(self):
        """Export history"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = self.output_dir / f"history_{timestamp}.json"
        
        try:
            with open(filename, 'w') as f:
                json.dump(self.search_history, f, indent=4)
            self.print_success(f"Exported: {filename}")
        except Exception as e:
            self.print_error(f"Export failed: {e}")
    
    def run(self):
        """Main execution loop"""
        if not self.detect_browser():
            self.print_warning("No browser detected")
        
        self.print_banner()
        
        while True:
            try:
                self.print_menu()
                choice = input(f"\n{Colors.OKGREEN}dorktool> {Colors.ENDC}").strip().upper()
                
                if choice == '0':
                    self.print_info("Exiting... Stay safe!")
                    break
                
                elif choice == 'S':
                    self.smart_search()
                
                elif choice == 'Q':
                    self.quick_patterns()
                
                elif choice.isdigit() and choice in self.dorks:
                    self.show_category(choice)
                
                elif choice == '30':
                    self.settings_menu()
                
                elif choice == '31':
                    self.show_history()
                
                elif choice == '34':
                    self.show_help()
                
                else:
                    self.print_error("Invalid choice!")
                
                if choice not in ['0', '30', '31', '34']:
                    input(f"\n{Colors.OKCYAN}Press Enter...{Colors.ENDC}")
                
            except KeyboardInterrupt:
                print(f"\n{Colors.WARNING}Interrupted!{Colors.ENDC}")
                break
            except Exception as e:
                self.print_error(f"Error: {e}")


if __name__ == "__main__":
    try:
        tool = KaliDorkTool()
        tool.run()
    except KeyboardInterrupt:
        print(f"\n{Colors.WARNING}Exiting...{Colors.ENDC}")
        sys.exit(0)
