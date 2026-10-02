"""
=============================================================================
                  LIGHTNING - ACTIVE HONEYPOT & DECOY TRAP ENGINE
                  CREATED BY NEXO-TECH BY ALEXANDER
=============================================================================
"""

import collections
from typing import Set, Optional, Tuple, Dict, Any

# Fake responses to waste attacker time
TRAP_RESPONSES = {
    "admin": "<html><body><h1>Admin Portal</h1><form><label>Username</label><input type='text' name='user'/><label>Password</label><input type='password' name='pass'/><input type='submit' value='Login'/></form></body></html>",
    "config": "DATABASE_URL=mysql://root:supersecret@localhost:3306/prod\nSECRET_KEY=fake_secret_key_99x2\nAWS_SECRET=AKIAIOSFODNN7EXAMPLE",
    "db": "-- MySQL dump\nDROP TABLE IF EXISTS users;\nCREATE TABLE users (id int, password varchar(255));\nINSERT INTO users VALUES (1, 'admin_hash_xyZ');",
    "devops": "aws_access_key_id=AKIAIOSFODNN7EXAMPLE\naws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n",
    "default": "<html><body><p>Access Denied - Logging request...</p></body></html>"
}

HONEYPOT_RULES = [
    # Admin Panels
    {"path": "/admin_login.php", "name": "Fake Admin Portal Trap", "severity": "High", "category": "admin"},
    {"path": "/admin", "name": "Admin Panel", "severity": "High", "category": "admin"},
    {"path": "/administrator", "name": "Admin Panel", "severity": "High", "category": "admin"},
    {"path": "/admin.php", "name": "Admin Panel", "severity": "High", "category": "admin"},
    {"path": "/wp-login.php", "name": "WordPress Login", "severity": "High", "category": "admin"},
    {"path": "/wp-admin", "name": "WordPress Admin", "severity": "High", "category": "admin"},
    {"path": "/cpanel", "name": "cPanel", "severity": "High", "category": "admin"},
    {"path": "/cPanel", "name": "cPanel", "severity": "High", "category": "admin"},
    {"path": "/webmail", "name": "Webmail", "severity": "High", "category": "admin"},
    {"path": "/manager/html", "name": "Tomcat Manager", "severity": "High", "category": "admin"},
    {"path": "/admin/config.php", "name": "Admin Config", "severity": "High", "category": "config"},
    {"path": "/jmx-console", "name": "JMX Console", "severity": "High", "category": "admin"},
    {"path": "/admin-console", "name": "Admin Console", "severity": "High", "category": "admin"},
    {"path": "/system/console", "name": "OSGi Console", "severity": "High", "category": "admin"},
    
    # Database Tools
    {"path": "/phpmyadmin", "name": "phpMyAdmin", "severity": "High", "category": "db"},
    {"path": "/pma", "name": "phpMyAdmin (pma)", "severity": "High", "category": "db"},
    {"path": "/adminer.php", "name": "Adminer", "severity": "High", "category": "db"},
    {"path": "/adminer", "name": "Adminer", "severity": "High", "category": "db"},
    {"path": "/dbadmin", "name": "DB Admin", "severity": "High", "category": "db"},
    {"path": "/myadmin", "name": "My Admin", "severity": "High", "category": "db"},
    {"path": "/sql", "name": "SQL Tools", "severity": "High", "category": "db"},
    {"path": "/mysql", "name": "MySQL Tools", "severity": "High", "category": "db"},
    {"path": "/pgadmin", "name": "pgAdmin", "severity": "High", "category": "db"},
    {"path": "/mongoexpress", "name": "Mongo Express", "severity": "High", "category": "db"},
    {"path": "/redis-commander", "name": "Redis Commander", "severity": "High", "category": "db"},

    # DevOps & Cloud
    {"path": "/.aws/credentials", "name": "AWS Credentials", "severity": "Critical", "category": "devops"},
    {"path": "/.aws/config", "name": "AWS Config", "severity": "Critical", "category": "devops"},
    {"path": "/.docker/config.json", "name": "Docker Config", "severity": "Critical", "category": "devops"},
    {"path": "/.kube/config", "name": "Kubernetes Config", "severity": "Critical", "category": "devops"},
    {"path": "/kubernetes", "name": "Kubernetes Folder", "severity": "High", "category": "devops"},
    {"path": "/.terraform", "name": "Terraform State", "severity": "Critical", "category": "devops"},
    {"path": "/ansible.cfg", "name": "Ansible Config", "severity": "Critical", "category": "devops"},
    {"path": "/docker-compose.yml", "name": "Docker Compose", "severity": "Medium", "category": "devops"},
    {"path": "/Dockerfile", "name": "Dockerfile", "severity": "Medium", "category": "devops"},
    {"path": "/Jenkinsfile", "name": "Jenkinsfile", "severity": "Medium", "category": "devops"},
    {"path": "/Vagrantfile", "name": "Vagrantfile", "severity": "Medium", "category": "devops"},
    {"path": "/.circleci/config.yml", "name": "CircleCI Config", "severity": "Medium", "category": "devops"},
    {"path": "/.github/workflows", "name": "GitHub Workflows", "severity": "Medium", "category": "devops"},

    # Debug & Monitoring
    {"path": "/actuator", "name": "Spring Actuator", "severity": "High", "category": "default"},
    {"path": "/debug/vars", "name": "Go Debug Vars", "severity": "Medium", "category": "default"},
    {"path": "/debug/pprof", "name": "Go pprof", "severity": "Medium", "category": "default"},
    {"path": "/server-status", "name": "Apache Status", "severity": "Medium", "category": "default"},
    {"path": "/server-info", "name": "Apache Info", "severity": "Medium", "category": "default"},
    {"path": "/_debug", "name": "Debug Endpoints", "severity": "Medium", "category": "default"},
    {"path": "/trace", "name": "Trace", "severity": "Medium", "category": "default"},
    {"path": "/elmah.axd", "name": "Elmah Logs", "severity": "Medium", "category": "default"},
    {"path": "/trace.axd", "name": "ASP.NET Trace", "severity": "Medium", "category": "default"},
    {"path": "/phpinfo.php", "name": "PHP Info", "severity": "Medium", "category": "default"},
    {"path": "/info.php", "name": "PHP Info", "severity": "Medium", "category": "default"},
    {"path": "/test.php", "name": "Test Script", "severity": "Low", "category": "default"},
    {"path": "/pi.php", "name": "PHP Info", "severity": "Medium", "category": "default"},

    # Config & Secret Files
    {"path": "/.env", "name": "Environment File", "severity": "Critical", "category": "config"},
    {"path": "/.env.backup", "name": "Environment Backup", "severity": "Critical", "category": "config"},
    {"path": "/.env.local", "name": "Environment Local", "severity": "Critical", "category": "config"},
    {"path": "/.env.production", "name": "Environment Prod", "severity": "Critical", "category": "config"},
    {"path": "/.env.staging", "name": "Environment Staging", "severity": "Critical", "category": "config"},
    {"path": "/.git/config", "name": "Git Config", "severity": "Critical", "category": "config"},
    {"path": "/.git/HEAD", "name": "Git HEAD", "severity": "High", "category": "config"},
    {"path": "/.svn/entries", "name": "SVN Entries", "severity": "High", "category": "config"},
    {"path": "/.hg", "name": "Mercurial Repo", "severity": "High", "category": "config"},
    {"path": "/web.config", "name": "Web Config", "severity": "Critical", "category": "config"},
    {"path": "/wp-config.php", "name": "WP Config", "severity": "Critical", "category": "config"},
    {"path": "/config.php", "name": "Config File", "severity": "Critical", "category": "config"},
    {"path": "/configuration.php", "name": "Joomla Config", "severity": "Critical", "category": "config"},
    {"path": "/settings.py", "name": "Django Settings", "severity": "Critical", "category": "config"},
    {"path": "/application.yml", "name": "Spring Config", "severity": "Critical", "category": "config"},
    {"path": "/application.properties", "name": "Spring Properties", "severity": "Critical", "category": "config"},
    {"path": "/appsettings.json", "name": "ASP.NET Settings", "severity": "Critical", "category": "config"},
    {"path": "/config.json", "name": "Config JSON", "severity": "Critical", "category": "config"},
    {"path": "/.htpasswd", "name": "HTPasswd File", "severity": "Critical", "category": "config"},
    {"path": "/.htaccess", "name": "HTAccess File", "severity": "High", "category": "config"},
    {"path": "/crossdomain.xml", "name": "Crossdomain Policy", "severity": "Medium", "category": "config"},
    {"path": "/clientaccesspolicy.xml", "name": "Client Access Policy", "severity": "Medium", "category": "config"},

    # Backup Files
    {"path": "/backup.sql", "name": "SQL Backup", "severity": "Critical", "category": "db"},
    {"path": "/backup.tar.gz", "name": "Archive Backup", "severity": "Critical", "category": "default"},
    {"path": "/backup.zip", "name": "Archive Backup", "severity": "Critical", "category": "default"},
    {"path": "/db.sql", "name": "Database Dump", "severity": "Critical", "category": "db"},
    {"path": "/database.sql", "name": "Database Dump", "severity": "Critical", "category": "db"},
    {"path": "/dump.sql", "name": "Database Dump", "severity": "Critical", "category": "db"},
    {"path": "/site.tar.gz", "name": "Site Archive", "severity": "Critical", "category": "default"},
    {"path": "/www.zip", "name": "WWW Archive", "severity": "Critical", "category": "default"},
    {"path": ".bak", "name": "Backup File", "severity": "Critical", "category": "default", "match": "endswith"},
    {"path": ".old", "name": "Old File", "severity": "High", "category": "default", "match": "endswith"},

    # API Exploits
    {"path": "/api/v1/internal", "name": "Internal API", "severity": "High", "category": "default"},
    {"path": "/graphql", "name": "GraphQL API", "severity": "High", "category": "default"},
    {"path": "/graphiql", "name": "GraphiQL Explorer", "severity": "High", "category": "default"},
    {"path": "/api-docs", "name": "API Docs", "severity": "Medium", "category": "default"},
    {"path": "/swagger.json", "name": "Swagger JSON", "severity": "Medium", "category": "default"},
    {"path": "/swagger-ui.html", "name": "Swagger UI", "severity": "Medium", "category": "default"},
    {"path": "/openapi.json", "name": "OpenAPI Spec", "severity": "Medium", "category": "default"},
    {"path": "/.well-known", "name": "Well Known Dir", "severity": "Medium", "category": "default"},
    {"path": "/oauth/token", "name": "OAuth Token", "severity": "Critical", "category": "default"},

    # Vulnerability Scanners
    {"path": "/cgi-bin", "name": "CGI Bin", "severity": "High", "category": "default"},
    {"path": "/fcgi-bin", "name": "FastCGI Bin", "severity": "High", "category": "default"},
    {"path": "/cgi-bin/test-cgi", "name": "Test CGI", "severity": "High", "category": "default"},
    {"path": "/cgi-bin/php", "name": "PHP CGI", "severity": "High", "category": "default"},
    {"path": "/cgi-bin/printenv", "name": "PrintEnv CGI", "severity": "High", "category": "default"},

    # Shell Uploads
    {"path": "/uploads/shell.php", "name": "Web Shell", "severity": "Critical", "category": "default"},
    {"path": "/upload.php", "name": "Upload Endpoint", "severity": "High", "category": "default"},
    {"path": "/cmd.php", "name": "Command Shell", "severity": "Critical", "category": "default"},
    {"path": "/c99.php", "name": "c99 Shell", "severity": "Critical", "category": "default"},
    {"path": "/r57.php", "name": "r57 Shell", "severity": "Critical", "category": "default"},
    {"path": "/webshell.php", "name": "Web Shell", "severity": "Critical", "category": "default"},
    {"path": "/backdoor.php", "name": "Backdoor", "severity": "Critical", "category": "default"}
]

class HoneypotEngine:
    """Decoy trap engine to catch and auto-blacklist aggressive scanners."""
    def __init__(self, auto_ban: bool = True):
        self.auto_ban = auto_ban
        self.trapped_ips: Set[str] = set()
        self.ip_hits: collections.Counter = collections.Counter()

    def get_trap_response(self, category: str) -> str:
        """Returns fake data to waste attacker time."""
        return TRAP_RESPONSES.get(category, TRAP_RESPONSES["default"])

    def is_honeypot_hit(self, path: str) -> Optional[Tuple[str, str]]:
        """Checks if a request path hit a configured honeypot trap with partial matching."""
        clean_path = path.split("?")[0].rstrip("/")
        if not clean_path:
            clean_path = "/"
            
        for rule in HONEYPOT_RULES:
            match_type = rule.get("match", "startswith")
            trap_path = rule["path"]
            
            if match_type == "startswith":
                if clean_path == trap_path or clean_path.startswith(trap_path + "/"):
                    return f"{rule['name']} ({rule['severity']})", trap_path
            elif match_type == "endswith":
                if clean_path.endswith(trap_path):
                    return f"{rule['name']} ({rule['severity']})", trap_path
                    
        return None

    def trigger_trap(self, ip: str, path: str) -> Tuple[str, str]:
        """Records a honeypot breach and flags the IP for permanent blacklist."""
        self.ip_hits[ip] += 1
        trap_info = self.is_honeypot_hit(path)
        
        if trap_info:
            trap_name_severity, matched_path = trap_info
            
            # Find the category to provide fake data
            category = "default"
            for rule in HONEYPOT_RULES:
                if rule["path"] == matched_path:
                    category = rule.get("category", "default")
                    break
                    
            fake_data = self.get_trap_response(category)
            trap_name = trap_name_severity
            message = f"[{self.ip_hits[ip]} hits] Attacker probed {trap_name}. Sending decoy response."
        else:
            trap_name = "General Decoy Trap"
            message = f"[{self.ip_hits[ip]} hits] Attacker probed active Honeypot decoy: {path}"

        if self.auto_ban:
            self.trapped_ips.add(ip)
            
        return trap_name, message
