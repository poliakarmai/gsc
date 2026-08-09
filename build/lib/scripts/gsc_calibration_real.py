#!/usr/bin/env python3
"""Create real-CVE calibration projects — not just demos, actual known vulns."""
import json, os, shutil
from pathlib import Path

BASE = Path("/tmp/gsc-calibration-real")
BASE.mkdir(parents=True, exist_ok=True)

PROJECTS = {
    "CVE-2021-44228-log4shell": {
        "files": {
            "pom.xml": '''<project><dependencies>
<dependency><groupId>org.apache.logging.log4j</groupId><artifactId>log4j-core</artifactId><version>2.14.1</version></dependency>
</dependencies></project>''',
            "vuln.java": '''Logger logger = LogManager.getLogger(MyClass.class);
String userInput = request.getParameter("input");
logger.info("User said: " + userInput);  // CVE-2021-44228: log4shell JNDI injection
logger.info("User said: {}", userInput);  // mitigated if >=2.15, not if <2.15''',
        },
        "expected": {"findings": [{"rule_id": "GS001"}]},  # log4j detection
    },
    "CVE-2018-1000805-paramiko": {
        "files": {
            "requirements.txt": "paramiko==2.4.0\n",
            "vuln.py": """import paramiko
transport = paramiko.Transport(("host", 22))
transport.connect(username="user", password="pass")
# CVE-2018-1000805: auth bypass in paramiko <2.4.2
# CVE-2023-48795: terrapin attack in paramiko""",
        },
        "expected": {"findings": [{"rule_id": "GS030"}]},  # SCA
    },
    "CVE-2023-27524-superset": {
        "files": {
            "config.py": """# CVE-2023-27524: Apache Superset default SECRET_KEY
SECRET_KEY = '\\x02\\x01thisismyscretkey\\x01\\x02\\\\e\\\\y\\\\y\\\\h'
# In production: replace with os.environ['SUPERSET_SECRET_KEY']
# Flask session forging via predictable key""",
        },
        "expected": {"findings": [{"rule_id": "GS029"}]},  # hardcoded secret
    },
    "CVE-2024-4577-php-cgi": {
        "files": {
            "index.php": """<?php
// CVE-2024-4577: PHP CGI argument injection (windows charset bypass)
$cmd = $_GET['cmd'];
system($cmd);  // command injection
echo "<div>" . $_GET['name'] . "</div>";  // reflected XSS
?>""",
        },
        "expected": {"findings": [{"rule_id": "GS020"}]},  # XSS
    },
    "clean-django-view": {
        "files": {
            "views.py": """from django.shortcuts import render
def hello(request):
    name = request.GET.get("name", "world")
    return render(request, "hello.html", {"name": name})
# Safe: Django auto-escapes templates by default""",
        },
        "expected": {"findings": []},  # clean
    },
}

for name, proj in PROJECTS.items():
    dir_path = BASE / name
    dir_path.mkdir(parents=True, exist_ok=True)
    for fname, content in proj["files"].items():
        (dir_path / fname).write_text(content)
    (dir_path / "expected.json").write_text(json.dumps(proj["expected"], indent=2))
    print(f"  ✅ {name}: {len(proj['files'])} files")

print(f"\nCreated {len(PROJECTS)} real-CVE projects in {BASE}")
