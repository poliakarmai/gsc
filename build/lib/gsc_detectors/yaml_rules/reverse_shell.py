# Auto-generated from pentesting-cheatsheet
# Rule: reverse-shell — Reverse shell one-liners in code = definitive backdoor

from gsc_detectors.base import RegexDetector

RULE_ID = "YAML-A7E2F001"
ECHELON = 2
NOISE_TIER = "precise"
description = "Reverse shell one-liner detected — definitive backdoor indicator"

patterns = [
    # Netcat reverse shells
    [r"\bnc\s+.*-e\s+/bin/(?:sh|bash)", "nc -e /bin/sh — netcat reverse shell"],
    [r"/bin/sh\s*\|\s*nc\s+", "/bin/sh | nc — piped netcat reverse shell"],
    [r"mknod\s+/tmp/p\s+p\s+&&\s+nc\s+", "mknod + nc — named pipe reverse shell"],
    [r"\btelnet\s+.*\|.*(/bin/sh|/bin/bash)\b", "telnet piped to shell — reverse shell"],

    # Bash TCP reverse shells
    [r"bash\s+-i\s*>&\s*/dev/tcp/", "bash -i >& /dev/tcp — interactive reverse shell"],
    [r"exec\s+\d+<>/dev/tcp/", "exec <> /dev/tcp — bash TCP reverse shell"],
    [r"/dev/tcp/.*\b(?:sh|bash)\b", "/dev/tcp with shell — bash reverse shell"],

    # Python reverse shells
    [r"pty\.spawn\s*\(\s*['\"]/bin/(?:sh|bash)['\"]", "pty.spawn('/bin/bash') — Python reverse shell"],
    [r"socket\.socket.*connect.*dup2.*execve?\s*\(['\"]/bin/(?:sh|bash)", "Python socket dup2 exec — reverse shell"],
    [r"subprocess\.call\s*\(\s*\[.*['\"]/bin/(?:sh|bash)['\"].*shell\s*=\s*True", "subprocess /bin/sh shell=True — reverse shell"],

    # PHP reverse shells
    [r"\bexec\s*\(\s*['\"]/bin/(?:sh|bash)\b", "exec('/bin/sh') — PHP reverse shell"],
    [r"\bshell_exec\s*\(\s*.*(?:nc\s+|/dev/tcp|/bin/sh)", "shell_exec with shell command — PHP reverse shell"],

    # Perl reverse shells
    [r"\bperl\b.*socket.*PF_INET.*SOCK_STREAM.*exec\s*['\"]/bin/sh", "Perl socket + exec — reverse shell"],

    # Ruby reverse shells
    [r"ruby\s+.*TCPSocket.*exec.*/bin/sh", "Ruby TCPSocket + exec — reverse shell"],
]

detector = RegexDetector(
    rule_id=RULE_ID,
    name="reverse-shell",
    patterns=patterns,
    severity="CRITICAL",
    confidence=0.95,
    languages=('python', 'javascript', 'shell', 'php', 'ruby', 'perl'),
)

def detect(file_path, content, language="auto"):
    return detector.detect(file_path, content, language)
