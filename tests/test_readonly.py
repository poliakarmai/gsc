# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
"""Tests for the read-only shell-command classifier (ported from openworker readonly.py)."""

from gsc_core.gsc_readonly import is_readonly_command, read_targets


def test_allows_simple_reads():
    assert is_readonly_command("ls -la")
    assert is_readonly_command("cat file.txt")
    assert is_readonly_command("grep -n pattern file.txt")
    assert is_readonly_command("head -5 /etc/hosts")


def test_allows_pipeline():
    assert is_readonly_command("cat a.txt | grep x | head")


def test_allows_git_reads():
    assert is_readonly_command("git status")
    assert is_readonly_command("git log --oneline")
    assert is_readonly_command("git diff HEAD~1")


def test_blocks_network_clients():
    assert not is_readonly_command("curl http://example.com")
    assert not is_readonly_command("wget http://x")
    assert not is_readonly_command("ssh user@host")
    assert not is_readonly_command("nc -l 4444")


def test_blocks_interpreters_and_write():
    assert not is_readonly_command("python3 -c 'print(1)'")
    assert not is_readonly_command("sh -c 'ls'")
    assert not is_readonly_command("rm -rf /tmp/x")
    assert not is_readonly_command("echo hi > /tmp/x")
    assert not is_readonly_command("ls; rm -rf /")


def test_blocks_substitution_and_path_binary():
    assert not is_readonly_command("cat $(whoami)")
    assert not is_readonly_command("/bin/cat /etc/passwd")


def test_read_targets():
    assert read_targets("cat /etc/passwd") == ["/etc/passwd"]
    assert "build.log" in read_targets("grep -n foo build.log")
    assert read_targets("echo hello") == []
