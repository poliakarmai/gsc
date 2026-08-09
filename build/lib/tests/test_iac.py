#!/usr/bin/env python3
"""tests/test_iac.py — IaC detector tests (Dockerfile + K8s + Terraform, +7)."""
import sys, os
os.chdir('/home/openclaw/gsc')
sys.path.insert(0, '.')

from gsc_iac import detect_dockerfile, detect_kubernetes, detect_terraform

passed, failed = 0, 0
def test(name, fn):
    global passed, failed
    try: fn(); print(f'  ✅ {name}'); passed += 1
    except Exception as e: print(f'  ❌ {name}: {e}'); failed += 1

def t1():
    hits = detect_dockerfile("Dockerfile", "FROM ubuntu:20.04\nUSER root\nRUN apt-get update")
    rules = {h["rule_id"] for h in hits}
    assert "GS031-DOCKER-ROOT" in rules
test('dockerfile root user', t1)

def t2():
    hits = detect_dockerfile("Dockerfile", "FROM ubuntu:20.04\nRUN apt-get update")
    rules = {h["rule_id"] for h in hits}
    assert "GS031-DOCKER-NO-USER" in rules
test('dockerfile no user', t2)

def t3():
    hits = detect_dockerfile("Dockerfile", "FROM node:latest\nENV API_SECRET=abc123")
    rules = {h["rule_id"] for h in hits}
    assert "GS031-DOCKER-LATEST" in rules
    assert "GS031-DOCKER-SECRET-ENV" in rules
test('dockerfile latest + secret', t3)

def t4():
    hits = detect_kubernetes("pod.yaml", "apiVersion: v1\nkind: Pod\nspec:\n  hostNetwork: true\n  containers:\n  - name: app\n    securityContext:\n      privileged: true\n      runAsUser: 0")
    rules = {h["rule_id"] for h in hits}
    assert "GS031-K8S-PRIVILEGED" in rules
    assert "GS031-K8S-HOST-NETWORK" in rules
    assert "GS031-K8S-ROOT" in rules
test('k8s privileged + hostNetwork + root', t4)

def t5():
    hits = detect_kubernetes("deploy.yaml", "apiVersion: apps/v1\nkind: Deployment\nspec:\n  template:\n    spec:\n      hostNetwork: true\n      containers:\n      - name: app")
    rules = {h["rule_id"] for h in hits}
    assert "GS031-K8S-HOST-NETWORK" in rules
test('k8s deployment spec nesting', t5)

def t6():
    hits = detect_terraform("main.tf", 'resource "aws_s3_bucket" "b" {\n  acl = "public-read"\n}')
    rules = {h["rule_id"] for h in hits}
    assert "GS031-TF-S3-PUBLIC-ACL" in rules
test('terraform public S3', t6)

def t7():
    hits = detect_terraform("main.tf", 'access_key = "AKIAIOSFODNN7EXAMPLE"')
    rules = {h["rule_id"] for h in hits}
    assert "GS031-TF-PLAINTEXT-SECRET" in rules
test('terraform hardcoded secret', t7)

print(f'\n{"="*50}')
print(f'Results: {passed} passed, {failed} failed')
sys.exit(0 if failed == 0 else 1)
