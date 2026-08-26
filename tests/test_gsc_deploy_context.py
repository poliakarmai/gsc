#!/usr/bin/env python3
"""Tests for gsc_cli/gsc_deploy_context.py — deployment-context parser."""

import tempfile
from pathlib import Path

from gsc_cli.gsc_deploy_context import parse_dockerfile, parse_docker_compose


def test_parse_dockerfile_single_stage_base_image():
    with tempfile.TemporaryDirectory() as d:
        f = Path(d) / "Dockerfile"
        f.write_text("FROM python:3.12-slim\nRUN pip install flask\n", encoding="utf-8")
        services = parse_dockerfile(f)
        assert len(services) == 1
        s = services[0]
        assert s.base_image == "python:3.12-slim"
        assert s.context == "base_image"


def test_parse_dockerfile_multistage_dev():
    with tempfile.TemporaryDirectory() as d:
        f = Path(d) / "Dockerfile"
        f.write_text(
            "FROM python:3.12 AS base\n"
            "FROM base AS dev\n"
            "RUN pip install -r requirements-dev.txt\n",
            encoding="utf-8",
        )
        services = parse_dockerfile(f)
        assert len(services) == 2
        assert services[-1].name == "dev"
        assert services[-1].context == "dev"


def test_parse_docker_compose_contexts():
    with tempfile.TemporaryDirectory() as d:
        f = Path(d) / "docker-compose.yml"
        f.write_text(
            "services:\n"
            "  web:\n"
            "    image: nginx:latest\n"
            "  dev-db:\n"
            "    build:\n"
            "      context: .\n"
            "      dockerfile: Dockerfile.db\n",
            encoding="utf-8",
        )
        services = parse_docker_compose(f)
        assert len(services) == 2
        assert services[0].name == "web"
        assert services[0].context == "prod"
        assert services[0].image == "nginx:latest"
        assert services[1].name == "dev-db"
        assert services[1].context == "dev"
        assert services[1].dockerfile_path == "Dockerfile.db"
