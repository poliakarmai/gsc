# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""
GSC Deployment Context Analysis.

Parses Dockerfile and docker-compose.yml files to determine the deployment
context (prod, dev, base-image) for services and images. This context
can then be used to filter CVE reachability.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Literal, Optional

# Deployment Context categories
DeployContext = Literal["prod", "dev", "base_image"]

@dataclass
class DockerfileService:
    """Represents a service or build stage defined within a Dockerfile."""
    name: str
    context: DeployContext = "prod"  # Default to prod unless explicitly dev
    base_image: Optional[str] = None
    build_stages: List[str] = field(default_factory=list)
    dockerfile_path: str = ""

@dataclass
class DockerComposeService:
    """Represents a service defined within a docker-compose.yml file."""
    name: str
    context: DeployContext = "prod"  # Default to prod unless explicitly dev
    image: Optional[str] = None
    dockerfile_path: Optional[str] = None
    build_context_path: Optional[str] = None

def parse_dockerfile(path: Path) -> List[DockerfileService]:
    """
    Parses a Dockerfile to extract build stages, base images, and inferred context.
    
    Args:
        path: Path to the Dockerfile.
        
    Returns:
        A list of DockerfileService objects, one for each build stage.
    """
    services: List[DockerfileService] = []
    content = path.read_text(encoding="utf-8", errors="ignore")
    lines = content.splitlines()
    
    current_stage: Optional[DockerfileService] = None
    
    for line_no, line in enumerate(lines, 1):
        stripped_line = line.strip()
        
        # Detect build stages: FROM <image> AS <stage_name>
        from_match = re.match(r"FROM\s+([^\s]+)(?:\s+AS\s+([^\s]+))?", stripped_line, re.IGNORECASE)
        if from_match:
            image = from_match.group(1)
            stage_name = from_match.group(2)
            
            if current_stage: # If a previous stage was active, finalize it
                services.append(current_stage)
            
            # Initialize new stage
            current_stage = DockerfileService(
                name=stage_name or f"base_image_{len(services) + 1}",
                base_image=image,
                dockerfile_path=str(path)
            )
            # Infer context based on stage name
            if stage_name and ("dev" in stage_name.lower() or "test" in stage_name.lower()):
                current_stage.context = "dev"
            elif not stage_name: # Base image without a specific stage name
                current_stage.context = "base_image"
            else:
                current_stage.context = "prod"
            
            current_stage.build_stages.append(image) # Add initial base image as a stage
            
        elif current_stage and stripped_line.startswith("FROM ") and not from_match:
            # If a base image without AS keyword is used in a multi-stage build context
            image = stripped_line[5:].strip()
            current_stage.build_stages.append(image) # Add subsequent FROM images to current stage's build history

    if current_stage: # Add the last stage after loop
        services.append(current_stage)
        
    # If no stages were explicitly defined, treat the entire Dockerfile as a single service
    if not services and lines:
        first_from_match = re.search(r"FROM\s+([^\s]+)", content, re.IGNORECASE)
        base_image = first_from_match.group(1) if first_from_match else None
        services.append(DockerfileService(
            name=path.name,
            context="prod", # Default to prod for single-stage Dockerfiles
            base_image=base_image,
            dockerfile_path=str(path)
        ))

    return services

def parse_docker_compose(path: Path) -> List[DockerComposeService]:
    """
    Parses a docker-compose.yml file to extract services and their deployment context.
    
    Args:
        path: Path to the docker-compose.yml file.
        
    Returns:
        A list of DockerComposeService objects.
    """
    import yaml  # Use standard library yaml parser, if available.
    
    services: List[DockerComposeService] = []
    content = path.read_text(encoding="utf-8", errors="ignore")
    
    try:
        compose_config = yaml.safe_load(content)
    except yaml.YAMLError:
        return []

    if not isinstance(compose_config, dict) or "services" not in compose_config:
        return []

    for service_name, service_config in compose_config["services"].items():
        if not isinstance(service_config, dict):
            continue

        image = service_config.get("image")
        build = service_config.get("build")
        dockerfile_path = None
        build_context_path = None
        
        if isinstance(build, dict):
            dockerfile_path = build.get("dockerfile")
            build_context_path = build.get("context")
        elif isinstance(build, str):
            build_context_path = build # build: . or build: path/to/context

        # Infer context based on service name
        service_context: DeployContext = "prod"
        if "dev" in service_name.lower() or "test" in service_name.lower():
            service_context = "dev"
        
        services.append(DockerComposeService(
            name=service_name,
            context=service_context,
            image=image,
            dockerfile_path=dockerfile_path,
            build_context_path=build_context_path
        ))
    
    return services

def analyze_deploy_context(root: Path) -> Dict[str, List]:
    """
    Analyzes a project root for Dockerfiles and docker-compose.yml to determine
    deployment context for all services.

    Args:
        root: The root path of the project.

    Returns:
        A dictionary containing lists of DockerfileService and DockerComposeService objects.
    """
    root = Path(root)
    dockerfile_services: List[DockerfileService] = []
    docker_compose_services: List[DockerComposeService] = []

    # Find Dockerfiles
    for dockerfile_path in root.rglob("Dockerfile*"): # Dockerfile, Dockerfile.dev, etc.
        if any(part in _SKIP_DIRS for part in dockerfile_path.parts):
            continue
        dockerfile_services.extend(parse_dockerfile(dockerfile_path))

    # Find docker-compose files
    for compose_file_path in root.rglob("docker-compose.yml"):
        if any(part in _SKIP_DIRS for part in compose_file_path.parts):
            continue
        docker_compose_services.extend(parse_docker_compose(compose_file_path))

    return {
        "dockerfile_services": dockerfile_services,
        "docker_compose_services": docker_compose_services,
    }

_SKIP_DIRS = {".git", ".venv", "venv", "__pycache__", "node_modules",
              "site-packages", "dist-packages", "tests", "benchmark", "calibration"}
