# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""OpenAPI 3.x Parser for BOLA/IDOR Fuzzing.

Parses OpenAPI/Swagger specifications (JSON and YAML) to extract API endpoints
with their paths, methods, parameters, and authentication requirements.
Identifies potential BOLA/IDOR candidates based on path or query parameters
that resemble resource IDs (e.g., 'id', 'user_id', 'account_id').

Usage: python3 gsc_openapi_parser.py <spec-path> [--output <json-file>]
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal, Mapping

import yaml


@dataclass
class OpenAPIParameter:
    """Represents an API parameter."""
    name: str
    in_location: Literal["query", "header", "path", "cookie"]
    required: bool
    schema_type: str | None = None
    description: str | None = None
    

@dataclass
class OpenAPIAuthRequirement:
    """Represents an authentication requirement for an endpoint."""
    scheme_name: str
    scopes: list[str] = field(default_factory=list)

@dataclass
class OpenAPIExtractedEndpoint:
    """Represents an extracted API endpoint with relevant details."""
    path: str
    method: Literal["get", "post", "put", "delete", "patch", "head", "options", "trace"]
    summary: str | None = None
    description: str | None = None
    parameters: list[OpenAPIParameter] = field(default_factory=list)
    auth_required: list[OpenAPIAuthRequirement] = field(default_factory=list)
    is_bola_idor_candidate: bool = False
    bola_idor_reason: str | None = None

    def to_dict(self) -> dict:
        from dataclasses import asdict
        return asdict(self)


ID_PATTERNS = re.compile(
    r"""
    (?:^|[-_])               # start of string or separator
    (?:id|user_id|account_id|client_id|order_id|document_id|post_id|item_id|transaction_id) # common ID names
    (?:$|[-_])               # end of string or separator
    """,
    re.IGNORECASE | re.VERBOSE,
)

def _is_bola_idor_candidate(param_name: str, param_in: str) -> bool:
    """Checks if a parameter name suggests a BOLA/IDOR vulnerability."""
    if param_in not in ["path", "query"]:
        return False
    return bool(ID_PATTERNS.search(param_name))

def parse_openapi_spec(spec_path: Path) -> list[OpenAPIExtractedEndpoint]:
    """Parses an OpenAPI 3.x specification file (JSON or YAML)."""
    content = spec_path.read_text()
    if spec_path.suffix in (".yml", ".yaml"):
        spec = yaml.safe_load(content)
    elif spec_path.suffix == ".json":
        spec = json.loads(content)
    else:
        raise ValueError(f"Unsupported file extension: {spec_path.suffix}. Must be .json, .yml, or .yaml")

    if "openapi" not in spec or not spec["openapi"].startswith("3."):
        raise ValueError("Not a valid OpenAPI 3.x specification.")

    endpoints: list[OpenAPIExtractedEndpoint] = []
    
    security_schemes = spec.get("components", {}).get("securitySchemes", {})

    for path, path_item in spec.get("paths", {}).items():
        # Common parameters for all methods under this path
        common_params = []
        for param_spec in path_item.get("parameters", []):
            common_params.append(
                OpenAPIParameter(
                    name=param_spec["name"],
                    in_location=param_spec["in"],
                    required=param_spec.get("required", False),
                    schema_type=param_spec.get("schema", {}).get("type")
                )
            )

        for method, method_spec in path_item.items():
            if method.lower() not in {"get", "post", "put", "delete", "patch", "head", "options", "trace"}:
                continue  # Skip non-HTTP methods like 'parameters', 'summary', 'description'

            all_params = common_params[:]  # Start with common parameters

            # Method-specific parameters
            for param_spec in method_spec.get("parameters", []):
                all_params.append(
                    OpenAPIParameter(
                        name=param_spec["name"],
                        in_location=param_spec["in"],
                        required=param_spec.get("required", False),
                        schema_type=param_spec.get("schema", {}).get("type")
                    )
                )

            auth_reqs = []
            for security_req in method_spec.get("security", spec.get("security", [])):
                for scheme_name, scopes in security_req.items():
                    auth_reqs.append(OpenAPIAuthRequirement(scheme_name=scheme_name, scopes=scopes))

            is_bola_idor = False
            bola_idor_reason = None
            for param in all_params:
                if _is_bola_idor_candidate(param.name, param.in_location):
                    is_bola_idor = True
                    bola_idor_reason = f"Parameter '{param.name}' in {param.in_location} looks like a resource ID."
                    break

            endpoints.append(
                OpenAPIExtractedEndpoint(
                    path=path,
                    method=method.lower(),
                    summary=method_spec.get("summary"),
                    description=method_spec.get("description"),
                    parameters=all_params,
                    auth_required=auth_reqs,
                    is_bola_idor_candidate=is_bola_idor,
                    bola_idor_reason=bola_idor_reason,
                )
            )
    return endpoints

def main():
    parser = argparse.ArgumentParser(description="OpenAPI 3.x Parser for BOLA/IDOR Fuzzing")
    parser.add_argument("spec_path", help="Path to OpenAPI specification file (JSON or YAML)")
    parser.add_argument("--output", "-o", help="Output JSON file for extracted endpoints")
    args = parser.parse_args()

    spec_file = Path(args.spec_path)
    if not spec_file.exists():
        print(f"❌ Error: Specification file not found at {spec_file}")
        sys.exit(1)

    try:
        print(f"🔍 Parsing OpenAPI spec from {spec_file}...")
        endpoints = parse_openapi_spec(spec_file)
        
        bola_idor_candidates = [e for e in endpoints if e.is_bola_idor_candidate]

        if args.output:
            output_data = [e.to_dict() for e in endpoints]
            with open(args.output, "w") as f:
                json.dump(output_data, f, indent=2, ensure_ascii=False)
            print(f"✅ Extracted endpoints saved to {args.output}")
        
        print(f"\nSummary:")
        print(f"Total endpoints found: {len(endpoints)}")
        print(f"Potential BOLA/IDOR candidates: {len(bola_idor_candidates)}")

        if bola_idor_candidates:
            print("\n--- BOLA/IDOR Candidates ---")
            for i, ep in enumerate(bola_idor_candidates, 1):
                print(f"\n{i}. Path: {ep.path}")
                print(f"   Method: {ep.method.upper()}")
                print(f"   Reason: {ep.bola_idor_reason}")
                if ep.auth_required:
                    auth_schemes = ", ".join([req.scheme_name for req in ep.auth_required])
                    print(f"   Auth: {auth_schemes}")
                if ep.summary:
                    print(f"   Summary: {ep.summary}")
        else:
            print("No BOLA/IDOR candidates identified.")

    except ValueError as e:
        print(f"❌ Error parsing OpenAPI spec: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"❌ An unexpected error occurred: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()