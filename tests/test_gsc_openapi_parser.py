# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""Tests for the OpenAPI parser module."""

import json
import pytest
from pathlib import Path

from gsc_cli.gsc_openapi_parser import parse_openapi_spec, OpenAPIExtractedEndpoint, OpenAPIParameter, OpenAPIAuthRequirement


def test_parse_openapi_spec_yaml(tmp_path):
    spec_content = """
openapi: 3.0.0
info:
  title: Sample API
  version: 1.0.0
servers:
  - url: http://localhost:8080

paths:
  /users:
    get:
      summary: List all users
      parameters:
        - name: limit
          in: query
          schema:
            type: integer
          required: false
      responses:
        '200':
          description: A list of users.
    post:
      summary: Create a new user
      responses:
        '201':
          description: User created
      security:
        - bearerAuth: []

  /users/{user_id}:
    get:
      summary: Get a user by ID
      parameters:
        - name: user_id
          in: path
          required: true
          schema:
            type: string
      responses:
        '200':
          description: User details
"""
    
    spec_file = tmp_path / "openapi.yaml"
    spec_file.write_text(spec_content)
    
    endpoints = parse_openapi_spec(spec_file)

    assert len(endpoints) == 3

    # Test case 1: GET /users
    ep1 = endpoints[0]
    assert ep1.path == "/users"
    assert ep1.method == "get"
    assert ep1.summary == "List all users"
    assert len(ep1.parameters) == 1
    assert ep1.parameters[0].name == "limit"
    assert ep1.parameters[0].in_location == "query"
    assert ep1.parameters[0].required == False
    assert ep1.parameters[0].schema_type == "integer"
    assert len(ep1.auth_required) == 0
    assert ep1.is_bola_idor_candidate == False

    # Test case 2: POST /users
    ep2 = endpoints[1]
    assert ep2.path == "/users"
    assert ep2.method == "post"
    assert ep2.summary == "Create a new user"
    assert len(ep2.parameters) == 0
    assert len(ep2.auth_required) == 1
    assert ep2.auth_required[0].scheme_name == "bearerAuth"
    assert ep2.is_bola_idor_candidate == False

    # Test case 3: GET /users/{user_id}
    ep3 = endpoints[2]
    assert ep3.path == "/users/{user_id}" 
    assert ep3.method == "get"
    assert ep3.summary == "Get a user by ID"
    assert len(ep3.parameters) == 1
    assert ep3.parameters[0].name == "user_id"
    assert ep3.parameters[0].in_location == "path"
    assert ep3.parameters[0].required == True
    assert ep3.parameters[0].schema_type == "string"
    assert ep3.is_bola_idor_candidate == True
    assert ep3.bola_idor_reason == "Parameter 'user_id' in path looks like a resource ID."

def test_parse_openapi_spec_json(tmp_path):
    spec_content = {
        "openapi": "3.0.0",
        "info": {
            "title": "Sample API JSON",
            "version": "1.0.0"
        },
        "servers": [
            {"url": "http://localhost:8080"}
        ],
        "paths": {
            "/items": {
                "get": {
                    "summary": "List items",
                    "parameters": [
                        {
                            "name": "account_id",
                            "in": "query",
                            "required": True,
                            "schema": {"type": "string"},
                            "description": "The account ID to filter items by"
                        }
                    ],
                    "responses": {
                        "200": {"description": "A list of items."}
                    }
                }
            },
             "/items/{item_id}": {
                "get": {
                    "summary": "Get item by ID",
                    "parameters": [
                        {
                            "name": "item_id",
                            "in": "path",
                            "required": True,
                            "schema": {"type": "string"}
                        }
                    ],
                    "responses": {
                        "200": {"description": "Item details."}
                    },
                    "security": [{"apiKeyAuth": []}]
                }
            }
        },
        "components": {
            "securitySchemes": {
                "apiKeyAuth": {
                    "type": "apiKey",
                    "in": "header",
                    "name": "X-API-Key"
                }
            }
        }
    }
    spec_file = tmp_path / "openapi.json"
    spec_file.write_text(json.dumps(spec_content))
    
    endpoints = parse_openapi_spec(spec_file)

    assert len(endpoints) == 2

    # Test case 1: GET /items (with BOLA/IDOR candidate query param)
    ep1 = endpoints[0]
    assert ep1.path == "/items"
    assert ep1.method == "get"
    assert ep1.summary == "List items"
    assert len(ep1.parameters) == 1
    assert ep1.parameters[0].name == "account_id"
    assert ep1.parameters[0].in_location == "query"
    assert ep1.parameters[0].required == True
    assert ep1.parameters[0].schema_type == "string"
    assert ep1.is_bola_idor_candidate == True
    assert ep1.bola_idor_reason == "Parameter 'account_id' in query looks like a resource ID."
    assert len(ep1.auth_required) == 0

    # Test case 2: GET /items/{item_id}
    ep2 = endpoints[1]
    assert ep2.path == "/items/{item_id}" 
    assert ep2.method == "get"
    assert ep2.summary == "Get item by ID"
    assert len(ep2.parameters) == 1
    assert ep2.parameters[0].name == "item_id"
    assert ep2.parameters[0].in_location == "path"
    assert ep2.parameters[0].required == True
    assert ep2.parameters[0].schema_type == "string"
    assert ep2.is_bola_idor_candidate == True
    assert ep2.bola_idor_reason == "Parameter 'item_id' in path looks like a resource ID."
    assert len(ep2.auth_required) == 1
    assert ep2.auth_required[0].scheme_name == "apiKeyAuth"

def test_invalid_spec_file(tmp_path):
    invalid_file = tmp_path / "invalid.txt"
    invalid_file.write_text("This is not a valid spec")
    with pytest.raises(ValueError, match="Unsupported file extension"):
        parse_openapi_spec(invalid_file)

def test_non_openapi_3_spec(tmp_path):
    non_openapi_file = tmp_path / "non_openapi.yaml"
    non_openapi_file.write_text("info:\n  title: Not OpenAPI")
    with pytest.raises(ValueError, match="Not a valid OpenAPI 3.x specification."):
        parse_openapi_spec(non_openapi_file)

def test_missing_spec_file():
    with pytest.raises(FileNotFoundError):
        parse_openapi_spec(Path("non_existent_file.yaml"))