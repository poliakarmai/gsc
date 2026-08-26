#!/usr/bin/env python3
"""Tests for the Java/Maven PoF parser."""

from gsc_cli.gsc_pof_java_parser import (
    MavenDependency,
    MavenProject,
    detect_java_project,
    parse_pom_xml,
)


# ── detect_java_project ──────────────────────────────────────────────────


def test_detect_java_project_with_pom():
    assert detect_java_project(["src/App.java", "pom.xml"]) is True


def test_detect_java_project_no_pom():
    assert detect_java_project(["src/App.java", "build.gradle"]) is False


def test_detect_java_project_empty():
    assert detect_java_project([]) is False


def test_detect_java_project_case_insensitive():
    assert detect_java_project(["POM.XML"]) is True


def test_detect_java_project_ignores_substrings():
    assert detect_java_project(["mypom.xml", "pom.xml.bak"]) is False


# ── parse_pom_xml ────────────────────────────────────────────────────────


MINIMAL_POM = (
    "<project>"
    "<groupId>com.example</groupId>"
    "<artifactId>demo</artifactId>"
    "<version>1.0.0</version>"
    "</project>"
)


def test_parse_minimal():
    p = parse_pom_xml(MINIMAL_POM)
    assert isinstance(p, MavenProject)
    assert p.valid is True
    assert p.group_id == "com.example"
    assert p.artifact_id == "demo"
    assert p.version == "1.0.0"
    assert p.dependencies == []


def test_parse_with_namespace():
    pom = (
        '<project xmlns="http://maven.apache.org/POM/4.0.0">'
        "<groupId>com.example</groupId>"
        "<artifactId>demo</artifactId>"
        "<version>1.0.0</version>"
        "</project>"
    )
    p = parse_pom_xml(pom)
    assert p.valid is True
    assert p.artifact_id == "demo"


def test_parse_with_dependencies():
    pom = (
        "<project>"
        "<groupId>com.example</groupId><artifactId>demo</artifactId>"
        "<version>1.0.0</version>"
        "<dependencies>"
        "<dependency>"
        "<groupId>org.foo</groupId><artifactId>bar</artifactId>"
        "<version>1.2.3</version><scope>compile</scope>"
        "</dependency>"
        "<dependency>"
        "<groupId>org.baz</groupId><artifactId>qux</artifactId>"
        "<version>2.0.0</version><scope>test</scope>"
        "</dependency>"
        "</dependencies>"
        "</project>"
    )
    p = parse_pom_xml(pom)
    assert len(p.dependencies) == 2
    d0 = p.dependencies[0]
    assert d0.group_id == "org.foo"
    assert d0.artifact_id == "bar"
    assert d0.version == "1.2.3"
    assert d0.scope == "compile"
    assert p.dependencies[1].scope == "test"


def test_parse_dependency_missing_scope_defaults():
    pom = (
        "<project><groupId>g</groupId><artifactId>a</artifactId>"
        "<dependencies><dependency>"
        "<groupId>org.foo</groupId><artifactId>bar</artifactId>"
        "<version>1.0.0</version>"
        "</dependency></dependencies></project>"
    )
    p = parse_pom_xml(pom)
    assert p.dependencies[0].scope == "compile"


def test_parse_broken_xml_returns_invalid():
    assert parse_pom_xml("<project><unclosed>").valid is False


def test_parse_empty_returns_invalid():
    assert parse_pom_xml("").valid is False
    assert parse_pom_xml(None).valid is False


def test_parse_non_project_root_returns_invalid():
    assert parse_pom_xml("<notproject></notproject>").valid is False


def test_to_dict_is_json_friendly():
    p = parse_pom_xml(MINIMAL_POM)
    d = p.to_dict()
    assert d["artifact_id"] == "demo"
    assert isinstance(d["dependencies"], list)
