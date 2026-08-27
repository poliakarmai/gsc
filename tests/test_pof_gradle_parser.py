# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Алексей Поляков
# Licensed under Apache License 2.0 — see LICENSE

"""Tests for the Gradle (Groovy DSL) PoF project parser (Phase 14).

Covers:
  * detect_gradle_project: case-insensitive basename, POSIX + Windows paths,
    ignores non-string entries, returns False on empty list, REJECTS
    ``build.gradle.kts`` (Kotlin DSL is a different dialect).
  * parse_gradle: string-form (``scope 'g:a:v'``), named-form
    (``scope group: 'g', name: 'n', version: 'v'``), mixed scopes, empty /
    None / non-string input, missing ``dependencies`` block, ``//`` and
    ``/* */`` comments, partial / dynamic version (``'g:a'`` with no
    version), and a real-world example.
  * GradleProject.require_for() helper and to_dict() shape.
"""

import pytest

from gsc_cli.gsc_pof_gradle_parser import (
    GradleDependency,
    GradleProject,
    detect_gradle_project,
    parse_gradle,
)


# ── detect_gradle_project ─────────────────────────────────────────────────


def test_detect_gradle_project_with_build_gradle():
    assert detect_gradle_project(["src/main/java", "build.gradle", "README.md"]) is True


def test_detect_gradle_project_in_subdir():
    assert detect_gradle_project(["app/build.gradle", "settings.gradle"]) is True


def test_detect_gradle_project_empty_list():
    assert detect_gradle_project([]) is False


def test_detect_gradle_project_case_insensitive():
    assert detect_gradle_project(["BUILD.GRADLE"]) is True
    assert detect_gradle_project(["Build.Gradle"]) is True
    assert detect_gradle_project(["bUiLd.GrAdLe"]) is True


def test_detect_gradle_project_rejects_kotlin_dsl():
    # Kotlin DSL is a different dialect — handled by a separate module.
    assert detect_gradle_project(["build.gradle.kts"]) is False
    assert detect_gradle_project(["app/build.gradle.kts"]) is False
    assert detect_gradle_project(["BUILD.GRADLE.KTS"]) is False


def test_detect_gradle_project_rejects_other_files():
    assert detect_gradle_project(["package.json", "pom.xml", "build.xml"]) is False


def test_detect_gradle_project_handles_windows_paths():
    files = [
        "C:\\projects\\demo\\build.gradle",
        "src\\nested\\build.gradle",
        "/home/user/proj/build.gradle",
    ]
    assert detect_gradle_project(files) is True


def test_detect_gradle_project_ignores_non_string_entries():
    # Should not raise even when the list contains garbage.
    detect_gradle_project([None, 42, b"build.gradle", "build.gradle"])  # type: ignore[list-item]


def test_detect_gradle_project_rejects_substring_matches():
    # "mybuild.gradle" must NOT match — only an exact basename.
    assert detect_gradle_project(["mybuild.gradle", "build.gradle.bak"]) is False


# ── parse_gradle — happy path ─────────────────────────────────────────────


def test_parse_gradle_string_form():
    p = parse_gradle(
        "dependencies {\n"
        "    implementation 'com.google.guava:guava:32.1.2-jre'\n"
        "}\n"
    )
    assert isinstance(p, GradleProject)
    assert p.valid is True
    assert len(p.dependencies) == 1
    d = p.dependencies[0]
    assert d == GradleDependency(
        scope="implementation",
        group="com.google.guava",
        name="guava",
        version="32.1.2-jre",
    )


def test_parse_gradle_multiple_scopes_string_form():
    content = """dependencies {
    implementation 'org.springframework.boot:spring-boot-starter-web:3.2.0'
    testImplementation 'junit:junit:4.13.2'
    compileOnly 'org.projectlombok:lombok:1.18.30'
    runtimeOnly 'mysql:mysql-connector-java:8.0.33'
    annotationProcessor 'org.projectlombok:lombok:1.18.30'
    api 'org.apache.commons:commons-lang3:3.14.0'
}
"""
    p = parse_gradle(content)
    assert p.valid is True
    assert len(p.dependencies) == 6
    assert p.dependencies[0].scope == "implementation"
    assert p.dependencies[0].name == "spring-boot-starter-web"
    assert p.dependencies[1].scope == "testImplementation"
    assert p.dependencies[1].name == "junit"
    assert p.dependencies[2].scope == "compileOnly"
    assert p.dependencies[3].scope == "runtimeOnly"
    assert p.dependencies[4].scope == "annotationProcessor"
    assert p.dependencies[5].scope == "api"
    assert p.dependencies[5].name == "commons-lang3"


def test_parse_gradle_named_form():
    p = parse_gradle(
        "dependencies {\n"
        "    implementation group: 'org.slf4j', name: 'slf4j-api', version: '2.0.9'\n"
        "}\n"
    )
    assert p.valid is True
    assert len(p.dependencies) == 1
    assert p.dependencies[0] == GradleDependency(
        scope="implementation",
        group="org.slf4j",
        name="slf4j-api",
        version="2.0.9",
    )


def test_parse_gradle_mixed_string_and_named_forms():
    content = """dependencies {
    implementation 'com.google.guava:guava:32.1.2-jre'
    api group: 'org.apache.commons:commons-lang3', name: 'commons-lang3', version: '3.14.0'
    testImplementation 'junit:junit:4.13.2'
}
"""
    p = parse_gradle(content)
    assert p.valid is True
    assert len(p.dependencies) == 3
    assert p.dependencies[0].name == "guava"
    assert p.dependencies[0].version == "32.1.2-jre"
    assert p.dependencies[1].name == "commons-lang3"
    assert p.dependencies[1].version == "3.14.0"
    assert p.dependencies[2].name == "junit"


# ── parse_gradle — error & edge cases ─────────────────────────────────────


def test_parse_gradle_empty_string():
    p = parse_gradle("")
    assert p.valid is False
    assert p.dependencies == []


def test_parse_gradle_whitespace_only():
    p = parse_gradle("   \n\t  \n")
    assert p.valid is False
    assert p.dependencies == []


def test_parse_gradle_none_input():
    p = parse_gradle(None)  # type: ignore[arg-type]
    assert p.valid is False
    assert p.dependencies == []


def test_parse_gradle_non_string_input():
    p = parse_gradle(12345)  # type: ignore[arg-type]
    assert p.valid is False
    assert p.dependencies == []


def test_parse_gradle_no_dependencies_block():
    # The plugins block is not the dependencies block.
    content = """plugins {
    id 'java'
    id 'org.springframework.boot' version '3.2.0'
}

repositories {
    mavenCentral()
}
"""
    p = parse_gradle(content)
    assert p.valid is False
    assert p.dependencies == []


def test_parse_gradle_dependencies_block_with_garbage_only():
    # An empty / non-deps dependencies block is still not "valid".
    content = """dependencies {
    // nothing yet
}
"""
    p = parse_gradle(content)
    assert p.valid is False
    assert p.dependencies == []


# ── parse_gradle — comments ───────────────────────────────────────────────


def test_parse_gradle_strips_line_comments():
    content = """dependencies {
    // web framework
    implementation 'org.springframework.boot:spring-boot-starter-web:3.2.0'  // web
    testImplementation 'junit:junit:4.13.2'
}
"""
    p = parse_gradle(content)
    assert p.valid is True
    assert len(p.dependencies) == 2
    assert p.dependencies[0].name == "spring-boot-starter-web"
    assert p.dependencies[1].name == "junit"


def test_parse_gradle_strips_block_comments():
    content = """dependencies {
    /* core logging */
    implementation 'org.slf4j:slf4j-api:2.0.9'
    /* multi
       line block
       comment */
    testImplementation 'junit:junit:4.13.2'
}
"""
    p = parse_gradle(content)
    assert p.valid is True
    assert len(p.dependencies) == 2
    assert p.dependencies[0].name == "slf4j-api"
    assert p.dependencies[1].name == "junit"


# ── to_dict / require_for ────────────────────────────────────────────────


def test_parse_gradle_to_dict_roundtrip():
    p = parse_gradle(
        "dependencies {\n"
        "    implementation 'com.google.guava:guava:32.1.2-jre'\n"
        "}\n"
    )
    d = p.to_dict()
    assert d == {
        "valid": True,
        "dependencies": [
            {
                "scope": "implementation",
                "group": "com.google.guava",
                "name": "guava",
                "version": "32.1.2-jre",
            }
        ],
    }


def test_gradle_project_require_for_found():
    p = parse_gradle(
        "dependencies {\n"
        "    implementation 'com.google.guava:guava:32.1.2-jre'\n"
        "    testImplementation 'junit:junit:4.13.2'\n"
        "}\n"
    )
    dep = p.require_for("junit")
    assert dep is not None
    assert dep.group == "junit"
    assert dep.version == "4.13.2"
    assert dep.scope == "testImplementation"


def test_gradle_project_require_for_not_found():
    p = parse_gradle(
        "dependencies {\n"
        "    implementation 'com.google.guava:guava:32.1.2-jre'\n"
        "}\n"
    )
    assert p.require_for("nonexistent-artifact") is None


# ── parse_gradle — partial / dynamic versions ────────────────────────────


def test_parse_gradle_string_form_without_version():
    """A dynamic dependency (``'g:a'`` with no version) is still parsed.

    The PoF orchestrator can later decide what to do with an empty
    version; the parser's job is just to keep the entry.
    """
    p = parse_gradle(
        "dependencies {\n"
        "    implementation 'com.google.guava:guava'\n"
        "}\n"
    )
    assert p.valid is True
    assert len(p.dependencies) == 1
    assert p.dependencies[0].group == "com.google.guava"
    assert p.dependencies[0].name == "guava"
    assert p.dependencies[0].version == ""


def test_parse_gradle_named_form_without_version():
    p = parse_gradle(
        "dependencies {\n"
        "    api group: 'org.apache.commons', name: 'commons-lang3'\n"
        "}\n"
    )
    assert p.valid is True
    assert p.dependencies[0].name == "commons-lang3"
    assert p.dependencies[0].version == ""


# ── parse_gradle — real-world example ────────────────────────────────────


def test_parse_gradle_real_world_example():
    content = """plugins {
    id 'java'
    id 'org.springframework.boot' version '3.2.0'
}

group = 'com.example'
version = '1.0.0'

repositories {
    mavenCentral()
}

dependencies {
    implementation 'org.springframework.boot:spring-boot-starter-web:3.2.0'
    implementation 'com.google.guava:guava:32.1.2-jre'
    testImplementation 'junit:junit:4.13.2'
    testImplementation 'org.springframework.boot:spring-boot-starter-test:3.2.0'
    compileOnly 'org.projectlombok:lombok:1.18.30'
    runtimeOnly 'com.mysql:mysql-connector-j:8.2.0'
    annotationProcessor 'org.projectlombok:lombok:1.18.30'
    api group: 'org.slf4j', name: 'slf4j-api', version: '2.0.9'
}
"""
    p = parse_gradle(content)
    assert p.valid is True
    # 8 dependencies total — mix of string- and named-form.
    assert len(p.dependencies) == 8
    # The named-form entry is the LAST one.
    assert p.dependencies[-1].name == "slf4j-api"
    assert p.dependencies[-1].scope == "api"
    # String-form entries all have non-empty versions.
    assert p.dependencies[0].version == "3.2.0"
    # The duplicate lombok entry (compileOnly + annotationProcessor) is
    # both kept — that's the parser's contract; the orchestrator decides
    # whether to dedupe.
    lombok = [d for d in p.dependencies if d.name == "lombok"]
    assert len(lombok) == 2
    assert {d.scope for d in lombok} == {"compileOnly", "annotationProcessor"}


def test_parse_gradle_skips_buildscript_dependencies():
    # Regression (judge finding): a `buildscript { dependencies { ... } }`
    # block (Spring Boot plugin classpath) must NOT stop the scan — the
    # top-level runtime `dependencies { ... }` block still gets parsed.
    content = (
        "buildscript {\n"
        "    dependencies {\n"
        "        classpath 'org.springframework.boot:spring-boot-gradle-plugin:3.2.0'\n"
        "    }\n"
        "}\n"
        "\n"
        "dependencies {\n"
        "    implementation 'org.springframework.boot:spring-boot-starter-web:3.2.0'\n"
        "    implementation 'com.google.guava:guava:32.1.2-jre'\n"
        "}\n"
    )
    p = parse_gradle(content)
    assert p.valid is True
    names = [d.name for d in p.dependencies]
    assert names == ["spring-boot-starter-web", "guava"]
    assert "spring-boot-gradle-plugin" not in names


def test_parse_gradle_double_quoted_string_form():
    # Groovy DSL accepts both single and double quotes for the string form.
    content = (
        "dependencies {\n"
        '    implementation "com.google.guava:guava:32.1.2-jre"\n'
        "}\n"
    )
    p = parse_gradle(content)
    assert p.valid is True
    assert len(p.dependencies) == 1
    assert p.dependencies[0].group == "com.google.guava"
    assert p.dependencies[0].name == "guava"
    assert p.dependencies[0].version == "32.1.2-jre"
