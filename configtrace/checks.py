from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


@dataclass(frozen=True)
class Finding:
    code: str
    message: str
    file: str


@dataclass(frozen=True)
class VaultReference:
    variable: str
    path: str
    key: str


LOOKUP_RE = re.compile(r"lookup\s*\(", re.IGNORECASE)
SECRET_RE = re.compile(r"secret\s*=\s*([^:'\"\s]+):([^'\"\s,)]+)")
TEMPLATE_RE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*\{\{\s*([A-Za-z_][A-Za-z0-9_]*)\s*\}\}\s*$")
COMPOSE_RE = re.compile(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?")


def _load_yaml(path: Path) -> list[Any]:
    try:
        return list(yaml.safe_load_all(path.read_text(encoding="utf-8")))
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        location = f" at line {mark.line + 1}" if mark is not None else ""
        raise ValueError(f"could not parse YAML file {path}{location}") from None
    except OSError as exc:
        raise ValueError(f"could not read YAML file {path}: {exc.strerror or 'file access failed'}") from None


def _walk_scalar_pairs(value: Any):
    if isinstance(value, dict):
        for key, child in value.items():
            if isinstance(key, str) and isinstance(child, str):
                yield key, child
            yield from _walk_scalar_pairs(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_scalar_pairs(child)


def _find_vault_references(path: Path) -> dict[str, VaultReference]:
    references: dict[str, VaultReference] = {}
    for document in _load_yaml(path):
        if not isinstance(document, dict):
            continue
        for variable, scalar in _walk_scalar_pairs(document):
            if not LOOKUP_RE.search(scalar):
                continue
            match = SECRET_RE.search(scalar)
            if match:
                references[variable] = VaultReference(variable, match.group(1), match.group(2))
    return references


def _find_template_mappings(path: Path) -> dict[str, str]:
    mappings: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        match = TEMPLATE_RE.match(line)
        if match:
            env_name, variable = match.groups()
            mappings[env_name] = variable
    return mappings


def _find_compose_environment(path: Path, service_name: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for document in _load_yaml(path):
        if not isinstance(document, dict):
            continue
        services = document.get("services", {})
        if not isinstance(services, dict):
            continue
        service = services.get(service_name, {})
        if not isinstance(service, dict):
            continue
        environment = service.get("environment", {})
        if isinstance(environment, dict):
            for name, value in environment.items():
                if not isinstance(name, str):
                    continue
                if value is None:
                    result[name] = name
                elif isinstance(value, str):
                    match = COMPOSE_RE.fullmatch(value.strip())
                    if match:
                        result[name] = match.group(1)
        elif isinstance(environment, list):
            for item in environment:
                if not isinstance(item, str):
                    continue
                if "=" not in item:
                    result[item] = item
                    continue
                name, value = item.split("=", 1)
                match = COMPOSE_RE.fullmatch(value.strip())
                if match:
                    result[name] = match.group(1)
    return result


def _kubernetes_external_secrets(path: Path) -> dict[str, set[str]]:
    """Return only declared target secret names and key names, never secret values."""
    result: dict[str, set[str]] = {}
    for document in _load_yaml(path):
        if not isinstance(document, dict) or document.get("kind") != "ExternalSecret":
            continue
        metadata = document.get("metadata", {})
        spec = document.get("spec", {})
        target = spec.get("target", {}) if isinstance(spec, dict) else {}
        target_name = target.get("name") if isinstance(target, dict) else None
        if not target_name and isinstance(metadata, dict):
            target_name = metadata.get("name")
        data = spec.get("data", []) if isinstance(spec, dict) else []
        if not isinstance(target_name, str) or not isinstance(data, list):
            continue
        keys = result.setdefault(target_name, set())
        for item in data:
            if isinstance(item, dict) and isinstance(item.get("secretKey"), str):
                keys.add(item["secretKey"])
    return result


def _kubernetes_references(path: Path) -> list[tuple[str, str]]:
    references: list[tuple[str, str]] = []
    for document in _load_yaml(path):
        if not isinstance(document, dict):
            continue
        _collect_secret_refs(document, references)
    return references


def _collect_secret_refs(value: Any, found: list[tuple[str, str]]) -> None:
    if isinstance(value, dict):
        reference = value.get("secretKeyRef")
        if isinstance(reference, dict):
            name, key = reference.get("name"), reference.get("key")
            if isinstance(name, str) and isinstance(key, str):
                found.append((name, key))
        for child in value.values():
            _collect_secret_refs(child, found)
    elif isinstance(value, list):
        for child in value:
            _collect_secret_refs(child, found)


def _project_file(project_dir: Path, relative: Any, label: str) -> Path:
    if not isinstance(relative, str) or not relative:
        raise ValueError(f"configtrace.yml must define a file path for {label}")
    root = project_dir.resolve()
    path = (root / relative).resolve()
    if path != root and root not in path.parents:
        raise ValueError(f"file path for {label} must stay inside the project folder")
    return path


def run_checks(project_dir: Path) -> list[Finding]:
    project_dir = project_dir.resolve()
    project_file = project_dir / "configtrace.yml"
    project = _load_yaml(project_file)[0]
    if not isinstance(project, dict):
        raise ValueError("configtrace.yml must contain a YAML mapping")

    ansible_file = _project_file(project_dir, project.get("ansible"), "ansible")
    template_file = _project_file(project_dir, project.get("template"), "template")
    compose_file = _project_file(project_dir, project.get("compose"), "compose")
    service_name = project.get("service")
    findings: list[Finding] = []

    for path in (ansible_file, template_file, compose_file):
        if not path.is_file():
            findings.append(Finding("FILE_MISSING", f"Required file was not found: {path.relative_to(project_dir)}", str(path.relative_to(project_dir))))
    if findings:
        return findings

    vault = _find_vault_references(ansible_file)
    template = _find_template_mappings(template_file)
    compose = _find_compose_environment(compose_file, service_name)

    for env_name, variable in template.items():
        reference = vault.get(variable)
        if reference is None:
            findings.append(Finding("VAULT_SOURCE_MISSING", f"Template key {env_name} uses {variable}, but no Vault lookup for that variable was found.", str(template_file.relative_to(project_dir))))
        elif env_name not in compose:
            findings.append(Finding("COMPOSE_KEY_MISSING", f"Compose service {service_name} does not read environment key {env_name}.", str(compose_file.relative_to(project_dir))))
        elif compose[env_name] != env_name:
            findings.append(Finding("COMPOSE_NAME_MISMATCH", f"Compose key {env_name} reads {compose[env_name]} instead of {env_name}.", str(compose_file.relative_to(project_dir))))

    for variable, reference in vault.items():
        if variable not in template.values():
            findings.append(Finding("TEMPLATE_MAPPING_MISSING", f"Vault variable {variable} from {reference.path}:{reference.key} is not mapped by the template.", str(template_file.relative_to(project_dir))))

    kubernetes_files = project.get("kubernetes", [])
    if not isinstance(kubernetes_files, list):
        raise ValueError("configtrace.yml must list Kubernetes files under kubernetes")
    declared_secrets: dict[str, set[str]] = {}
    existing_kubernetes_files: list[tuple[str, Path]] = []
    for relative in kubernetes_files:
        path = _project_file(project_dir, relative, "kubernetes")
        if not path.is_file():
            findings.append(Finding("FILE_MISSING", f"Kubernetes file was not found: {relative}", str(relative)))
            continue
        existing_kubernetes_files.append((relative, path))
        for name, keys in _kubernetes_external_secrets(path).items():
            declared_secrets.setdefault(name, set()).update(keys)

    for relative, path in existing_kubernetes_files:
        for secret_name, key in _kubernetes_references(path):
            if secret_name not in declared_secrets:
                findings.append(Finding("EXTERNAL_SECRET_MISSING", f"Workload references secret {secret_name}, but no ExternalSecret target with that name was found.", str(relative)))
            elif key not in declared_secrets[secret_name]:
                findings.append(Finding("EXTERNAL_SECRET_KEY_MISSING", f"Workload references key {key} in secret {secret_name}, but that key is not declared by its ExternalSecret.", str(relative)))

    return findings
