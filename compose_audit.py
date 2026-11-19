#!/usr/bin/env python3
"""
docker-compose-security-audit-cli-lite
100% Python 3.9+ stdlib CLI tool for auditing docker-compose.yml files
for security vulnerabilities and production-readiness issues.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
DB_PORTS = {"5432", "3306", "27017", "6379", "9200", "5984", "1433", "1521", "9042"}
SECRET_KEY_PATTERNS = re.compile(
    r"(password|passwd|pwd|secret|api_key|apikey|token|private_key|auth_key|access_key|db_pass)",
    re.IGNORECASE,
)
ENV_VAR_REF_PATTERN = re.compile(r"^\$\{?[A-Za-z_][A-Za-z0-9_]*(?::[-?]?[^}]*)?\}?$")


@dataclass
class Finding:
    rule_id: str
    severity: str
    service: str
    title: str
    description: str
    remediation: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class SimpleYAMLParser:
    """
    Lightweight Python stdlib-only YAML subset parser tailored for docker-compose.yml.
    Supports mappings, sequences (- item), inline lists ([a, b]), inline dicts ({k: v}),
    quoted strings, booleans, numbers, comments, and multi-line indentation.
    """

    def parse(self, text: str) -> Dict[str, Any]:
        raw_lines = text.splitlines()
        tokens: List[Tuple[int, str]] = []
        for raw in raw_lines:
            stripped = self._strip_comment(raw)
            if not stripped.strip():
                continue
            indent = len(raw) - len(raw.lstrip(" "))
            tokens.append((indent, stripped.strip()))

        if not tokens:
            return {}

        value, _ = self._parse_block(tokens, 0, tokens[0][0])
        if isinstance(value, dict):
            return value
        return {"root": value}

    def _strip_comment(self, line: str) -> str:
        in_single = False
        in_double = False
        for i, ch in enumerate(line):
            if ch == "'" and not in_double:
                in_single = not in_single
            elif ch == '"' and not in_single:
                in_double = not in_double
            elif ch == "#" and not in_single and not in_double:
                if i == 0 or line[i - 1].isspace():
                    return line[:i]
        return line

    def _parse_block(self, tokens: List[Tuple[int, str]], idx: int, base_indent: int) -> Tuple[Any, int]:
        if idx >= len(tokens):
            return {}, idx

        _, first_content = tokens[idx]
        if first_content.startswith("- ") or first_content == "-":
            return self._parse_list(tokens, idx, base_indent)
        return self._parse_dict(tokens, idx, base_indent)

    def _parse_list(self, tokens: List[Tuple[int, str]], idx: int, base_indent: int) -> Tuple[List[Any], int]:
        items: List[Any] = []
        while idx < len(tokens):
            indent, content = tokens[idx]
            if indent < base_indent:
                break
            if indent > base_indent:
                break
            if not (content.startswith("- ") or content == "-"):
                break

            rest = content[1:].strip() if content == "-" else content[2:].strip()
            idx += 1

            if not rest:
                if idx < len(tokens) and tokens[idx][0] > indent:
                    nested, idx = self._parse_block(tokens, idx, tokens[idx][0])
                    items.append(nested)
                else:
                    items.append(None)
            elif ":" in rest and not self._is_quoted(rest) and not rest.startswith("{"):
                k, v = self._split_kv(rest)
                item_dict: Dict[str, Any] = {}
                if v == "":
                    if idx < len(tokens) and tokens[idx][0] > indent:
                        nested, idx = self._parse_block(tokens, idx, tokens[idx][0])
                        item_dict[k] = nested
                    else:
                        item_dict[k] = None
                else:
                    item_dict[k] = self._parse_scalar(v)

                if idx < len(tokens) and tokens[idx][0] > indent:
                    more, idx = self._parse_dict(tokens, idx, tokens[idx][0])
                    if isinstance(more, dict):
                        item_dict.update(more)
                items.append(item_dict)
            else:
                items.append(self._parse_scalar(rest))
        return items, idx

    def _parse_dict(self, tokens: List[Tuple[int, str]], idx: int, base_indent: int) -> Tuple[Dict[str, Any], int]:
        result: Dict[str, Any] = {}
        while idx < len(tokens):
            indent, content = tokens[idx]
            if indent < base_indent:
                break
            if indent > base_indent:
                break
            if content.startswith("- ") or content == "-":
                break
            if ":" not in content:
                idx += 1
                continue

            key, val = self._split_kv(content)
            idx += 1

            if val == "" or val in ("|", ">", "|-", ">-"):
                if idx < len(tokens) and tokens[idx][0] > indent:
                    nested, idx = self._parse_block(tokens, idx, tokens[idx][0])
                    result[key] = nested
                else:
                    result[key] = {}
            else:
                result[key] = self._parse_scalar(val)
        return result, idx

    def _split_kv(self, text: str) -> Tuple[str, str]:
        in_single = False
        in_double = False
        for i, ch in enumerate(text):
            if ch == "'" and not in_double:
                in_single = not in_single
            elif ch == '"' and not in_single:
                in_double = not in_double
            elif ch == ":" and not in_single and not in_double:
                if i + 1 == len(text) or text[i + 1].isspace():
                    key = self._unquote(text[:i].strip())
                    val = text[i + 1 :].strip()
                    return key, val
        return self._unquote(text.strip()), ""

    def _is_quoted(self, text: str) -> bool:
        return (text.startswith('"') and text.endswith('"')) or (
            text.startswith("'") and text.endswith("'")
        )

    def _unquote(self, text: str) -> str:
        if len(text) >= 2 and self._is_quoted(text):
            return text[1:-1]
        return text

    def _parse_scalar(self, val: str) -> Any:
        val = val.strip()
        if not val:
            return ""
        if self._is_quoted(val):
            return val[1:-1]
        if val.startswith("[") and val.endswith("]"):
            inner = val[1:-1].strip()
            if not inner:
                return []
            return [self._parse_scalar(p.strip()) for p in inner.split(",")]
        if val.startswith("{") and val.endswith("}"):
            inner = val[1:-1].strip()
            if not inner:
                return {}
            out: Dict[str, Any] = {}
            for part in inner.split(","):
                if ":" in part:
                    k, v = self._split_kv(part.strip())
                    out[k] = self._parse_scalar(v)
            return out
        low = val.lower()
        if low in ("true", "yes", "on"):
            return True
        if low in ("false", "no", "off"):
            return False
        if low in ("null", "~"):
            return None
        if re.fullmatch(r"-?\d+", val):
            return int(val)
        if re.fullmatch(r"-?\d+\.\d+", val):
            return float(val)
        return val


def _normalize_env(env: Any) -> Dict[str, str]:
    result: Dict[str, str] = {}
    if isinstance(env, dict):
        for k, v in env.items():
            result[str(k)] = "" if v is None else str(v)
    elif isinstance(env, list):
        for item in env:
            s = str(item)
            if "=" in s:
                k, v = s.split("=", 1)
                result[k.strip()] = v.strip()
            else:
                result[s.strip()] = ""
    return result


def audit_compose(data: Dict[str, Any]) -> List[Finding]:
    findings: List[Finding] = []
    services = data.get("services")
    if not isinstance(services, dict):
        return findings

    for svc_name, svc in services.items():
        if not isinstance(svc, dict):
            continue

        # 1. Privileged mode
        if svc.get("privileged") is True:
            findings.append(
                Finding(
                    rule_id="DC001",
                    severity="CRITICAL",
                    service=svc_name,
                    title="Privileged container enabled",
                    description="Container runs with 'privileged: true', granting full host kernel capabilities.",
                    remediation="Remove 'privileged: true' and use granular 'cap_add' only if strictly required.",
                )
            )

        # 2. Host network mode
        if str(svc.get("network_mode", "")).lower() == "host":
            findings.append(
                Finding(
                    rule_id="DC002",
                    severity="HIGH",
                    service=svc_name,
                    title="Host network mode enabled",
                    description="Service uses 'network_mode: host', bypassing Docker network isolation.",
                    remediation="Use bridge or custom overlay networks and expose only required ports.",
                )
            )

        # 3. Docker socket mount
        volumes = svc.get("volumes") or []
        if isinstance(volumes, list):
            for vol in volumes:
                vol_str = str(vol.get("source", "")) if isinstance(vol, dict) else str(vol)
                if "docker.sock" in vol_str:
                    findings.append(
                        Finding(
                            rule_id="DC003",
                            severity="CRITICAL",
                            service=svc_name,
                            title="Docker socket mounted inside container",
                            description=f"Volume '{vol_str}' exposes the host Docker daemon socket, allowing full host takeover.",
                            remediation="Avoid mounting /var/run/docker.sock; use a restricted Docker socket proxy if needed.",
                        )
                    )
                    break

        # 4. Latest or untagged image
        image = svc.get("image")
        if isinstance(image, str) and image.strip():
            img = image.strip()
            last_part = img.split("/")[-1]
            if ":" not in last_part or last_part.endswith(":latest"):
                findings.append(
                    Finding(
                        rule_id="DC004",
                        severity="MEDIUM",
                        service=svc_name,
                        title="Unpinned or ':latest' image tag",
                        description=f"Image '{img}' uses ':latest' or omits a specific version tag.",
                        remediation="Pin images to an immutable version tag or SHA256 digest.",
                    )
                )

        # 5. Hardcoded secrets in environment
        env_map = _normalize_env(svc.get("environment"))
        for k, v in env_map.items():
            if SECRET_KEY_PATTERNS.search(k) and v:
                if not ENV_VAR_REF_PATTERN.match(v):
                    findings.append(
                        Finding(
                            rule_id="DC005",
                            severity="HIGH",
                            service=svc_name,
                            title="Hardcoded secret in environment variable",
                            description=f"Environment variable '{k}' appears to contain a hardcoded secret value.",
                            remediation="Use Docker secrets or variable substitution (e.g., ${DB_PASSWORD}).",
                        )
                    )

        # 6. Missing restart policy
        deploy = svc.get("deploy") if isinstance(svc.get("deploy"), dict) else {}
        has_restart = bool(svc.get("restart")) or bool(deploy.get("restart_policy"))
        if not has_restart:
            findings.append(
                Finding(
                    rule_id="DC006",
                    severity="LOW",
                    service=svc_name,
                    title="Missing restart policy",
                    description="Service has no 'restart' or 'deploy.restart_policy' configured.",
                    remediation="Set 'restart: unless-stopped' or 'deploy.restart_policy.condition: on-failure'.",
                )
            )

        # 7. Missing healthcheck
        hc = svc.get("healthcheck")
        if not hc or (isinstance(hc, dict) and hc.get("disable") is True):
            findings.append(
                Finding(
                    rule_id="DC007",
                    severity="LOW",
                    service=svc_name,
                    title="Missing container healthcheck",
                    description="Service does not define a 'healthcheck' probe for orchestration readiness.",
                    remediation="Add a 'healthcheck' block with 'test', 'interval', 'timeout', and 'retries'.",
                )
            )

        # 8. Missing memory / CPU resource limits
        resources = deploy.get("resources") if isinstance(deploy.get("resources"), dict) else {}
        limits = resources.get("limits") if isinstance(resources.get("limits"), dict) else {}
        has_mem_limit = bool(svc.get("mem_limit")) or bool(limits.get("memory"))
        has_cpu_limit = bool(svc.get("cpus")) or bool(limits.get("cpus"))
        if not (has_mem_limit and has_cpu_limit):
            findings.append(
                Finding(
                    rule_id="DC008",
                    severity="MEDIUM",
                    service=svc_name,
                    title="Missing CPU or memory resource limits",
                    description="Service lacks explicit memory and/or CPU limits, risking host resource exhaustion.",
                    remediation="Define 'deploy.resources.limits.memory' and 'deploy.resources.limits.cpus'.",
                )
            )

        # 9. Exposed database ports on 0.0.0.0
        ports = svc.get("ports") or []
        if isinstance(ports, list):
            for p in ports:
                p_str = str(p.get("published", "")) if isinstance(p, dict) else str(p)
                for db_port in DB_PORTS:
                    if re.search(rf"(^|:){db_port}(/|$)", p_str) and not p_str.startswith("127.0.0.1:"):
                        findings.append(
                            Finding(
                                rule_id="DC009",
                                severity="HIGH",
                                service=svc_name,
                                title="Database port exposed on all interfaces (0.0.0.0)",
                                description=f"Port mapping '{p_str}' exposes database port {db_port} publicly.",
                                remediation=f"Bind to localhost (e.g., '127.0.0.1:{db_port}:{db_port}') or use internal networks only.",
                            )
                        )
                        break

        # 10. Running as root user
        user = svc.get("user")
        if user is None or str(user).strip() in ("0", "root", "0:0", "root:root"):
            findings.append(
                Finding(
                    rule_id="DC010",
                    severity="MEDIUM",
                    service=svc_name,
                    title="Container may run as root user",
                    description="Service does not specify a non-root 'user' (or explicitly sets root/0).",
                    remediation="Set 'user: \"1000:1000\"' or a dedicated non-root UID:GID.",
                )
            )

        # 11. Host PID or IPC namespace sharing
        if str(svc.get("pid", "")).lower() == "host" or str(svc.get("ipc", "")).lower() == "host":
            findings.append(
                Finding(
                    rule_id="DC011",
                    severity="HIGH",
                    service=svc_name,
                    title="Host PID or IPC namespace shared",
                    description="Service shares host 'pid' or 'ipc' namespace, weakening process isolation.",
                    remediation="Remove 'pid: host' and 'ipc: host' unless performing low-level host diagnostics.",
                )
            )

        # 12. Writable root filesystem
        if svc.get("read_only") is not True:
            findings.append(
                Finding(
                    rule_id="DC012",
                    severity="INFO",
                    service=svc_name,
                    title="Root filesystem is writable",
                    description="Container root filesystem is not mounted as 'read_only: true'.",
                    remediation="Consider setting 'read_only: true' and mounting writable paths via 'tmpfs' or volumes.",
                )
            )

    findings.sort(key=lambda f: (-SEVERITY_ORDER.get(f.severity, 0), f.service, f.rule_id))
    return findings


def format_text(findings: List[Finding], file_path: str) -> str:
    if not findings:
        return f"[PASS] {file_path}: No security or production-readiness issues found."

    lines = [f"Docker Compose Security Audit: {file_path}", f"Total findings: {len(findings)}", "-" * 72]
    for f in findings:
        lines.append(f"[{f.severity}] {f.rule_id} ({f.service}) - {f.title}")
        lines.append(f"  Detail: {f.description}")
        lines.append(f"  Fix:    {f.remediation}")
    return "\n".join(lines)


def format_json(findings: List[Finding], file_path: str) -> str:
    counts: Dict[str, int] = {k: 0 for k in SEVERITY_ORDER}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    payload = {
        "file": file_path,
        "total_findings": len(findings),
        "summary": counts,
        "findings": [f.to_dict() for f in findings],
    }
    return json.dumps(payload, indent=2)


def format_markdown(findings: List[Finding], file_path: str) -> str:
    if not findings:
        return f"## Docker Compose Security Audit: `{file_path}`\n\nNo issues found."

    lines = [
        f"## Docker Compose Security Audit: `{file_path}`",
        "",
        f"**Total findings:** {len(findings)}",
        "",
        "| Severity | Rule | Service | Issue | Remediation |",
        "| --- | --- | --- | --- | --- |",
    ]
    for f in findings:
        lines.append(f"| **{f.severity}** | `{f.rule_id}` | `{f.service}` | {f.title} | {f.remediation} |")
    return "\n".join(lines)


def should_fail(findings: List[Finding], fail_on: str) -> bool:
    if fail_on == "none":
        return False
    threshold = SEVERITY_ORDER.get(fail_on.upper(), 3)
    return any(SEVERITY_ORDER.get(f.severity, 0) >= threshold for f in findings)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="compose-audit",
        description="Audit docker-compose.yml files for security and production-readiness.",
    )
    parser.add_argument("file", nargs="?", default="docker-compose.yml", help="Path to docker-compose.yml")
    parser.add_argument("-f", "--format", choices=["text", "json", "markdown"], default="text", help="Output format")
    parser.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low", "info", "none"],
        default="high",
        help="Minimum severity level to return non-zero exit code (default: high)",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    target = Path(args.file)
    if not target.is_file():
        print(f"Error: File not found: {args.file}", file=sys.stderr)
        return 2

    content = target.read_text(encoding="utf-8")
    parsed = SimpleYAMLParser().parse(content)
    findings = audit_compose(parsed)

    if args.format == "json":
        print(format_json(findings, str(target)))
    elif args.format == "markdown":
        print(format_markdown(findings, str(target)))
    else:
        print(format_text(findings, str(target)))

    return 1 if should_fail(findings, args.fail_on) else 0


if __name__ == "__main__":
    sys.exit(main())
