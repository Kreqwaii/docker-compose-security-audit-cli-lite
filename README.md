# docker-compose-security-audit-cli-lite

Zero-dependency Python 3.9+ CLI tool to audit `docker-compose.yml` files for security vulnerabilities, misconfigurations, and production-readiness gaps.

## Features

- **100% Python Standard Library**: No `pip install`, no `PyYAML`, no external dependencies.
- **Built-in Compose YAML Parser**: Parses services, nested mappings, lists, inline arrays, environment variables, ports, and deploy limits.
- **12 Security & Production Checks**:
  - `DC001` (CRITICAL): Privileged container (`privileged: true`)
  - `DC002` (HIGH): Host network mode (`network_mode: host`)
  - `DC003` (CRITICAL): Docker daemon socket mount (`/var/run/docker.sock`)
  - `DC004` (MEDIUM): Unpinned or `:latest` image tags
  - `DC005` (HIGH): Hardcoded passwords, API keys, or tokens in `environment`
  - `DC006` (LOW): Missing `restart` or `deploy.restart_policy`
  - `DC007` (LOW): Missing `healthcheck`
  - `DC008` (MEDIUM): Missing CPU or memory resource limits
  - `DC009` (HIGH): Database ports (`5432`, `3306`, `27017`, `6379`, etc.) exposed on `0.0.0.0`
  - `DC010` (MEDIUM): Container running as `root` / missing `user`
  - `DC011` (HIGH): Host `pid` or `ipc` namespace sharing
  - `DC012` (INFO): Writable root filesystem (`read_only: true` not set)
- **CI/CD Ready**: Supports `text`, `json`, and `markdown` output formats with configurable `--fail-on` severity exit codes.

## Quick Start

```bash
# Audit default docker-compose.yml
python compose_audit.py

# Audit a specific file with JSON output
python compose_audit.py sample_compose/insecure-docker-compose.yml --format json

# Generate a Markdown report for Pull Requests
python compose_audit.py sample_compose/insecure-docker-compose.yml --format markdown --fail-on medium
```

## Running Tests

```bash
python -m unittest discover -s tests -v
```

## Pro Studio Version (Web Dashboard + HTML Audit Reports + Policy Presets)

Need team-wide compliance policies, interactive Web Dashboard, executive HTML/PDF audit reports, and custom rule presets?

Check out the **Pro Studio Version** on our storefront:
👉 [https://funpay.com/users/20096179/](https://funpay.com/users/20096179/)

## License

MIT License — see [LICENSE](LICENSE) for details.
