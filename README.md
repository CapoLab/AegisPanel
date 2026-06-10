# AegisPanel

AegisPanel is a commercial-ready infrastructure control panel for subscription-based operators.

The goal is to build a clean, original, installable product with licensing, reseller workflows, reliable traffic accounting, and Docker-first deployment.

## Status

Initial project setup. Public planning and installation docs will live here as the product takes shape.

## Product Direction

- Super admin and admin workflows
- Reseller management
- Subscription and license enforcement
- Traffic accounting and return logic
- Docker-first installation
- Clean public documentation
- Secure defaults for production deployments

## Install Target

The public install path will be Docker-first.

Planned shape:

```bash
git clone https://github.com/YOUNGGUNNAA/AegisPanel.git
cd AegisPanel
docker compose up -d
```

These commands are a target interface, not a finished installer yet.

## Project Rules

- Original product name and branding only
- No inherited project names in code, docs, UI, commits, or release notes
- No secrets, credentials, server IPs, or customer data in public commits
- Commercial licensing model before public production release
- Every install step must be documented before release

## Roadmap

1. Define clean architecture and repository structure
2. Build Docker-ready backend and frontend foundation
3. Implement admin and reseller workflows
4. Add license and subscription enforcement
5. Harden deployment, logs, backups, and update flow
6. Publish installation docs and first release notes

## License

No public license is granted yet. Commercial and evaluation terms will be published before the first production release.
