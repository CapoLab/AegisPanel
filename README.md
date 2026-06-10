# AegisPanel

AegisPanel is a commercial-ready infrastructure control panel for subscription-based operators.

The goal is to build a clean, original, installable product with licensing, reseller workflows, reliable traffic accounting, and Docker-first deployment.

## Status

Foundation build is in progress. The repository now contains an original Node.js control surface with API routes, a responsive web UI, Docker deployment, an installer command, audit logs, backup export, panel adapter contracts, role-based access, traffic accounting, and Community Edition distribution mode.

## Product Direction

- Super admin and admin workflows
- Reseller management
- Subscription workflows
- Community Edition distribution with paid licensing disabled for the initial public period
- Traffic accounting and return logic
- Delete-return and update-return traffic controls
- Adapter layer for 3x-ui, Tx-ui, Marzban, Guard, and S-ui
- Backup, logs, news, system info, and audit operations
- Docker-first installation
- Clean public documentation
- Secure defaults for production deployments

## Quick Start

```bash
git clone https://github.com/CapoLab/AegisPanel.git
cd AegisPanel
cp .env.example .env
npm install
npm start
```

Open `http://localhost:8080`.

Default credentials come from `.env`:

```env
AEGIS_ADMIN_USERNAME=admin
AEGIS_ADMIN_PASSWORD=change-me-now
```

## Docker

```bash
git clone https://github.com/CapoLab/AegisPanel.git
cd AegisPanel
cp .env.example .env
docker compose up -d
```

## One-Line Installer Target

```bash
bash <(curl -s https://raw.githubusercontent.com/CapoLab/AegisPanel/main/install.sh)
```

After installation:

```bash
aegis-panel start
aegis-panel stop
aegis-panel restart
aegis-panel update
aegis-panel logs
aegis-panel status
aegis-panel edit-env
aegis-panel backup
```

## Project Rules

- Original product name and branding only
- No inherited project names in code, docs, UI, commits, or release notes
- External panels/projects may inform behavior only; do not copy code, UI text, naming, or structure
- No secrets, credentials, server IPs, or customer data in public commits
- Commercial licensing model before public production release
- Every install step must be documented before release

## API Foundation

- `POST /api/auth/login`
- `GET /api/dashboard`
- `GET /api/meta`
- `GET /api/health`
- `GET|POST /api/superadmin/admins`
- `PUT|DELETE /api/superadmin/admins/:id`
- `GET|POST /api/superadmin/panels`
- `PUT|DELETE /api/superadmin/panels/:id`
- `GET /api/superadmin/panels/:id/inbounds`
- `POST /api/panels/:id/sync`
- `GET|POST /api/admin/users`
- `PUT|DELETE /api/admin/users/:id`
- `GET /api/superadmin/backup`
- `GET /api/superadmin/logs`
- `GET /api/superadmin/system`
- `GET|POST /api/superadmin/news`
- `GET /api/community`

See [docs/FEATURE-MATRIX.md](docs/FEATURE-MATRIX.md).

## Roadmap

1. Replace MVP JSON storage with SQLite/Postgres migrations
2. Encrypt panel credentials at rest
3. Implement real connector clients for supported panels
4. Add background sync with retry budgets and circuit breakers
5. Add granular reseller permissions and plan enforcement
6. Publish installation docs, release notes, and commercial terms

## License

No commercial terms are enforced during the initial free public period. Future paid terms can be published later without changing the Community Edition foundation.
