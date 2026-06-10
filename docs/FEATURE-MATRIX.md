# AegisPanel Feature Matrix

This project is an original implementation. External projects may inform the required behavior, but code, names, UI copy, and internal structure must stay unique to AegisPanel.

## Covered In The Foundation

- Role-based access with `superadmin` and `admin`.
- Unified dashboard metrics.
- Panel registry with adapters for `3x-ui`, `Tx-ui`, `Marzban`, `Guard`, and `S-ui`.
- Panel CRUD for super admins.
- Admin CRUD for super admins.
- User CRUD for operators and resellers.
- Traffic limit, used traffic, remaining traffic, expiry, inbound, flow, and subscription identifiers.
- Delete-return traffic accounting.
- Backup export.
- Audit logs.
- Community/free distribution state with commercial enforcement disabled.
- Docker-first deployment.
- Management command installer.
- Dark responsive UI.

## Designed Improvements

- One canonical adapter contract instead of panel-specific logic leaking into the UI.
- No product inheritance in names, docs, commands, or code.
- Atomic JSON writes for MVP storage.
- Password hashing with Node `scrypt`.
- Signed session auth without server-side session storage.
- Audit trail for security-sensitive operations.
- Community edition modeled from day one so paid licensing can be added later without affecting the free public release.
- `deleteReturnTraffic` and `updateReturnTraffic` modeled separately from day one.
- Panel type IDs use stable internal slugs, while UI labels can change freely.

## Next Production Hardening

- Replace JSON storage with SQLite/Postgres migrations.
- Encrypt panel secrets at rest.
- Add real connector implementations with retry budgets and circuit breakers.
- Add background sync scheduler.
- Add granular permissions per reseller/admin.
- Add automated browser tests and API contract tests.
- Add commercial activation only when the free public period ends.
