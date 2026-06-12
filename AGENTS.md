# AegisPanel Agent Rules

- Keep AegisPanel adapter-based and panel-agnostic.
- Marzban is one adapter, not the whole product.
- three-x-ui/Sanaei must use adapter dispatch, not Marzban-specific logic.
- SuperAdmin owns upstream panels.
- Admin/Reseller creates customer VPN users within assigned panel, quota, and validity.
- Reseller routes must stay scoped to assigned panel and owned users.
- Remote create, update, and delete must not silently fall back to local-only for real panels.
- Do not expose panel credentials, cookies, tokens, or raw protocol links.
- `subscriptionUrl` must be a safe HTTP/HTTPS public subscription URL, never `vless://`, `vmess://`, `trojan://`, `ss://`, `hysteria://`, or `hy2://`.
- Do not touch the Resellers page unless a story explicitly requires it.
- Before commit run:
  - `npm test`
  - `git --no-pager diff --check`
