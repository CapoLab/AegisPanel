#!/usr/bin/env sh
set -eu

INSTALL_DIR="${INSTALL_DIR:-/opt/aegis-panel}"
REPO_URL="${REPO_URL:-https://github.com/CapoLab/AegisPanel.git}"
BIN_PATH="${BIN_PATH:-/usr/local/bin/aegis-panel}"

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Missing required command: $1" >&2
    exit 1
  }
}

need_cmd git
need_cmd docker

if ! docker compose version >/dev/null 2>&1; then
  echo "Docker Compose plugin is required." >&2
  exit 1
fi

mkdir -p "$INSTALL_DIR"
if [ ! -d "$INSTALL_DIR/.git" ]; then
  git clone "$REPO_URL" "$INSTALL_DIR"
else
  git -C "$INSTALL_DIR" pull --ff-only
fi

cd "$INSTALL_DIR"
if [ ! -f .env ]; then
  cp .env.example .env
  ADMIN_PASSWORD="$(openssl rand -hex 18 2>/dev/null || date +%s | sha256sum | cut -c1-36)"
  sed -i "s/AEGIS_ADMIN_PASSWORD=.*/AEGIS_ADMIN_PASSWORD=$ADMIN_PASSWORD/" .env
  echo "Generated initial admin password: $ADMIN_PASSWORD"
fi

cat > "$BIN_PATH" <<'SCRIPT'
#!/usr/bin/env sh
set -eu
cd /opt/aegis-panel
case "${1:-help}" in
  start) docker compose up -d ;;
  stop) docker compose down ;;
  restart) docker compose down && docker compose up -d ;;
  update) git pull --ff-only && docker compose up -d --build ;;
  logs) docker compose logs -f --tail=200 ;;
  status) docker compose ps ;;
  edit-env) ${EDITOR:-vi} .env ;;
  backup) mkdir -p backups && tar -czf "backups/aegis-$(date +%Y%m%d-%H%M%S).tgz" data .env ;;
  uninstall) docker compose down; echo "Remove /opt/aegis-panel manually if you want to delete data." ;;
  *) echo "Usage: aegis-panel {start|stop|restart|update|logs|status|edit-env|backup|uninstall}" ;;
esac
SCRIPT
chmod +x "$BIN_PATH"

docker compose up -d --build
echo "AegisPanel is running. Use: aegis-panel logs"
