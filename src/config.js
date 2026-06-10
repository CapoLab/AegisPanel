import { randomBytes } from "node:crypto";
import { mkdirSync } from "node:fs";
import { resolve } from "node:path";

export const config = {
  host: process.env.AEGIS_HOST || "127.0.0.1",
  port: Number(process.env.AEGIS_PORT || 8080),
  dataDir: resolve(process.env.AEGIS_DATA_DIR || "./data"),
  publicUrl: process.env.AEGIS_PUBLIC_URL || "http://localhost:8080",
  sessionSecret: process.env.AEGIS_SESSION_SECRET || randomBytes(32).toString("hex"),
  adminUsername: process.env.AEGIS_ADMIN_USERNAME || "admin",
  adminPassword: process.env.AEGIS_ADMIN_PASSWORD || "admin"
};

mkdirSync(config.dataDir, { recursive: true });
