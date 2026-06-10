import { randomBytes } from "node:crypto";
import { existsSync, mkdirSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

function loadLocalEnvFile(path = ".env") {
  if (!existsSync(path)) return;
  const content = readFileSync(path, "utf8");
  for (const line of content.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const equalsIndex = trimmed.indexOf("=");
    if (equalsIndex === -1) continue;
    const key = trimmed.slice(0, equalsIndex).trim();
    if (!key || process.env[key] !== undefined) continue;
    let value = trimmed.slice(equalsIndex + 1).trim();
    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }
    process.env[key] = value;
  }
}

loadLocalEnvFile();

function requiredEnv(name) {
  const value = process.env[name];
  if (!value) {
    throw new Error(`Missing required environment variable: ${name}`);
  }
  return value;
}

export const config = {
  host: process.env.AEGIS_HOST || "127.0.0.1",
  port: Number(process.env.AEGIS_PORT || 8080),
  dataDir: resolve(process.env.AEGIS_DATA_DIR || "./data"),
  publicUrl: process.env.AEGIS_PUBLIC_URL || "http://localhost:8080",
  sessionSecret: process.env.AEGIS_SESSION_SECRET || randomBytes(32).toString("hex"),
  adminUsername: requiredEnv("AEGIS_ADMIN_USERNAME"),
  adminPassword: requiredEnv("AEGIS_ADMIN_PASSWORD")
};

mkdirSync(config.dataDir, { recursive: true });
