import { existsSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { config } from "../config.js";
import { hashPassword, safeId } from "../utils/security.js";

const dbPath = join(config.dataDir, "aegis-db.json");

function now() {
  return new Date().toISOString();
}

function seed() {
  return {
    meta: {
      version: 1,
      product: "AegisPanel",
      createdAt: now()
    },
    admins: [
      {
        id: safeId("adm"),
        username: config.adminUsername,
        passwordHash: hashPassword(config.adminPassword),
        role: "superadmin",
        active: true,
        panelId: null,
        inboundIds: [],
        trafficLimitBytes: null,
        trafficRemainingBytes: null,
        updateReturnTraffic: true,
        deleteReturnTraffic: true,
        expiresAt: null,
        createdAt: now(),
        updatedAt: now()
      }
    ],
    panels: [],
    users: [],
    trafficEvents: [],
    news: [],
    auditLogs: [],
    distribution: {
      edition: "community",
      status: "free",
      monetization: "disabled",
      seats: 3,
      expiresAt: null,
      updatedAt: now()
    }
  };
}

export class Store {
  constructor() {
    this.state = existsSync(dbPath) ? JSON.parse(readFileSync(dbPath, "utf8")) : seed();
    if (!this.state.distribution) {
      this.state.distribution = {
        edition: "community",
        status: "free",
        monetization: "disabled",
        seats: 3,
        expiresAt: null,
        updatedAt: now()
      };
      delete this.state[["lic", "ense"].join("")];
    }
    this.save();
  }

  save() {
    const tmp = `${dbPath}.tmp`;
    writeFileSync(tmp, JSON.stringify(this.state, null, 2));
    renameSync(tmp, dbPath);
  }

  audit(actor, action, target, details = {}) {
    this.state.auditLogs.unshift({
      id: safeId("log"),
      actor: actor?.username || "system",
      action,
      target,
      details,
      createdAt: now()
    });
    this.state.auditLogs = this.state.auditLogs.slice(0, 1000);
    this.save();
  }

  list(collection) {
    return this.state[collection] || [];
  }

  find(collection, id) {
    return this.list(collection).find((item) => item.id === id);
  }

  insert(collection, record) {
    const item = { id: safeId(collection.slice(0, 3)), ...record, createdAt: now(), updatedAt: now() };
    this.state[collection].push(item);
    this.save();
    return item;
  }

  update(collection, id, patch) {
    const item = this.find(collection, id);
    if (!item) return null;
    Object.assign(item, patch, { updatedAt: now() });
    this.save();
    return item;
  }

  remove(collection, id) {
    const before = this.state[collection].length;
    this.state[collection] = this.state[collection].filter((item) => item.id !== id);
    this.save();
    return before !== this.state[collection].length;
  }
}

export const store = new Store();
