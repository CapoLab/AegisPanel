import { marzbanAdapter } from "./marzban.js";

const supported = new Map();

function capabilityFlags(flags = {}) {
  return {
    canTestConnection: Boolean(flags.canTestConnection),
    canListInbounds: Boolean(flags.canListInbounds),
    canCreateUser: Boolean(flags.canCreateUser),
    canUpdateUser: Boolean(flags.canUpdateUser),
    canDeleteUser: Boolean(flags.canDeleteUser),
    canSyncTraffic: Boolean(flags.canSyncTraffic),
    canBuildSubscriptionUrl: Boolean(flags.canBuildSubscriptionUrl),
    canGetUser: Boolean(flags.canGetUser)
  };
}

function notImplemented(type, method) {
  const error = new Error(`${type} ${method} is not implemented yet`);
  error.status = 501;
  return error;
}

function makeAdapter(type, label, capabilities) {
  const contract = capabilityFlags(capabilities);
  return {
    type,
    label,
    capabilities: contract,
    async health() {
      throw notImplemented(type, "health");
    },
    async testConnection() {
      throw notImplemented(type, "testConnection");
    },
    async buildClient() {
      throw notImplemented(type, "buildClient");
    },
    async authenticate() {
      throw notImplemented(type, "authenticate");
    },
    async listInbounds() {
      throw notImplemented(type, "listInbounds");
    },
    async listUsers() {
      throw notImplemented(type, "listUsers");
    },
    async createUser() {
      throw notImplemented(type, "createUser");
    },
    async updateUser() {
      throw notImplemented(type, "updateUser");
    },
    async deleteUser() {
      throw notImplemented(type, "deleteUser");
    },
    async getUser() {
      throw notImplemented(type, "getUser");
    },
    async syncUserTraffic() {
      throw notImplemented(type, "syncUserTraffic");
    },
    async buildSubscriptionUrl() {
      throw notImplemented(type, "buildSubscriptionUrl");
    },
    async sync() {
      throw notImplemented(type, "sync");
    }
  };
}

[
  ["three-x-ui", "3x-ui"],
  ["tx-ui", "Tx-ui"],
  ["guard", "Guard"],
  ["s-ui", "S-ui"]
].forEach(([type, label, capabilities]) => supported.set(type, makeAdapter(type, label, capabilities)));

supported.set("marzban", marzbanAdapter);

export function adapterFor(type) {
  return supported.get(type);
}

export function supportedPanels() {
  return [...supported.values()].map(({ type, label, capabilities }) => ({ type, label, capabilities }));
}
