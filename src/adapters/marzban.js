function notImplemented(method) {
  const error = new Error(`Marzban ${method} is not implemented yet`);
  error.status = 501;
  return error;
}

function reject(method) {
  throw notImplemented(method);
}

export const marzbanAdapter = {
  type: "marzban",
  label: "Marzban",
  capabilities: ["password-auth", "multi-inbound", "data-limit", "status-sync"],
  async health() {
    reject("health");
  },
  async buildClient() {
    reject("buildClient");
  },
  async authenticate() {
    reject("authenticate");
  },
  async listInbounds() {
    reject("listInbounds");
  },
  async listUsers() {
    reject("listUsers");
  },
  async createUser() {
    reject("createUser");
  },
  async deleteUser() {
    reject("deleteUser");
  },
  async syncUserTraffic() {
    reject("syncUserTraffic");
  },
  async sync() {
    reject("sync");
  }
};
