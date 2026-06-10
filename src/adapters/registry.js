import { marzbanAdapter } from "./marzban.js";

const supported = new Map();

function makeAdapter(type, label, capabilities) {
  return {
    type,
    label,
    capabilities,
    async health(panel) {
      return {
        ok: Boolean(panel.url),
        latencyMs: 0,
        message: panel.url ? "Connector configured" : "Panel URL is missing"
      };
    },
    async listInbounds() {
      return [
        { id: "default", label: "Default inbound", flow: "", protocol: "mixed" }
      ];
    },
    async listUsers(panel, users) {
      return users.filter((user) => user.panelId === panel.id);
    },
    async sync(panel, users) {
      return {
        panelId: panel.id,
        pulled: users.filter((user) => user.panelId === panel.id).length,
        pushed: 0,
        conflicts: []
      };
    }
  };
}

[
  ["three-x-ui", "3x-ui", ["api-key auth", "inbounds", "traffic-sync", "subscription-links"]],
  ["tx-ui", "Tx-ui", ["password-auth", "inbounds", "traffic-sync"]],
  ["guard", "Guard", ["api-key auth", "guard-users", "traffic-sync"]],
  ["s-ui", "S-ui", ["password-auth", "inbounds", "traffic-sync"]]
].forEach(([type, label, capabilities]) => supported.set(type, makeAdapter(type, label, capabilities)));

supported.set("marzban", marzbanAdapter);

export function adapterFor(type) {
  return supported.get(type);
}

export function supportedPanels() {
  return [...supported.values()].map(({ type, label, capabilities }) => ({ type, label, capabilities }));
}
