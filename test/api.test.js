import { test } from "node:test";
import assert from "node:assert/strict";
import { hashPassword, verifyPassword, signSession, verifySession } from "../src/utils/security.js";
import { supportedPanels, adapterFor } from "../src/adapters/registry.js";

test("password hashing verifies the original secret only", () => {
  const stored = hashPassword("safe-password");
  assert.equal(verifyPassword("safe-password", stored), true);
  assert.equal(verifyPassword("wrong-password", stored), false);
});

test("signed sessions round-trip and expose role claims", () => {
  const session = signSession({ sub: "adm_1", role: "superadmin" }, "secret", 60);
  assert.equal(verifySession(session, "secret").role, "superadmin");
  assert.equal(verifySession(session, "other-secret"), null);
});

test("all planned panel adapters are registered", () => {
  const types = supportedPanels().map((panel) => panel.type).sort();
  assert.deepEqual(types, ["guard", "marzban", "s-ui", "three-x-ui", "tx-ui"]);
  assert.equal(adapterFor("marzban").label, "Marzban");
});
