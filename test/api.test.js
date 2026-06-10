import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { hashPassword, verifyPassword, signSession, verifySession } from "../src/utils/security.js";
import { supportedPanels, adapterFor } from "../src/adapters/registry.js";

async function withTempEnv(env, fn) {
  const keys = [
    "AEGIS_ADMIN_USERNAME",
    "AEGIS_ADMIN_PASSWORD",
    "AEGIS_DATA_DIR",
    "AEGIS_SESSION_SECRET",
    "AEGIS_HOST",
    "AEGIS_PORT",
    "AEGIS_PUBLIC_URL"
  ];
  const previousEnv = {};
  for (const key of keys) {
    previousEnv[key] = process.env[key];
    if (Object.prototype.hasOwnProperty.call(env, key)) process.env[key] = env[key];
    else delete process.env[key];
  }
  const previousCwd = process.cwd();
  const tempDir = await mkdtemp(join(tmpdir(), "aegis-env-"));
  try {
    process.chdir(tempDir);
    return await fn(tempDir);
  } finally {
    process.chdir(previousCwd);
    for (const [key, value] of Object.entries(previousEnv)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  }
}

async function importFresh(specifier) {
  return import(`${specifier}?v=${Date.now()}-${Math.random()}`);
}

async function importApiFresh() {
  const { handleApi } = await importFresh("../src/routes/api.js");
  return handleApi;
}

async function withMockDateNow(now, fn) {
  const originalNow = Date.now;
  Date.now = () => now;
  try {
    return await fn();
  } finally {
    Date.now = originalNow;
  }
}

test("loads local env file values without insecure defaults", async () => {
  await withTempEnv({}, async (tempDir) => {
    await writeFile(
      join(tempDir, ".env"),
      "AEGIS_ADMIN_USERNAME=env-admin\nAEGIS_ADMIN_PASSWORD=env-pass\nAEGIS_DATA_DIR=./tmp-data\n"
    );
    const mod = await importFresh("../src/config.js");
    assert.equal(mod.config.adminUsername, "env-admin");
    assert.equal(mod.config.adminPassword, "env-pass");
    assert.equal(mod.config.dataDir.endsWith("tmp-data"), true);
  });
});

test("startup fails clearly when admin credentials are missing", async () => {
  await withTempEnv(
    {
      AEGIS_DATA_DIR: "./tmp-data",
      AEGIS_SESSION_SECRET: "test-secret"
    },
    async () => {
      await assert.rejects(importFresh("../src/config.js"), /Missing required environment variable: AEGIS_ADMIN_USERNAME/);
    }
  );
});

test("startup does not fall back to insecure admin/admin defaults", async () => {
  await withTempEnv(
    {
      AEGIS_DATA_DIR: "./tmp-data",
      AEGIS_SESSION_SECRET: "test-secret"
    },
    async () => {
      await assert.rejects(importFresh("../src/config.js"), (error) => {
        assert.match(error.message, /AEGIS_ADMIN_USERNAME/);
        assert.doesNotMatch(error.message, /admin\/admin/);
        return true;
      });
    }
  );
});

test("configured credentials still allow login through the auth flow", async () => {
  await withTempEnv(
    {
      AEGIS_ADMIN_USERNAME: "env-admin",
      AEGIS_ADMIN_PASSWORD: "env-pass",
      AEGIS_DATA_DIR: "./tmp-data",
      AEGIS_SESSION_SECRET: "test-secret"
    },
    async () => {
      const { handleApi } = await importFresh("../src/routes/api.js");
      const req = {
        method: "POST",
        url: "/api/auth/login",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ username: "env-admin", password: "env-pass" }),
        [Symbol.asyncIterator]: async function* () {
          yield Buffer.from(this.body);
        }
      };
      const res = createMockResponse();
      const route = { method: "POST", pathname: "/api/auth/login", search: new URLSearchParams() };
      await handleApi(req, res, route);
      assert.equal(res.statusCode, 200);
      assert.equal(res.json.ok, true);
      assert.equal(res.json.admin.username, "env-admin");
      assert.equal(typeof res.json.session, "string");
    }
  );
});

test("oversized JSON request returns 413", async () => {
  await withTempEnv(
    {
      AEGIS_ADMIN_USERNAME: "env-admin",
      AEGIS_ADMIN_PASSWORD: "env-pass",
      AEGIS_DATA_DIR: "./tmp-data",
      AEGIS_SESSION_SECRET: "test-secret"
    },
    async () => {
      const handleApi = await importApiFresh();
      const payload = JSON.stringify({ username: "env-admin", password: "env-pass", pad: "x".repeat(1024 * 1024) });
      const res = await callApiWithOutcome(handleApi, {
        method: "POST",
        pathname: "/api/auth/login",
        rawBody: payload
      });
      assert.equal(res.statusCode, 413);
      assert.equal(res.json.error, "Request body too large");
    }
  );
});

test("invalid JSON returns 400", async () => {
  await withTempEnv(
    {
      AEGIS_ADMIN_USERNAME: "env-admin",
      AEGIS_ADMIN_PASSWORD: "env-pass",
      AEGIS_DATA_DIR: "./tmp-data",
      AEGIS_SESSION_SECRET: "test-secret"
    },
    async () => {
      const handleApi = await importApiFresh();
      const res = await callApiWithOutcome(handleApi, {
        method: "POST",
        pathname: "/api/auth/login",
        rawBody: "{not json"
      });
      assert.equal(res.statusCode, 400);
      assert.equal(res.json.error, "Invalid JSON body");
    }
  );
});

test("missing required login fields return 400", async () => {
  await withTempEnv(
    {
      AEGIS_ADMIN_USERNAME: "env-admin",
      AEGIS_ADMIN_PASSWORD: "env-pass",
      AEGIS_DATA_DIR: "./tmp-data",
      AEGIS_SESSION_SECRET: "test-secret"
    },
    async () => {
      const handleApi = await importApiFresh();
      const res = await callApiWithOutcome(handleApi, {
        method: "POST",
        pathname: "/api/auth/login",
        body: { username: "env-admin" }
      });
      assert.equal(res.statusCode, 400);
      assert.match(res.json.error, /Missing required field: password/);
    }
  );
});

test("missing required panel fields return 400", async () => {
  await withTempEnv(
    {
      AEGIS_ADMIN_USERNAME: "env-admin",
      AEGIS_ADMIN_PASSWORD: "env-pass",
      AEGIS_DATA_DIR: "./tmp-data",
      AEGIS_SESSION_SECRET: "test-secret"
    },
    async () => {
      const handleApi = await importApiFresh();
      const login = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/auth/login",
        body: { username: "env-admin", password: "env-pass" }
      });
      const res = await callApiWithOutcome(handleApi, {
        method: "POST",
        pathname: "/api/superadmin/panels",
        session: login.session,
        body: { name: "Panel One", type: "marzban" }
      });
      assert.equal(res.statusCode, 400);
      assert.match(res.json.error, /Missing required field: url/);
    }
  );
});

test("existing valid admin user flow still passes", async () => {
  await withTempEnv(
    {
      AEGIS_ADMIN_USERNAME: "env-admin",
      AEGIS_ADMIN_PASSWORD: "env-pass",
      AEGIS_DATA_DIR: "./tmp-data",
      AEGIS_SESSION_SECRET: "test-secret"
    },
    async () => {
      const handleApi = await importApiFresh();
      const login = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/auth/login",
        body: { username: "env-admin", password: "env-pass" }
      });
      const panel = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/superadmin/panels",
        session: login.session,
        body: {
          name: "Panel One",
          type: "marzban",
          url: "https://panel.example.com"
        }
      });
      const user = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/admin/users",
        session: login.session,
        body: {
          username: "user-one",
          panelId: panel.id
        }
      });
      assert.equal(user.username, "user-one");
      assert.equal(user.panelId, panel.id);
    }
  );
});

test("creating a user subtracts traffic from the owner", async () => {
  await withTempEnv(
    {
      AEGIS_ADMIN_USERNAME: "env-admin",
      AEGIS_ADMIN_PASSWORD: "env-pass",
      AEGIS_DATA_DIR: "./tmp-data",
      AEGIS_SESSION_SECRET: "test-secret"
    },
    async () => {
      const handleApi = await importApiFresh();
      const superLogin = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/auth/login",
        body: { username: "env-admin", password: "env-pass" }
      });
      const owner = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/superadmin/admins",
        session: superLogin.session,
        body: {
          username: "quota-admin",
          password: "admin-pass",
          trafficLimitBytes: 1000
        }
      });
      const ownerBefore = owner.trafficRemainingBytes;
      const panel = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/superadmin/panels",
        session: superLogin.session,
        body: {
          name: "Panel One",
          type: "marzban",
          url: "https://panel.example.com"
        }
      });
      const user = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/admin/users",
        session: superLogin.session,
        body: {
          username: "quota-user",
          panelId: panel.id,
          ownerAdminId: owner.id,
          limitBytes: 400
        }
      });
      assert.equal(user.limitBytes, 400);
      const admins = await callApi(handleApi, {
        method: "GET",
        pathname: "/api/superadmin/admins",
        session: superLogin.session
      });
      const updatedOwner = admins.find((admin) => admin.username === "quota-admin");
      assert.equal(updatedOwner.trafficRemainingBytes, ownerBefore - 400);
    }
  );
});

test("creating a user fails when the owner has insufficient traffic", async () => {
  await withTempEnv(
    {
      AEGIS_ADMIN_USERNAME: "env-admin",
      AEGIS_ADMIN_PASSWORD: "env-pass",
      AEGIS_DATA_DIR: "./tmp-data",
      AEGIS_SESSION_SECRET: "test-secret"
    },
    async () => {
      const handleApi = await importApiFresh();
      const superLogin = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/auth/login",
        body: { username: "env-admin", password: "env-pass" }
      });
      const owner = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/superadmin/admins",
        session: superLogin.session,
        body: {
          username: "small-quota-admin",
          password: "admin-pass",
          trafficLimitBytes: 100
        }
      });
      const ownerLogin = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/auth/login",
        body: { username: "small-quota-admin", password: "admin-pass" }
      });
      const panel = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/superadmin/panels",
        session: superLogin.session,
        body: {
          name: "Panel One",
          type: "marzban",
          url: "https://panel.example.com"
        }
      });
      const res = await callApiWithOutcome(handleApi, {
        method: "POST",
        pathname: "/api/admin/users",
        session: superLogin.session,
        body: {
          username: "too-much",
          panelId: panel.id,
          ownerAdminId: owner.id,
          limitBytes: 101
        }
      });
      assert.equal(res.statusCode, 409);
      assert.match(res.json.error, /Insufficient traffic quota/i);
    }
  );
});

test("deleting a user returns only unused traffic", async () => {
  await withTempEnv(
    {
      AEGIS_ADMIN_USERNAME: "env-admin",
      AEGIS_ADMIN_PASSWORD: "env-pass",
      AEGIS_DATA_DIR: "./tmp-data",
      AEGIS_SESSION_SECRET: "test-secret"
    },
    async () => {
      const handleApi = await importApiFresh();
      const superLogin = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/auth/login",
        body: { username: "env-admin", password: "env-pass" }
      });
      const owner = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/superadmin/admins",
        session: superLogin.session,
        body: {
          username: "delete-quota-admin",
          password: "admin-pass",
          trafficLimitBytes: 1000
        }
      });
      const panel = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/superadmin/panels",
        session: superLogin.session,
        body: {
          name: "Panel One",
          type: "marzban",
          url: "https://panel.example.com"
        }
      });
      const user = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/admin/users",
        session: superLogin.session,
        body: {
          username: "delete-user",
          panelId: panel.id,
          ownerAdminId: owner.id,
          limitBytes: 500,
          usedBytes: 200
        }
      });
      const deleted = await callApi(handleApi, {
        method: "DELETE",
        pathname: `/api/admin/users/${user.id}`,
        session: superLogin.session
      });
      assert.equal(deleted.ok, true);
      const admins = await callApi(handleApi, {
        method: "GET",
        pathname: "/api/superadmin/admins",
        session: superLogin.session
      });
      const updatedOwner = admins.find((admin) => admin.username === "delete-quota-admin");
      assert.equal(updatedOwner.trafficRemainingBytes, owner.trafficRemainingBytes - user.limitBytes + (user.limitBytes - user.usedBytes));
    }
  );
});

test("deleting an overused user does not increase owner traffic", async () => {
  await withTempEnv(
    {
      AEGIS_ADMIN_USERNAME: "env-admin",
      AEGIS_ADMIN_PASSWORD: "env-pass",
      AEGIS_DATA_DIR: "./tmp-data",
      AEGIS_SESSION_SECRET: "test-secret"
    },
    async () => {
      const handleApi = await importApiFresh();
      const superLogin = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/auth/login",
        body: { username: "env-admin", password: "env-pass" }
      });
      const owner = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/superadmin/admins",
        session: superLogin.session,
        body: {
          username: "overused-admin",
          password: "admin-pass",
          trafficLimitBytes: 1000
        }
      });
      const panel = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/superadmin/panels",
        session: superLogin.session,
        body: {
          name: "Panel One",
          type: "marzban",
          url: "https://panel.example.com"
        }
      });
      const user = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/admin/users",
        session: superLogin.session,
        body: {
          username: "overused-user",
          panelId: panel.id,
          ownerAdminId: owner.id,
          limitBytes: 300,
          usedBytes: 450
        }
      });
      const afterCreateAdmins = await callApi(handleApi, {
        method: "GET",
        pathname: "/api/superadmin/admins",
        session: superLogin.session
      });
      const ownerAfterCreate = afterCreateAdmins.find((admin) => admin.username === "overused-admin");
      const deleted = await callApi(handleApi, {
        method: "DELETE",
        pathname: `/api/admin/users/${user.id}`,
        session: superLogin.session
      });
      assert.equal(deleted.ok, true);
      const afterDeleteAdmins = await callApi(handleApi, {
        method: "GET",
        pathname: "/api/superadmin/admins",
        session: superLogin.session
      });
      const ownerAfterDelete = afterDeleteAdmins.find((admin) => admin.username === "overused-admin");
      assert.equal(ownerAfterDelete.trafficRemainingBytes, ownerAfterCreate.trafficRemainingBytes);
    }
  );
});

test("repeated failed login attempts eventually return 429", async () => {
  await withTempEnv(
    {
      AEGIS_ADMIN_USERNAME: "env-admin",
      AEGIS_ADMIN_PASSWORD: "env-pass",
      AEGIS_DATA_DIR: "./tmp-data",
      AEGIS_SESSION_SECRET: "test-secret"
    },
    async () => {
      const handleApi = await importApiFresh();
      await withMockDateNow(1_000_000, async () => {
        for (let attempt = 1; attempt <= 5; attempt += 1) {
          const res = await callApiWithOutcome(handleApi, {
            method: "POST",
            pathname: "/api/auth/login",
            session: undefined,
            body: { username: "env-admin", password: "wrong-pass" },
            remoteAddress: "10.0.0.5"
          });
          assert.equal(res.statusCode, 401);
        }

        const blocked = await callApiWithOutcome(handleApi, {
          method: "POST",
          pathname: "/api/auth/login",
          body: { username: "env-admin", password: "wrong-pass" },
          remoteAddress: "10.0.0.5"
        });
        assert.equal(blocked.statusCode, 429);
        assert.match(blocked.json.error, /Too many failed login attempts/);
      });
    }
  );
});

test("rate limiting does not affect unrelated endpoints", async () => {
  await withTempEnv(
    {
      AEGIS_ADMIN_USERNAME: "env-admin",
      AEGIS_ADMIN_PASSWORD: "env-pass",
      AEGIS_DATA_DIR: "./tmp-data",
      AEGIS_SESSION_SECRET: "test-secret"
    },
    async () => {
      const handleApi = await importApiFresh();
      await withMockDateNow(2_000_000, async () => {
        for (let attempt = 1; attempt <= 5; attempt += 1) {
          await callApiWithOutcome(handleApi, {
            method: "POST",
            pathname: "/api/auth/login",
            body: { username: "env-admin", password: "wrong-pass" },
            remoteAddress: "10.0.0.6"
          });
        }

        const health = await callApiWithOutcome(handleApi, {
          method: "GET",
          pathname: "/api/health",
          remoteAddress: "10.0.0.6"
        });
        assert.equal(health.statusCode, 200);
        assert.equal(health.json.ok, true);

        const otherIpLogin = await callApi(handleApi, {
          method: "POST",
          pathname: "/api/auth/login",
          body: { username: "env-admin", password: "env-pass" },
          remoteAddress: "10.0.0.7"
        });
        assert.equal(otherIpLogin.session.length > 0, true);
      });
    }
  );
});

test("panel credentials are stripped from api responses", async () => {
  await withTempEnv(
    {
      AEGIS_ADMIN_USERNAME: "env-admin",
      AEGIS_ADMIN_PASSWORD: "env-pass",
      AEGIS_DATA_DIR: "./tmp-data",
      AEGIS_SESSION_SECRET: "test-secret"
    },
    async () => {
      const { handleApi } = await importFresh("../src/routes/api.js");
      const login = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/auth/login",
        body: { username: "env-admin", password: "env-pass" }
      });
      const session = login.session;

      const created = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/superadmin/panels",
        session,
        body: {
          name: "Panel One",
          type: "marzban",
          url: "https://panel.example.com",
          username: "panel-user",
          secret: "panel-secret",
          apiKey: "panel-key",
          token: "panel-token",
          credentials: "panel-creds"
        }
      });

      assert.equal(created.username, undefined);
      assert.equal(created.secret, undefined);
      assert.equal(created.apiKey, undefined);
      assert.equal(created.token, undefined);
      assert.equal(created.credentials, undefined);

      const updated = await callApi(handleApi, {
        method: "PUT",
        pathname: `/api/superadmin/panels/${created.id}`,
        session,
        body: {
          name: "Panel One Updated",
          type: "marzban",
          url: "https://panel.example.com",
          username: "updated-user",
          secret: "updated-secret",
          apiKey: "updated-key",
          token: "updated-token"
        }
      });

      assert.equal(updated.username, undefined);
      assert.equal(updated.secret, undefined);
      assert.equal(updated.apiKey, undefined);
      assert.equal(updated.token, undefined);

      const dashboard = await callApi(handleApi, {
        method: "GET",
        pathname: "/api/dashboard",
        session
      });
      assert.equal(dashboard.panels[0].username, undefined);
      assert.equal(dashboard.panels[0].secret, undefined);
      assert.equal(dashboard.panels[0].apiKey, undefined);

      const panelList = await callApi(handleApi, {
        method: "GET",
        pathname: "/api/superadmin/panels",
        session
      });
      assert.equal(panelList[0].username, undefined);
      assert.equal(panelList[0].secret, undefined);
      assert.equal(panelList[0].apiKey, undefined);

      const backup = await callApi(handleApi, {
        method: "GET",
        pathname: "/api/superadmin/backup",
        session
      });
      assert.equal(backup.panels[0].username, undefined);
      assert.equal(backup.panels[0].secret, undefined);
      assert.equal(backup.panels[0].apiKey, undefined);
    }
  );
});

test("a superadmin cannot delete itself", async () => {
  const { canDeleteAdmin } = await importFresh("../src/routes/api.js");
  const actor = { id: "adm_1", role: "superadmin" };
  const result = canDeleteAdmin(actor, actor, 1);
  assert.equal(result.status, 400);
  assert.match(result.error, /cannot delete your own account/i);
});

test("the last superadmin cannot be deleted", async () => {
  const { canDeleteAdmin } = await importFresh("../src/routes/api.js");
  const actor = { id: "adm_1", role: "superadmin" };
  const target = { id: "adm_2", role: "superadmin" };
  const result = canDeleteAdmin(actor, target, 1);
  assert.equal(result.status, 409);
  assert.match(result.error, /At least one superadmin must remain/i);
});

test("a normal admin can still be deleted by a superadmin", async () => {
  await withTempEnv(
    {
      AEGIS_ADMIN_USERNAME: "env-admin",
      AEGIS_ADMIN_PASSWORD: "env-pass",
      AEGIS_DATA_DIR: "./tmp-data",
      AEGIS_SESSION_SECRET: "test-secret"
    },
    async () => {
      const handleApi = await importApiFresh();
      const login = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/auth/login",
        body: { username: "env-admin", password: "env-pass" }
      });
      const admin = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/superadmin/admins",
        session: login.session,
        body: {
          username: "team-admin",
          password: "admin-pass",
          role: "admin"
        }
      });
      const res = await callApiWithOutcome(handleApi, {
        method: "DELETE",
        pathname: `/api/superadmin/admins/${admin.id}`,
        session: login.session
      });
      assert.equal(res.statusCode, 200);
      assert.equal(res.json.ok, true);
    }
  );
});

function createMockResponse() {
  return {
    statusCode: 200,
    headers: {},
    json: null,
    writeHead(status, headers) {
      this.statusCode = status;
      this.headers = headers;
    },
    end(body) {
      this.json = JSON.parse(body);
    }
  };
}

async function callApi(handleApi, { method, pathname, session, body, remoteAddress }) {
  const req = createMockRequest(method, pathname, session, body, undefined, remoteAddress);
  const res = createMockResponse();
  const route = { method, pathname, search: new URLSearchParams() };
  await handleApi(req, res, route);
  assert.equal(res.statusCode >= 200 && res.statusCode < 300, true);
  assert.equal(res.json.ok, true);
  return res.json.data ?? res.json;
}

async function callApiWithOutcome(handleApi, { method, pathname, session, body, rawBody, remoteAddress }) {
  const req = createMockRequest(method, pathname, session, body, rawBody, remoteAddress);
  const res = createMockResponse();
  const route = { method, pathname, search: new URLSearchParams() };
  try {
    await handleApi(req, res, route);
  } catch (error) {
    res.writeHead(error.status || 500, { "content-type": "application/json; charset=utf-8" });
    res.end(JSON.stringify({ ok: false, error: error.message || "Internal server error" }));
  }
  return res;
}

function createMockRequest(method, pathname, session, body, rawBody, remoteAddress = "127.0.0.1") {
  const payload = rawBody ?? (body ? JSON.stringify(body) : "");
  return {
    method,
    url: pathname,
    socket: { remoteAddress },
    headers: {
      "content-type": "application/json",
      ...(session ? { "x-aegis-session": session } : {})
    },
    body: payload,
    [Symbol.asyncIterator]: async function* () {
      if (payload) yield Buffer.from(payload);
    }
  };
}

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
