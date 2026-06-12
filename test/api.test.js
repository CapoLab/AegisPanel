import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { EventEmitter } from "node:events";
import { tmpdir } from "node:os";
import { join } from "node:path";
import https from "node:https";
import { readJson } from "../src/utils/http.js";
import { hashPassword, verifyPassword, signSession, verifySession } from "../src/utils/security.js";
import { supportedPanels, adapterFor } from "../src/adapters/registry.js";
import { buildClient, marzbanAdapter } from "../src/adapters/marzban.js";
import { buildClient as buildThreeXUiClient, threeXUiAdapter } from "../src/adapters/three-x-ui.js";

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

test("oversized request bodies are rejected while streaming chunks", async () => {
  let thirdChunkRead = false;
  const req = {
    [Symbol.asyncIterator]: async function* () {
      yield Buffer.alloc(700_000, 97);
      yield Buffer.alloc(400_001, 98);
      thirdChunkRead = true;
      yield Buffer.from('{"after":"limit"}');
    }
  };
  await assert.rejects(readJson(req), (error) => {
    assert.equal(error.status, 413);
    assert.equal(error.message, "Request body too large");
    return true;
  });
  assert.equal(thirdChunkRead, false);
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

test("past expiry is rejected on create before remote calls", async () => {
  const calls = [];
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
          name: "Marzban Panel",
          type: "marzban",
          url: "https://marzban.example.com",
          subscriptionUrl: "https://marzban.example.com",
          username: "panel-admin",
          secret: "panel-secret"
        }
      });
      const res = await callApiWithOutcome(handleApi, {
        method: "POST",
        pathname: "/api/admin/users",
        session: login.session,
        body: {
          username: "expired-create",
          panelId: panel.id,
          limitBytes: 100,
          expiresAt: "2000-01-01T23:59:59.000Z",
          inboundIds: ["vless:WS TLS:10002"]
        }
      });
      assert.equal(res.statusCode, 400);
      assert.match(res.json.error, /Expiry date cannot be in the past\./i);
    }
  );
  assert.equal(calls.length, 0);
});

test("editing traffic limit consumes and returns reseller quota safely", async () => {
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
      const owner = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/superadmin/admins",
        session: login.session,
        body: {
          username: "edit-quota-owner",
          password: "admin-pass",
          trafficLimitBytes: 1000
        }
      });
      const panel = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/superadmin/panels",
        session: login.session,
        body: {
          name: "Panel One",
          type: "tx-ui",
          url: "https://panel.example.com"
        }
      });
      const user = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/admin/users",
        session: login.session,
        body: {
          username: "edit-quota-user",
          panelId: panel.id,
          ownerAdminId: owner.id,
          limitBytes: 200,
          usedBytes: 50
        }
      });

      const afterCreateAdmins = await callApi(handleApi, {
        method: "GET",
        pathname: "/api/superadmin/admins",
        session: login.session
      });
      const ownerAfterCreate = afterCreateAdmins.find((admin) => admin.username === "edit-quota-owner");
      assert.equal(ownerAfterCreate.trafficRemainingBytes, 800);

      const increased = await callApi(handleApi, {
        method: "PUT",
        pathname: `/api/admin/users/${user.id}`,
        session: login.session,
        body: {
          limitBytes: 500
        }
      });
      assert.equal(increased.limitBytes, 500);
      assert.equal(increased.reservedBytes, 500);

      const afterIncreaseAdmins = await callApi(handleApi, {
        method: "GET",
        pathname: "/api/superadmin/admins",
        session: login.session
      });
      const ownerAfterIncrease = afterIncreaseAdmins.find((admin) => admin.username === "edit-quota-owner");
      assert.equal(ownerAfterIncrease.trafficRemainingBytes, 500);

      const decreased = await callApi(handleApi, {
        method: "PUT",
        pathname: `/api/admin/users/${user.id}`,
        session: login.session,
        body: {
          limitBytes: 150
        }
      });
      assert.equal(decreased.limitBytes, 150);
      assert.equal(decreased.reservedBytes, 150);

      const afterDecreaseAdmins = await callApi(handleApi, {
        method: "GET",
        pathname: "/api/superadmin/admins",
        session: login.session
      });
      const ownerAfterDecrease = afterDecreaseAdmins.find((admin) => admin.username === "edit-quota-owner");
      assert.equal(ownerAfterDecrease.trafficRemainingBytes, 850);
    }
  );
});

test("editing traffic limit above reseller remaining quota is rejected before Marzban update", async () => {
  const calls = [];
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
      const owner = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/superadmin/admins",
        session: login.session,
        body: {
          username: "edit-remote-owner",
          password: "admin-pass",
          trafficLimitBytes: 100
        }
      });
      const panel = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/superadmin/panels",
        session: login.session,
        body: {
          name: "Marzban Panel",
          type: "marzban",
          url: "https://marzban.example.com",
          subscriptionUrl: "https://marzban.example.com",
          username: "panel-admin",
          secret: "panel-secret"
        }
      });
      const resellerLogin = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/auth/login",
        body: { username: owner.username, password: "admin-pass" }
      });

      await withMockFetch(
        [
          {
            ok: true,
            status: 200,
            json: async () => ({ access_token: "marzban-token" })
          },
          {
            ok: true,
            status: 201,
            json: async () => ({ id: "remote-user-edit", username: "edit-remote", status: "active" })
          },
          {
            ok: true,
            status: 200,
            json: async () => ({ access_token: "marzban-token" })
          },
          {
            ok: true,
            status: 200,
            json: async () => ({ username: "edit-remote", subscription_url: "https://marzban.example.com/sub/edit-remote" })
          }
        ],
        calls,
        async () => {
          const created = await callApi(handleApi, {
            method: "POST",
            pathname: "/api/admin/users",
            session: login.session,
            body: {
              username: "edit-remote",
              panelId: panel.id,
              ownerAdminId: owner.id,
              limitBytes: 80,
              usedBytes: 20,
              inboundIds: ["vless:WS TLS:10002"]
            }
          });
          const res = await callApiWithOutcome(handleApi, {
            method: "PUT",
            pathname: `/api/admin/users/${created.id}`,
            session: login.session,
            body: {
              limitBytes: 200
            }
          });
          assert.equal(res.statusCode, 409);
          assert.match(res.json.error, /Insufficient traffic quota/i);
        }
      );
    }
  );
  assert.equal(calls.length, 2);
});

test("editing traffic limit below usedBytes is rejected", async () => {
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
          type: "tx-ui",
          url: "https://panel.example.com"
        }
      });
      const user = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/admin/users",
        session: login.session,
        body: {
          username: "edit-used-user",
          panelId: panel.id,
          limitBytes: 200,
          usedBytes: 150
        }
      });

      const res = await callApiWithOutcome(handleApi, {
        method: "PUT",
        pathname: `/api/admin/users/${user.id}`,
        session: login.session,
        body: {
          limitBytes: 100
        }
      });
      assert.equal(res.statusCode, 400);
      assert.match(res.json.error, /Traffic limit cannot be lower than used traffic/i);
    }
  );
});

test("past expiry is rejected on edit before Marzban remote update", async () => {
  const calls = [];
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
      const owner = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/superadmin/admins",
        session: login.session,
        body: {
          username: "edit-past-owner",
          password: "admin-pass",
          trafficLimitBytes: 1000
        }
      });
      const panel = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/superadmin/panels",
        session: login.session,
        body: {
          name: "Marzban Panel",
          type: "marzban",
          url: "https://marzban.example.com",
          subscriptionUrl: "https://marzban.example.com",
          username: "panel-admin",
          secret: "panel-secret"
        }
      });
      const resellerLogin = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/auth/login",
        body: { username: owner.username, password: "admin-pass" }
      });

      await withMockFetch(
        [
          {
            ok: true,
            status: 200,
            json: async () => ({ access_token: "marzban-token" })
          },
          {
            ok: true,
            status: 201,
            json: async () => ({ id: "remote-user-past", username: "edit-past", status: "active" })
          },
          {
            ok: true,
            status: 200,
            json: async () => ({ access_token: "marzban-token" })
          },
          {
            ok: true,
            status: 200,
            json: async () => ({ username: "edit-past", subscription_url: "https://marzban.example.com/sub/edit-past" })
          }
        ],
        calls,
        async () => {
          const created = await callApi(handleApi, {
            method: "POST",
            pathname: "/api/admin/users",
            session: login.session,
            body: {
              username: "edit-past",
              panelId: panel.id,
              ownerAdminId: owner.id,
              limitBytes: 200,
              usedBytes: 50,
              expiresAt: "2030-01-02T23:59:59.000Z",
              inboundIds: ["vless:WS TLS:10002"]
            }
          });

          const updateRes = await callApiWithOutcome(handleApi, {
            method: "PUT",
            pathname: `/api/admin/users/${created.id}`,
            session: login.session,
            body: {
              expiresAt: "2000-01-01T23:59:59.000Z"
            }
          });
          assert.equal(updateRes.statusCode, 400);
          assert.match(updateRes.json.error, /Expiry date cannot be in the past\./i);
        }
      );
    }
  );

  assert.equal(calls.length, 2);
});

test("marzban remote update failure leaves local limitBytes, reservedBytes, and owner quota unchanged", async () => {
  const calls = [];
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
      const owner = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/superadmin/admins",
        session: login.session,
        body: {
          username: "rollback-edit-owner",
          password: "admin-pass",
          trafficLimitBytes: 1000
        }
      });
      const panel = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/superadmin/panels",
        session: login.session,
        body: {
          name: "Marzban Panel",
          type: "marzban",
          url: "https://marzban.example.com",
          subscriptionUrl: "https://marzban.example.com",
          username: "panel-admin",
          secret: "panel-secret"
        }
      });
      const resellerLogin = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/auth/login",
        body: { username: owner.username, password: "admin-pass" }
      });

      await withMockFetch(
        [
          {
            ok: true,
            status: 200,
            json: async () => ({ access_token: "marzban-token" })
          },
          {
            ok: true,
            status: 201,
            json: async () => ({ id: "remote-user-edit-rollback", username: "edit-rollback", status: "active" })
          },
          {
            ok: true,
            status: 200,
            json: async () => ({ access_token: "marzban-token" })
          },
          {
            ok: false,
            status: 500,
            json: async () => ({ detail: "boom" })
          }
        ],
        calls,
        async () => {
          const created = await callApi(handleApi, {
            method: "POST",
            pathname: "/api/admin/users",
            session: login.session,
            body: {
              username: "edit-rollback",
              panelId: panel.id,
              ownerAdminId: owner.id,
              limitBytes: 200,
              usedBytes: 50,
              inboundIds: ["vless:WS TLS:10002"]
            }
          });

          const updateRes = await callApiWithOutcome(handleApi, {
            method: "PUT",
            pathname: `/api/admin/users/${created.id}`,
            session: login.session,
            body: {
              limitBytes: 500
            }
          });
          assert.equal(updateRes.statusCode, 500);
          assert.match(updateRes.json.error, /Marzban update user failed with HTTP 500/i);

          const users = await callApi(handleApi, {
            method: "GET",
            pathname: "/api/admin/users",
            session: login.session
          });
          const stored = users.find((user) => user.username === "edit-rollback");
          assert.equal(stored.limitBytes, 200);
          assert.equal(stored.reservedBytes, 200);

          const admins = await callApi(handleApi, {
            method: "GET",
            pathname: "/api/superadmin/admins",
            session: login.session
          });
          const rollbackOwner = admins.find((admin) => admin.username === "rollback-edit-owner");
          assert.equal(rollbackOwner.trafficRemainingBytes, 800);
        }
      );
    }
  );

  assert.equal(calls.length, 4);
  assert.equal(calls[0].url, "https://marzban.example.com/api/admin/token");
  assert.equal(calls[1].url, "https://marzban.example.com/api/user");
  assert.equal(calls[2].url, "https://marzban.example.com/api/admin/token");
  assert.equal(calls[3].url, "https://marzban.example.com/api/user/edit-rollback");
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
          type: "tx-ui",
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
      assert.equal(user.inboundId, "default");
      assert.equal("inboundIds" in user, false);

      const inboundUser = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/admin/users",
        session: login.session,
        body: {
          username: "user-two",
          panelId: panel.id,
          inboundId: "vless:ws:10001"
        }
      });
      assert.equal(inboundUser.inboundId, "vless:ws:10001");
      assert.deepEqual(inboundUser.inboundIds, ["vless:ws:10001"]);
    }
  );
});

test("reseller validity persists on create and legacy resellers without validity still work", async () => {
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
          type: "tx-ui",
          url: "https://panel.example.com"
        }
      });
      const validUntil = "2030-01-02T23:59:59.000Z";
      const reseller = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/superadmin/admins",
        session: login.session,
        body: {
          username: "reseller-valid",
          password: "admin-pass",
          role: "admin",
          panelId: panel.id,
          trafficLimitBytes: 1000,
          validUntil
        }
      });
      assert.equal(reseller.validUntil, validUntil);

      const admins = await callApi(handleApi, {
        method: "GET",
        pathname: "/api/superadmin/admins",
        session: login.session
      });
      assert.equal(admins.find((admin) => admin.username === "reseller-valid").validUntil, validUntil);

      const legacyReseller = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/superadmin/admins",
        session: login.session,
        body: {
          username: "reseller-legacy",
          password: "admin-pass",
          role: "admin",
          panelId: panel.id,
          trafficLimitBytes: 1000
        }
      });
      assert.equal(legacyReseller.validUntil ?? null, null);

      const legacyLogin = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/auth/login",
        body: { username: "reseller-legacy", password: "admin-pass" }
      });
      const vpnAccount = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/admin/users",
        session: legacyLogin.session,
        body: {
          username: "legacy-client"
        }
      });
      assert.equal(vpnAccount.username, "legacy-client");
    }
  );
});

test("reseller validity blocks invalid vpn account expiries before remote create", async () => {
  const calls = [];
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
          name: "Marzban Panel",
          type: "marzban",
          url: "https://marzban.example.com",
          username: "admin",
          secret: "secret"
        }
      });
      const reseller = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/superadmin/admins",
        session: login.session,
        body: {
          username: "reseller-expiry",
          password: "admin-pass",
          role: "admin",
          panelId: panel.id,
          trafficLimitBytes: 1000,
          validUntil: "2030-01-02T23:59:59.000Z"
        }
      });

      await withMockFetch([], calls, async () => {
        await withMockDateNow(new Date("2030-01-01T12:00:00.000Z").getTime(), async () => {
          const resellerLogin = await callApi(handleApi, {
            method: "POST",
            pathname: "/api/auth/login",
            body: { username: reseller.username, password: "admin-pass" }
          });
          const missingExpiry = await callApiWithOutcome(handleApi, {
            method: "POST",
            pathname: "/api/admin/users",
            session: resellerLogin.session,
            body: {
              username: "client-missing",
              limitBytes: 100,
              inboundIds: ["vless:WS TLS:10002"]
            }
          });
          assert.equal(missingExpiry.statusCode, 400);
          assert.match(missingExpiry.json.error, /VPN account expiry is required for resellers with a validity limit\./i);

          const tooLate = await callApiWithOutcome(handleApi, {
            method: "POST",
            pathname: "/api/admin/users",
            session: resellerLogin.session,
            body: {
              username: "client-late",
              limitBytes: 100,
              expiresAt: "2030-01-03T23:59:59.000Z",
              inboundIds: ["vless:WS TLS:10002"]
            }
          });
          assert.equal(tooLate.statusCode, 400);
          assert.match(tooLate.json.error, /VPN account expiry cannot exceed reseller validity\./i);
        });

        await withMockDateNow(new Date("2030-01-03T12:00:00.000Z").getTime(), async () => {
          const resellerLogin = await callApi(handleApi, {
            method: "POST",
            pathname: "/api/auth/login",
            body: { username: reseller.username, password: "admin-pass" }
          });
          const expired = await callApiWithOutcome(handleApi, {
            method: "POST",
            pathname: "/api/admin/users",
            session: resellerLogin.session,
            body: {
              username: "client-expired",
              limitBytes: 100,
              expiresAt: "2030-01-02T23:59:59.000Z",
              inboundIds: ["vless:WS TLS:10002"]
            }
          });
          assert.equal(expired.statusCode, 400);
          assert.match(expired.json.error, /Reseller validity has expired\./i);
        });
      });
    }
  );
  assert.equal(calls.length, 0);
});

test("reseller validity allows vpn account expiry within limit and superadmin is not restricted", async () => {
  const calls = [];
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
      const marzbanPanel = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/superadmin/panels",
        session: login.session,
        body: {
          name: "Marzban Panel",
          type: "marzban",
          url: "https://marzban.example.com",
          username: "admin",
          secret: "secret"
        }
      });
      const reseller = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/superadmin/admins",
        session: login.session,
        body: {
          username: "reseller-safe",
          password: "admin-pass",
          role: "admin",
          panelId: marzbanPanel.id,
          trafficLimitBytes: 1000,
          validUntil: "2030-01-02T23:59:59.000Z"
        }
      });

      await withMockFetch(
        [
          {
            ok: true,
            status: 200,
            json: async () => ({ access_token: "marzban-token" })
          },
          {
            ok: true,
            status: 200,
            json: async () => ({
              vless: [
                { tag: "WS TLS", protocol: "vless", network: "ws", tls: "tls", port: 10002 }
              ],
              vmess: [
                { tag: "VMess TLS", protocol: "vmess", network: "ws", tls: "tls", port: 10001 }
              ]
            })
          },
          {
            ok: true,
            status: 200,
            json: async () => ({ access_token: "marzban-token" })
          },
          {
            ok: true,
            status: 201,
            json: async () => ({ id: "remote-user" })
          },
          {
            ok: true,
            status: 200,
            json: async () => ({ access_token: "marzban-token" })
          },
          {
            ok: true,
            status: 200,
            json: async () => ({ username: "client-ok", subscription_url: "https://marzban.example.com/sub/client-ok" })
          }
        ],
        calls,
        async () => {
          await withMockDateNow(new Date("2030-01-01T12:00:00.000Z").getTime(), async () => {
            const resellerLogin = await callApi(handleApi, {
              method: "POST",
              pathname: "/api/auth/login",
              body: { username: reseller.username, password: "admin-pass" }
            });
            const allowed = await callApi(handleApi, {
              method: "POST",
              pathname: "/api/admin/users",
              session: resellerLogin.session,
              body: {
                username: "client-ok",
                limitBytes: 100,
                expiresAt: "2030-01-02T23:59:59.000Z",
                note: "within valid window"
              }
            });
            assert.equal(allowed.username, "client-ok");
            assert.equal(allowed.inboundId, "vless:WS TLS:10002");
            assert.deepEqual(allowed.inboundIds, ["vless:WS TLS:10002", "vmess:VMess TLS:10001"]);
          });
        }
      );
      assert.equal(calls.length, 6);

      const superadmin = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/superadmin/admins",
        session: login.session,
        body: {
          username: "super-valid",
          password: "super-pass",
          role: "superadmin",
          validUntil: "2000-01-01T23:59:59.000Z"
        }
      });
      const superLogin = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/auth/login",
        body: { username: superadmin.username, password: "super-pass" }
      });
      const txPanel = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/superadmin/panels",
        session: login.session,
        body: {
          name: "Tx Panel",
          type: "tx-ui",
          url: "https://panel.example.com"
        }
      });
      const superUser = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/admin/users",
        session: superLogin.session,
        body: {
          username: "super-client",
          panelId: txPanel.id,
          limitBytes: 100,
          expiresAt: null
        }
      });
      assert.equal(superUser.username, "super-client");
    }
  );
});

test("invalid quota values are rejected on user create", async () => {
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
          type: "tx-ui",
          url: "https://panel.example.com"
        }
      });

      const negativeLimit = await callApiWithOutcome(handleApi, {
        method: "POST",
        pathname: "/api/admin/users",
        session: login.session,
        body: {
          username: "neg-limit",
          panelId: panel.id,
          limitBytes: -1
        }
      });
      assert.equal(negativeLimit.statusCode, 400);
      assert.match(negativeLimit.json.error, /Invalid limitBytes/i);

      const nonNumericLimit = await callApiWithOutcome(handleApi, {
        method: "POST",
        pathname: "/api/admin/users",
        session: login.session,
        body: {
          username: "string-limit",
          panelId: panel.id,
          limitBytes: "10"
        }
      });
      assert.equal(nonNumericLimit.statusCode, 400);
      assert.match(nonNumericLimit.json.error, /Invalid limitBytes/i);

      const negativeUsed = await callApiWithOutcome(handleApi, {
        method: "POST",
        pathname: "/api/admin/users",
        session: login.session,
        body: {
          username: "neg-used",
          panelId: panel.id,
          usedBytes: -5
        }
      });
      assert.equal(negativeUsed.statusCode, 400);
      assert.match(negativeUsed.json.error, /Invalid usedBytes/i);
    }
  );
});

test("put cannot change quota accounting fields", async () => {
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
          type: "tx-ui",
          url: "https://panel.example.com"
        }
      });
      const user = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/admin/users",
        session: login.session,
        body: {
          username: "locked-user",
          panelId: panel.id,
          limitBytes: 200,
          usedBytes: 50
        }
      });

      for (const field of ["username", "panelId", "ownerAdminId", "usedBytes", "reservedBytes"]) {
        const res = await callApiWithOutcome(handleApi, {
          method: "PUT",
          pathname: `/api/admin/users/${user.id}`,
          session: login.session,
          body: {
            [field]: field === "ownerAdminId" ? "adm_other" : 999
          }
        });
        assert.equal(res.statusCode, 400);
        assert.match(res.json.error, new RegExp(`Cannot update ${field}`));
      }
    }
  );
});

test("delete returns at most the reserved bytes", async () => {
  const calls = [];
  await withTempEnv(
    {
      AEGIS_ADMIN_USERNAME: "env-admin",
      AEGIS_ADMIN_PASSWORD: "env-pass",
      AEGIS_DATA_DIR: "./tmp-data",
      AEGIS_SESSION_SECRET: "test-secret"
    },
    async () => {
      const handleApi = await importApiFresh();
      const { store } = await import("../src/storage/store.js");
      await withMockFetch([], calls, async () => {
        const login = await callApi(handleApi, {
          method: "POST",
          pathname: "/api/auth/login",
          body: { username: "env-admin", password: "env-pass" }
        });
        const owner = await callApi(handleApi, {
          method: "POST",
          pathname: "/api/superadmin/admins",
          session: login.session,
          body: {
            username: "cap-admin",
            password: "admin-pass",
            trafficLimitBytes: 1000
          }
        });
        const panel = await callApi(handleApi, {
          method: "POST",
          pathname: "/api/superadmin/panels",
          session: login.session,
          body: {
            name: "Panel One",
            type: "tx-ui",
            url: "https://panel.example.com"
          }
        });
        const user = await callApi(handleApi, {
          method: "POST",
          pathname: "/api/admin/users",
          session: login.session,
          body: {
            username: "tampered-user",
            panelId: panel.id,
            ownerAdminId: owner.id,
            limitBytes: 500,
            usedBytes: 100
          }
        });
        store.update("users", user.id, {
          limitBytes: 1200,
          usedBytes: 50,
          reservedBytes: 200
        });

        const before = await callApi(handleApi, {
          method: "GET",
          pathname: "/api/superadmin/admins",
          session: login.session
        });
        const beforeOwner = before.find((admin) => admin.username === "cap-admin");
        const deleted = await callApi(handleApi, {
          method: "DELETE",
          pathname: `/api/admin/users/${user.id}`,
          session: login.session
        });
        assert.equal(deleted.ok, true);
        const after = await callApi(handleApi, {
          method: "GET",
          pathname: "/api/superadmin/admins",
          session: login.session
        });
        const afterOwner = after.find((admin) => admin.username === "cap-admin");
        assert.equal(afterOwner.trafficRemainingBytes - beforeOwner.trafficRemainingBytes, 200);
      });
    }
  );
  assert.equal(calls.length, 0);
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
          type: "tx-ui",
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
      const panel = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/superadmin/panels",
        session: superLogin.session,
        body: {
          name: "Panel One",
          type: "tx-ui",
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
          type: "tx-ui",
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
          type: "tx-ui",
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

test("marzban-backed user creation reserves quota and calls the remote create api", async () => {
  const calls = [];
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
          name: "Marzban Panel",
          type: "marzban",
          url: "https://marzban.example.com/",
          username: "panel-admin",
          secret: "panel-secret"
        }
      });
      const owner = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/superadmin/admins",
        session: login.session,
        body: {
          username: "marz-owner",
          password: "admin-pass",
          panelId: panel.id,
          trafficLimitBytes: 1000
        }
      });
      const resellerLogin = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/auth/login",
        body: { username: owner.username, password: "admin-pass" }
      });

      await withMockFetch(
        [
          {
            ok: true,
            status: 200,
            json: async () => ({ access_token: "marzban-token" })
          },
          {
            ok: true,
            status: 200,
            json: async () => ({
              vless: [
                { tag: "WS TLS", protocol: "vless", network: "ws", tls: "tls", port: 10002 }
              ],
              vmess: [
                { tag: "VMess TLS", protocol: "vmess", network: "ws", tls: "tls", port: 10001 }
              ]
            })
          },
          {
            ok: true,
            status: 200,
            json: async () => ({ access_token: "marzban-token" })
          },
          {
            ok: true,
            status: 201,
            json: async () => ({ id: "remote-user-1", username: "marz-user", status: "active" })
          },
          {
            ok: true,
            status: 200,
            json: async () => ({ access_token: "marzban-token" })
          },
          {
            ok: true,
            status: 200,
            json: async () => ({ username: "marz-user", subscription_url: "https://marzban.example.com/sub/marz-user" })
          }
        ],
        calls,
        async () => {
          const created = await callApi(handleApi, {
            method: "POST",
            pathname: "/api/admin/users",
            session: resellerLogin.session,
            body: {
              username: "marz-user",
              limitBytes: 250,
              expiresAt: "2030-01-02T03:04:05.000Z",
              note: "Reseller customer"
            }
          });

          assert.equal(created.username, "marz-user");
          assert.equal(created.panelId, panel.id);
          assert.equal(created.limitBytes, 250);
          assert.equal(created.inboundId, "vless:WS TLS:10002");
          assert.deepEqual(created.inboundIds, ["vless:WS TLS:10002", "vmess:VMess TLS:10001"]);
          assert.equal(created.note, "Reseller customer");
        }
      );
      const admins = await callApi(handleApi, {
        method: "GET",
        pathname: "/api/superadmin/admins",
        session: login.session
      });
      const ownerAfter = admins.find((admin) => admin.username === "marz-owner");
      assert.equal(ownerAfter.trafficRemainingBytes, 750);
    }
  );

  assert.equal(calls.length, 6);
  assert.equal(calls[0].url, "https://marzban.example.com/api/admin/token");
  assert.equal(calls[1].url, "https://marzban.example.com/api/inbounds");
  assert.equal(calls[2].url, "https://marzban.example.com/api/admin/token");
  assert.equal(calls[3].url, "https://marzban.example.com/api/user");
  assert.equal(calls[3].options.headers.authorization, "Bearer marzban-token");
  const remoteCreateBody = JSON.parse(calls[3].options.body);
  assert.deepEqual(remoteCreateBody.inbounds, {
    vless: ["WS TLS"],
    vmess: ["VMess TLS"]
  });
  assert.equal(remoteCreateBody.note, "Reseller customer");
});

test("marzban user creation rolls back on remote failure", async () => {
  const calls = [];
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
      const owner = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/superadmin/admins",
        session: login.session,
        body: {
          username: "rollback-owner",
          password: "admin-pass",
          trafficLimitBytes: 1000
        }
      });
      const panel = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/superadmin/panels",
        session: login.session,
        body: {
          name: "Marzban Panel",
          type: "marzban",
          url: "https://marzban.example.com",
          subscriptionUrl: "https://marzban.example.com",
          username: "panel-admin",
          secret: "panel-secret"
        }
      });

      const beforeAdmins = await callApi(handleApi, {
        method: "GET",
        pathname: "/api/superadmin/admins",
        session: login.session
      });
      const beforeOwner = beforeAdmins.find((admin) => admin.username === "rollback-owner");

      await withMockFetch(
        [
          {
            ok: true,
            status: 200,
            json: async () => ({ access_token: "marzban-token" })
          },
          {
            ok: false,
            status: 500,
            json: async () => ({ detail: "boom" })
          }
        ],
        calls,
        async () => {
          const res = await callApiWithOutcome(handleApi, {
            method: "POST",
            pathname: "/api/admin/users",
            session: login.session,
            body: {
              username: "marz-fail",
              panelId: panel.id,
              ownerAdminId: owner.id,
              limitBytes: 300,
              usedBytes: 10,
              inboundIds: ["vless:WS TLS:10002"]
            }
          });

          assert.equal(res.statusCode, 500);
          assert.match(res.json.error, /Marzban create user failed with HTTP 500/i);
        }
      );

      const users = await callApi(handleApi, {
        method: "GET",
        pathname: "/api/admin/users",
        session: login.session
      });
      assert.equal(users.some((user) => user.username === "marz-fail"), false);

      const afterAdmins = await callApi(handleApi, {
        method: "GET",
        pathname: "/api/superadmin/admins",
        session: login.session
      });
      const afterOwner = afterAdmins.find((admin) => admin.username === "rollback-owner");
      assert.equal(afterOwner.trafficRemainingBytes, beforeOwner.trafficRemainingBytes);
    }
  );

  assert.equal(calls.length, 2);
  assert.equal(calls[0].url, "https://marzban.example.com/api/admin/token");
  assert.equal(calls[1].url, "https://marzban.example.com/api/user");
});

test("marzban-backed user update updates remote before local state and prefers a real primary inbound", async () => {
  const calls = [];
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
      const owner = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/superadmin/admins",
        session: login.session,
        body: {
          username: "update-owner",
          password: "admin-pass",
          trafficLimitBytes: 1000
        }
      });
      const panel = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/superadmin/panels",
        session: login.session,
        body: {
          name: "Marzban Panel",
          type: "marzban",
          url: "https://marzban.example.com/",
          username: "panel-admin",
          secret: "panel-secret"
        }
      });

      await withMockFetch(
        [
          {
            ok: true,
            status: 200,
            json: async () => ({ access_token: "marzban-token" })
          },
          {
            ok: true,
            status: 201,
            json: async () => ({ id: "remote-user-1", username: "update-user", status: "active" })
          },
          {
            ok: true,
            status: 200,
            json: async () => ({ access_token: "marzban-token" })
          },
          {
            ok: true,
            status: 200,
            json: async () => ({ username: "update-user", subscription_url: "https://marzban.example.com/sub/update-user" })
          }
        ],
        calls,
        async () => {
          const created = await callApi(handleApi, {
            method: "POST",
            pathname: "/api/admin/users",
            session: login.session,
            body: {
              username: "update-user",
              panelId: panel.id,
              ownerAdminId: owner.id,
              limitBytes: 300,
              usedBytes: 25,
              inboundIds: ["vless:WS TLS:10002"],
              inboundMode: "custom",
              expiresAt: "2030-01-02T03:04:05.000Z"
            }
          });
          assert.equal(created.username, "update-user");
        }
      );

      await withMockFetch(
        [
          {
            ok: true,
            status: 200,
            json: async () => ({ access_token: "marzban-token" })
          },
          {
            ok: true,
            status: 200,
            json: async () => ({ username: "update-user", status: "disabled" })
          }
        ],
        calls,
        async () => {
          const currentUsers = await callApi(handleApi, {
            method: "GET",
            pathname: "/api/admin/users",
            session: login.session
          });
          const updateUserId = currentUsers.find((user) => user.username === "update-user").id;
          const updated = await callApi(handleApi, {
            method: "PUT",
            pathname: `/api/admin/users/${updateUserId}`,
            session: login.session,
            body: {
              inboundIds: ["vless:METRICS_DUMMY:123", "vless:Falkenstein VLESS WS TLS:10002"],
              inboundId: "vless:METRICS_DUMMY:123",
              inboundMode: "custom",
              limitBytes: 400,
              expiresAt: "2030-02-03T04:05:06.000Z",
              note: "Renew at month-end",
              flow: "xtls-rprx-vision",
              active: false
            }
          });

          assert.equal(updated.username, "update-user");
          assert.equal(updated.inboundId, "vless:METRICS_DUMMY:123");
          assert.equal(updated.inboundMode, "custom");
          assert.deepEqual(updated.inboundIds, ["vless:METRICS_DUMMY:123", "vless:Falkenstein VLESS WS TLS:10002"]);
          assert.equal(updated.limitBytes, 400);
          assert.equal(updated.reservedBytes, 400);
          assert.equal(updated.note, "Renew at month-end");
          assert.equal(updated.flow, "xtls-rprx-vision");
          assert.equal(updated.active, false);
        }
      );

      const users = await callApi(handleApi, {
        method: "GET",
        pathname: "/api/admin/users",
        session: login.session
      });
      const stored = users.find((user) => user.username === "update-user");
      assert.equal(stored.inboundId, "vless:METRICS_DUMMY:123");
      assert.equal(stored.inboundMode, "custom");
      assert.equal(stored.limitBytes, 400);
      assert.equal(stored.reservedBytes, 400);
      assert.equal(stored.note, "Renew at month-end");
      assert.equal(stored.flow, "xtls-rprx-vision");
      assert.equal(stored.active, false);
      const admins = await callApi(handleApi, {
        method: "GET",
        pathname: "/api/superadmin/admins",
        session: login.session
      });
      const updatedOwner = admins.find((admin) => admin.username === "update-owner");
      assert.equal(updatedOwner.trafficRemainingBytes, 600);
      assert.equal(calls.length, 6);
      assert.equal(calls[4].url, "https://marzban.example.com/api/admin/token");
      assert.equal(calls[5].url, "https://marzban.example.com/api/user/update-user");
      assert.equal(calls[5].options.method, "PUT");
      assert.equal(JSON.parse(calls[5].options.body).data_limit, 400);
      assert.equal(JSON.parse(calls[5].options.body).note, "Renew at month-end");
    }
  );
});

test("marzban-backed user update rolls back when remote update fails", async () => {
  const calls = [];
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
      const owner = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/superadmin/admins",
        session: login.session,
        body: {
          username: "rollback-update-owner",
          password: "admin-pass",
          trafficLimitBytes: 1000
        }
      });
      const panel = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/superadmin/panels",
        session: login.session,
        body: {
          name: "Marzban Panel",
          type: "marzban",
          url: "https://marzban.example.com/",
          username: "panel-admin",
          secret: "panel-secret"
        }
      });

      await withMockFetch(
        [
          {
            ok: true,
            status: 200,
            json: async () => ({ access_token: "marzban-token" })
          },
          {
            ok: true,
            status: 201,
            json: async () => ({ id: "remote-user-1", username: "rollback-update-user", status: "active" })
          },
          {
            ok: true,
            status: 200,
            json: async () => ({ access_token: "marzban-token" })
          },
          {
            ok: true,
            status: 200,
            json: async () => ({ username: "rollback-update-user", subscription_url: "https://marzban.example.com/sub/rollback-update-user" })
          }
        ],
        calls,
        async () => {
          await callApi(handleApi, {
            method: "POST",
            pathname: "/api/admin/users",
            session: login.session,
            body: {
              username: "rollback-update-user",
              panelId: panel.id,
              ownerAdminId: owner.id,
              limitBytes: 300,
              usedBytes: 25,
              inboundIds: ["vless:WS TLS:10002"],
              expiresAt: "2030-01-02T03:04:05.000Z"
            }
          });
        }
      );

      const beforeUsers = await callApi(handleApi, {
        method: "GET",
        pathname: "/api/admin/users",
        session: login.session
      });
      const before = beforeUsers.find((user) => user.username === "rollback-update-user");

      await withMockFetch(
        [
          {
            ok: true,
            status: 200,
            json: async () => ({ access_token: "marzban-token" })
          },
          {
            ok: false,
            status: 500,
            json: async () => ({ detail: "boom" })
          }
        ],
        calls,
        async () => {
          const outcome = await callApiWithOutcome(handleApi, {
            method: "PUT",
            pathname: `/api/admin/users/${before.id}`,
            session: login.session,
            body: {
              inboundIds: ["vless:METRICS_DUMMY:123", "vless:Falkenstein VLESS WS TLS:10002"],
              inboundId: "vless:METRICS_DUMMY:123",
              inboundMode: "custom",
              expiresAt: "2030-02-03T04:05:06.000Z",
              flow: "xtls-rprx-vision",
              active: false
            }
          });

          assert.equal(outcome.statusCode, 500);
          assert.match(outcome.json.error, /Marzban update user failed with HTTP 500/i);
        }
      );

      const afterUsers = await callApi(handleApi, {
        method: "GET",
        pathname: "/api/admin/users",
        session: login.session
      });
      const after = afterUsers.find((user) => user.username === "rollback-update-user");
      assert.deepEqual(after, before);
      assert.equal(calls.length, 6);
    }
  );
});

test("reseller-backed user update allows safe fields and rejects technical routing fields", async () => {
  const calls = [];
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
          name: "Marzban Panel",
          type: "marzban",
          url: "https://marzban.example.com/",
          username: "panel-admin",
          secret: "panel-secret"
        }
      });
      const owner = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/superadmin/admins",
        session: login.session,
        body: {
          username: "reseller-edit-owner",
          password: "admin-pass",
          role: "admin",
          panelId: panel.id,
          trafficLimitBytes: 1000,
          validUntil: "2030-01-02T23:59:59.000Z"
        }
      });
      const resellerLogin = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/auth/login",
        body: { username: owner.username, password: "admin-pass" }
      });

      await withMockFetch(
        [
          {
            ok: true,
            status: 200,
            json: async () => ({ access_token: "marzban-token" })
          },
          {
            ok: true,
            status: 200,
            json: async () => ({
              vless: [
                { tag: "WS TLS", protocol: "vless", network: "ws", tls: "tls", port: 10002 }
              ],
              vmess: [
                { tag: "VMess TLS", protocol: "vmess", network: "ws", tls: "tls", port: 10001 }
              ]
            })
          },
          {
            ok: true,
            status: 200,
            json: async () => ({ access_token: "marzban-token" })
          },
          {
            ok: true,
            status: 201,
            json: async () => ({ id: "remote-user-2", username: "reseller-edit-user", status: "active" })
          }
        ],
        calls,
        async () => {
          await callApi(handleApi, {
            method: "POST",
            pathname: "/api/admin/users",
            session: resellerLogin.session,
            body: {
              username: "reseller-edit-user",
              limitBytes: 300,
              expiresAt: "2030-01-02T23:59:59.000Z",
              note: "Initial note"
            }
          });
        }
      );

      const beforeUpdateUsers = await callApi(handleApi, {
        method: "GET",
        pathname: "/api/admin/users",
        session: resellerLogin.session
      });
      const user = beforeUpdateUsers.find((item) => item.username === "reseller-edit-user");

      await withMockFetch(
        [
          {
            ok: true,
            status: 200,
            json: async () => ({ access_token: "marzban-token" })
          },
          {
            ok: true,
            status: 200,
            json: async () => ({ username: "reseller-edit-user", status: "disabled" })
          }
        ],
        calls,
        async () => {
          const updated = await callApi(handleApi, {
            method: "PUT",
            pathname: `/api/admin/users/${user.id}`,
            session: resellerLogin.session,
            body: {
              limitBytes: 400,
              expiresAt: "2030-02-03T04:05:06.000Z",
              note: "Renew at month-end",
              active: false
            }
          });
          assert.equal(updated.limitBytes, 400);
          assert.equal(updated.reservedBytes, 400);
          assert.equal(updated.note, "Renew at month-end");
          assert.equal(updated.active, false);
        }
      );

      const afterSafeUsers = await callApi(handleApi, {
        method: "GET",
        pathname: "/api/admin/users",
        session: resellerLogin.session
      });
      const updatedUser = afterSafeUsers.find((item) => item.username === "reseller-edit-user");
      assert.equal(updatedUser.limitBytes, 400);
      assert.equal(updatedUser.reservedBytes, 400);
      assert.equal(updatedUser.note, "Renew at month-end");
      assert.equal(updatedUser.active, false);

      const admins = await callApi(handleApi, {
        method: "GET",
        pathname: "/api/superadmin/admins",
        session: login.session
      });
      const updatedOwner = admins.find((admin) => admin.username === "reseller-edit-owner");
      assert.equal(updatedOwner.trafficRemainingBytes, 600);

      const beforeRejectCalls = calls.length;
      for (const field of ["inboundId", "inboundIds", "inboundMode", "flow", "panelId"]) {
        const value = field === "inboundIds"
          ? ["vless:WS TLS:10002"]
          : field === "inboundMode"
            ? "custom"
            : field === "panelId"
              ? panel.id
              : "blocked-value";
        const outcome = await callApiWithOutcome(handleApi, {
          method: "PUT",
          pathname: `/api/admin/users/${user.id}`,
          session: resellerLogin.session,
          body: { [field]: value }
        });
        assert.equal(outcome.statusCode, 400);
        assert.match(outcome.json.error, new RegExp(`Cannot update ${field}`, "i"));
      }
      assert.equal(calls.length, beforeRejectCalls);
    }
  );
});

test("reseller cannot edit another reseller's VPN account", async () => {
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
          type: "tx-ui",
          url: "https://panel.example.com"
        }
      });
      const ownerA = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/superadmin/admins",
        session: login.session,
        body: {
          username: "editor-a",
          password: "admin-pass-a",
          role: "admin",
          panelId: panel.id,
          trafficLimitBytes: 1000,
          validUntil: "2030-01-02T23:59:59.000Z"
        }
      });
      const ownerB = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/superadmin/admins",
        session: login.session,
        body: {
          username: "editor-b",
          password: "admin-pass-b",
          role: "admin",
          panelId: panel.id,
          trafficLimitBytes: 1000,
          validUntil: "2030-01-02T23:59:59.000Z"
        }
      });
      const ownerALogin = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/auth/login",
        body: { username: ownerA.username, password: "admin-pass-a" }
      });
      const ownerBLogin = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/auth/login",
        body: { username: ownerB.username, password: "admin-pass-b" }
      });

      const user = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/admin/users",
        session: ownerALogin.session,
        body: {
          username: "owner-a-user",
          limitBytes: 100,
          inboundId: "default",
          expiresAt: "2030-01-02T03:04:05.000Z"
        }
      });

      const outcome = await callApiWithOutcome(handleApi, {
        method: "PUT",
        pathname: `/api/admin/users/${user.id}`,
        session: ownerBLogin.session,
        body: {
          flow: "xtls-rprx-vision"
        }
      });

      assert.equal(outcome.statusCode, 404);
      assert.match(outcome.json.error, /User not found/i);
    }
  );
});

test("marzban-backed delete removes remote first and then local state", async () => {
  const calls = [];
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
      const owner = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/superadmin/admins",
        session: login.session,
        body: {
          username: "delete-owner",
          password: "admin-pass",
          trafficLimitBytes: 1000
        }
      });
      const panel = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/superadmin/panels",
        session: login.session,
        body: {
          name: "Marzban Panel",
          type: "marzban",
          url: "https://marzban.example.com",
          subscriptionUrl: "https://marzban.example.com",
          username: "panel-admin",
          secret: "panel-secret"
        }
      });

      await withMockFetch(
        [
          {
            ok: true,
            status: 200,
            json: async () => ({ access_token: "marzban-token" })
          },
          {
            ok: true,
            status: 201,
            json: async () => ({ id: "remote-user-1", username: "delete-me", status: "active" })
          },
          {
            ok: true,
            status: 200,
            json: async () => ({ access_token: "marzban-token" })
          },
          {
            ok: true,
            status: 200,
            json: async () => ({ used_traffic: 250 })
          },
          {
            ok: true,
            status: 200,
            json: async () => ({ access_token: "marzban-token" })
          },
          {
            ok: false,
            status: 204,
            json: async () => ({})
          }
        ],
        calls,
        async () => {
          const created = await callApi(handleApi, {
            method: "POST",
            pathname: "/api/admin/users",
            session: login.session,
            body: {
              username: "delete-me",
              panelId: panel.id,
              ownerAdminId: owner.id,
              limitBytes: 300,
              usedBytes: 120,
              inboundIds: ["vless:WS TLS:10002"]
            }
          });

          const beforeDeleteAdmins = await callApi(handleApi, {
            method: "GET",
            pathname: "/api/superadmin/admins",
            session: login.session
          });
          const beforeOwner = beforeDeleteAdmins.find((admin) => admin.username === "delete-owner");
          assert.equal(beforeOwner.trafficRemainingBytes, 700);

          const deleted = await callApi(handleApi, {
            method: "DELETE",
            pathname: `/api/admin/users/${created.id}`,
            session: login.session
          });
          assert.equal(deleted.ok, true);

          const users = await callApi(handleApi, {
            method: "GET",
            pathname: "/api/admin/users",
            session: login.session
          });
          assert.equal(users.some((user) => user.username === "delete-me"), false);

          const afterDeleteAdmins = await callApi(handleApi, {
            method: "GET",
            pathname: "/api/superadmin/admins",
            session: login.session
          });
          const afterOwner = afterDeleteAdmins.find((admin) => admin.username === "delete-owner");
          assert.equal(afterOwner.trafficRemainingBytes, 750);
        }
      );
    }
  );

  assert.equal(calls.length, 7);
  assert.equal(calls[0].url, "https://marzban.example.com/api/admin/token");
  assert.equal(calls[1].url, "https://marzban.example.com/api/user");
  assert.equal(calls[2].url, "https://marzban.example.com/api/admin/token");
  assert.equal(calls[3].url, "https://marzban.example.com/api/user/delete-me");
  assert.equal(calls[3].options.headers.authorization, "Bearer marzban-token");
  assert.equal(calls[4].url, "https://marzban.example.com/api/admin/token");
  assert.equal(calls[5].url, "https://marzban.example.com/api/user/delete-me");
  assert.equal(calls[5].options.method, "DELETE");
  assert.equal(calls[5].options.headers.authorization, "Bearer marzban-token");
});

test("marzban delete failure keeps the local user and quota untouched", async () => {
  const calls = [];
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
      const owner = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/superadmin/admins",
        session: login.session,
        body: {
          username: "delete-fail-owner",
          password: "admin-pass",
          trafficLimitBytes: 1000
        }
      });
      const panel = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/superadmin/panels",
        session: login.session,
        body: {
          name: "Marzban Panel",
          type: "marzban",
          url: "https://marzban.example.com",
          username: "panel-admin",
          secret: "panel-secret"
        }
      });

      await withMockFetch(
        [
          {
            ok: true,
            status: 200,
            json: async () => ({ access_token: "marzban-token" })
          },
          {
            ok: true,
            status: 201,
            json: async () => ({ id: "remote-user-2", username: "keep-me", status: "active" })
          },
          {
            ok: true,
            status: 200,
            json: async () => ({ access_token: "marzban-token" })
          },
          {
            ok: true,
            status: 200,
            json: async () => ({ username: "keep-me", subscription_url: "https://marzban.example.com/sub/keep-me" })
          },
          {
            ok: true,
            status: 200,
            json: async () => ({ access_token: "marzban-token" })
          },
          {
            ok: false,
            status: 500,
            json: async () => ({ detail: "boom" })
          }
        ],
        calls,
        async () => {
          const created = await callApi(handleApi, {
            method: "POST",
            pathname: "/api/admin/users",
            session: login.session,
            body: {
              username: "keep-me",
              panelId: panel.id,
              ownerAdminId: owner.id,
              limitBytes: 300,
              usedBytes: 120,
              inboundIds: ["vless:WS TLS:10002"]
            }
          });

          const deleteRes = await callApiWithOutcome(handleApi, {
            method: "DELETE",
            pathname: `/api/admin/users/${created.id}`,
            session: login.session
          });
          assert.equal(deleteRes.statusCode, 500);
          assert.match(deleteRes.json.error, /Marzban user lookup failed with HTTP 500/i);

          const users = await callApi(handleApi, {
            method: "GET",
            pathname: "/api/admin/users",
            session: login.session
          });
          assert.equal(users.some((user) => user.username === "keep-me"), true);

          const admins = await callApi(handleApi, {
            method: "GET",
            pathname: "/api/superadmin/admins",
            session: login.session
          });
          const deleteOwner = admins.find((admin) => admin.username === "delete-fail-owner");
          assert.equal(deleteOwner.trafficRemainingBytes, 700);
        }
      );
    }
  );

  assert.equal(calls.length, 7);
  assert.equal(calls[0].url, "https://marzban.example.com/api/admin/token");
  assert.equal(calls[1].url, "https://marzban.example.com/api/user");
  assert.equal(calls[2].url, "https://marzban.example.com/api/admin/token");
  assert.equal(calls[3].url, "https://marzban.example.com/api/user/keep-me");
  assert.equal(calls[4].url, "https://marzban.example.com/api/admin/token");
  assert.equal(calls[5].url, "https://marzban.example.com/api/user/keep-me");
});

test("marzban traffic lookup failure prevents delete and quota return", async () => {
  const calls = [];
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
      const owner = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/superadmin/admins",
        session: login.session,
        body: {
          username: "lookup-fail-owner",
          password: "admin-pass",
          trafficLimitBytes: 1000
        }
      });
      const panel = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/superadmin/panels",
        session: login.session,
        body: {
          name: "Marzban Panel",
          type: "marzban",
          url: "https://marzban.example.com",
          username: "panel-admin",
          secret: "panel-secret"
        }
      });

      await withMockFetch(
        [
          {
            ok: true,
            status: 200,
            json: async () => ({ access_token: "marzban-token" })
          },
          {
            ok: true,
            status: 201,
            json: async () => ({ id: "remote-user-3", username: "lookup-fail", status: "active" })
          },
          {
            ok: true,
            status: 200,
            json: async () => ({ access_token: "marzban-token" })
          },
          {
            ok: true,
            status: 200,
            json: async () => ({ username: "lookup-fail", subscription_url: "https://marzban.example.com/sub/lookup-fail" })
          },
          {
            ok: true,
            status: 200,
            json: async () => ({ access_token: "marzban-token" })
          },
          {
            ok: false,
            status: 500,
            json: async () => ({ detail: "boom" })
          }
        ],
        calls,
        async () => {
          const created = await callApi(handleApi, {
            method: "POST",
            pathname: "/api/admin/users",
            session: login.session,
            body: {
              username: "lookup-fail",
              panelId: panel.id,
              ownerAdminId: owner.id,
              limitBytes: 300,
              usedBytes: 120,
              inboundIds: ["vless:WS TLS:10002"]
            }
          });

          const deleteRes = await callApiWithOutcome(handleApi, {
            method: "DELETE",
            pathname: `/api/admin/users/${created.id}`,
            session: login.session
          });
          assert.equal(deleteRes.statusCode, 500);
          assert.match(deleteRes.json.error, /Marzban user lookup failed with HTTP 500/i);

          const users = await callApi(handleApi, {
            method: "GET",
            pathname: "/api/admin/users",
            session: login.session
          });
          assert.equal(users.some((user) => user.username === "lookup-fail"), true);

          const admins = await callApi(handleApi, {
            method: "GET",
            pathname: "/api/superadmin/admins",
            session: login.session
          });
          const lookupOwner = admins.find((admin) => admin.username === "lookup-fail-owner");
          assert.equal(lookupOwner.trafficRemainingBytes, 700);
        }
      );
    }
  );

  assert.equal(calls.length, 7);
  assert.equal(calls[0].url, "https://marzban.example.com/api/admin/token");
  assert.equal(calls[1].url, "https://marzban.example.com/api/user");
  assert.equal(calls[2].url, "https://marzban.example.com/api/admin/token");
  assert.equal(calls[3].url, "https://marzban.example.com/api/user/lookup-fail");
  assert.equal(calls[4].url, "https://marzban.example.com/api/admin/token");
  assert.equal(calls[5].url, "https://marzban.example.com/api/user/lookup-fail");
});

test("marzban single-user traffic sync updates local usedBytes", async () => {
  const calls = [];
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
      const owner = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/superadmin/admins",
        session: login.session,
        body: {
          username: "sync-owner",
          password: "admin-pass",
          trafficLimitBytes: 1000
        }
      });
      const panel = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/superadmin/panels",
        session: login.session,
        body: {
          name: "Marzban Panel",
          type: "marzban",
          url: "https://marzban.example.com",
          username: "panel-admin",
          secret: "panel-secret"
        }
      });

      await withMockFetch(
        [
          {
            ok: true,
            status: 200,
            json: async () => ({ access_token: "marzban-token" })
          },
          {
            ok: true,
            status: 201,
            json: async () => ({ id: "remote-user-4", username: "sync-me", status: "active" })
          },
          {
            ok: true,
            status: 200,
            json: async () => ({ access_token: "marzban-token" })
          },
          {
            ok: true,
            status: 200,
            json: async () => ({ username: "sync-me", subscription_url: "https://marzban.example.com/sub/sync-me" })
          },
          {
            ok: true,
            status: 200,
            json: async () => ({ access_token: "marzban-token" })
          },
          {
            ok: true,
            status: 200,
            json: async () => ({ used_traffic: 432 })
          }
        ],
        calls,
        async () => {
          const created = await callApi(handleApi, {
            method: "POST",
            pathname: "/api/admin/users",
            session: login.session,
            body: {
              username: "sync-me",
              panelId: panel.id,
              ownerAdminId: owner.id,
              limitBytes: 300,
              usedBytes: 10,
              inboundIds: ["vless:WS TLS:10002"]
            }
          });

          const synced = await callApi(handleApi, {
            method: "POST",
            pathname: `/api/admin/users/${created.id}/sync-traffic`,
            session: login.session
          });
          assert.equal(synced.usedBytes, 432);

          const users = await callApi(handleApi, {
            method: "GET",
            pathname: "/api/admin/users",
            session: login.session
          });
          const syncedUser = users.find((user) => user.username === "sync-me");
          assert.equal(syncedUser.usedBytes, 432);
        }
      );
    }
  );

  assert.equal(calls.length, 7);
  assert.equal(calls[0].url, "https://marzban.example.com/api/admin/token");
  assert.equal(calls[1].url, "https://marzban.example.com/api/user");
  assert.equal(calls[2].url, "https://marzban.example.com/api/admin/token");
  assert.equal(calls[3].url, "https://marzban.example.com/api/user/sync-me");
  assert.equal(calls[3].options.headers.authorization, "Bearer marzban-token");
});

test("marzban single-user traffic sync preserves existing subscriptionUrl when remote omits it", async () => {
  const calls = [];
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
      const owner = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/superadmin/admins",
        session: login.session,
        body: {
          username: "sync-owner-2",
          password: "admin-pass",
          trafficLimitBytes: 1000
        }
      });
      const panel = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/superadmin/panels",
        session: login.session,
        body: {
          name: "Marzban Panel 2",
          type: "marzban",
          url: "https://marzban.example.com",
          username: "panel-admin",
          secret: "panel-secret"
        }
      });

      await withMockFetch(
        [
          {
            ok: true,
            status: 200,
            json: async () => ({ access_token: "marzban-token" })
          },
          {
            ok: true,
            status: 201,
            json: async () => ({
              id: "remote-user-5",
              username: "sync-link",
              status: "active",
              subscription_url: "https://marzban.example.com/sub/sync-link"
            })
          },
          {
            ok: true,
            status: 200,
            json: async () => ({ access_token: "marzban-token" })
          },
          {
            ok: true,
            status: 200,
            json: async () => ({ used_traffic: 777 })
          }
        ],
        calls,
        async () => {
          const created = await callApi(handleApi, {
            method: "POST",
            pathname: "/api/admin/users",
            session: login.session,
            body: {
              username: "sync-link",
              panelId: panel.id,
              ownerAdminId: owner.id,
              limitBytes: 300,
              usedBytes: 10,
              inboundIds: ["vless:WS TLS:10002"]
            }
          });
          assert.equal(created.subscriptionUrl, "https://marzban.example.com/sub/sync-link");

          const synced = await callApi(handleApi, {
            method: "POST",
            pathname: `/api/admin/users/${created.id}/sync-traffic`,
            session: login.session
          });
          assert.equal(synced.usedBytes, 777);
          assert.equal(synced.subscriptionUrl, "https://marzban.example.com/sub/sync-link");

          const users = await callApi(handleApi, {
            method: "GET",
            pathname: "/api/admin/users",
            session: login.session
          });
          const syncedUser = users.find((user) => user.username === "sync-link");
          assert.equal(syncedUser.usedBytes, 777);
          assert.equal(syncedUser.subscriptionUrl, "https://marzban.example.com/sub/sync-link");
        }
      );
    }
  );

  assert.equal(calls.length, 5);
  assert.equal(calls[0].url, "https://marzban.example.com/api/admin/token");
  assert.equal(calls[1].url, "https://marzban.example.com/api/user");
  assert.equal(calls[2].url, "https://marzban.example.com/api/admin/token");
  assert.equal(calls[3].url, "https://marzban.example.com/api/user/sync-link");
});

test("marzban single-user traffic sync failure leaves local usedBytes unchanged", async () => {
  const calls = [];
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
      const owner = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/superadmin/admins",
        session: login.session,
        body: {
          username: "sync-fail-owner",
          password: "admin-pass",
          trafficLimitBytes: 1000
        }
      });
      const panel = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/superadmin/panels",
        session: login.session,
        body: {
          name: "Marzban Panel",
          type: "marzban",
          url: "https://marzban.example.com",
          username: "panel-admin",
          secret: "panel-secret"
        }
      });

      await withMockFetch(
        [
          {
            ok: true,
            status: 200,
            json: async () => ({ access_token: "marzban-token" })
          },
          {
            ok: true,
            status: 201,
            json: async () => ({ id: "remote-user-5", username: "sync-fail", status: "active" })
          },
          {
            ok: true,
            status: 200,
            json: async () => ({ access_token: "marzban-token" })
          },
          {
            ok: true,
            status: 200,
            json: async () => ({ username: "sync-fail", subscription_url: "https://marzban.example.com/sub/sync-fail" })
          },
          {
            ok: true,
            status: 200,
            json: async () => ({ access_token: "marzban-token" })
          },
          {
            ok: false,
            status: 500,
            json: async () => ({ detail: "boom" })
          }
        ],
        calls,
        async () => {
          const created = await callApi(handleApi, {
            method: "POST",
            pathname: "/api/admin/users",
            session: login.session,
            body: {
              username: "sync-fail",
              panelId: panel.id,
              ownerAdminId: owner.id,
              limitBytes: 300,
              usedBytes: 10,
              inboundIds: ["vless:WS TLS:10002"]
            }
          });

          const syncRes = await callApiWithOutcome(handleApi, {
            method: "POST",
            pathname: `/api/admin/users/${created.id}/sync-traffic`,
            session: login.session
          });
          assert.equal(syncRes.statusCode, 500);
          assert.match(syncRes.json.error, /Marzban user lookup failed with HTTP 500/i);

          const users = await callApi(handleApi, {
            method: "GET",
            pathname: "/api/admin/users",
            session: login.session
          });
          const syncedUser = users.find((user) => user.username === "sync-fail");
          assert.equal(syncedUser.usedBytes, 10);
        }
      );
    }
  );

  assert.equal(calls.length, 7);
  assert.equal(calls[0].url, "https://marzban.example.com/api/admin/token");
  assert.equal(calls[1].url, "https://marzban.example.com/api/user");
  assert.equal(calls[2].url, "https://marzban.example.com/api/admin/token");
  assert.equal(calls[3].url, "https://marzban.example.com/api/user/sync-fail");
  assert.equal(calls[4].url, "https://marzban.example.com/api/admin/token");
  assert.equal(calls[5].url, "https://marzban.example.com/api/user/sync-fail");
});

test("missing user returns 404 for single-user traffic sync", async () => {
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
        pathname: "/api/admin/users/user_missing/sync-traffic",
        session: login.session
      });
      assert.equal(res.statusCode, 404);
      assert.match(res.json.error, /User not found/i);
    }
  );
});

test("non-marzban panels return not implemented for single-user traffic sync", async () => {
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
          name: "Local Panel",
          type: "tx-ui",
          url: "https://tx.example.com"
        }
      });
      const user = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/admin/users",
        session: login.session,
        body: {
          username: "local-user",
          panelId: panel.id
        }
      });
      const res = await callApiWithOutcome(handleApi, {
        method: "POST",
        pathname: `/api/admin/users/${user.id}/sync-traffic`,
        session: login.session
      });
      assert.equal(res.statusCode, 501);
      assert.match(res.json.error, /Single-user traffic sync is not available for this panel type yet/i);
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
      const { store } = await import("../src/storage/store.js");
      let rawUserId = "";
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

      const owner = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/superadmin/admins",
        session,
        body: {
          username: "subscription-owner",
          password: "owner-pass",
          trafficLimitBytes: 100
        }
      });
      const rawPanel = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/superadmin/panels",
        session,
        body: {
          name: "Raw Subscription Panel",
          type: "marzban",
          url: "https://marzban.example.com",
          subscriptionUrl: "https://marzban.example.com",
          username: "panel-admin",
          secret: "panel-secret"
        }
      });

      await withMockFetch(
        [
          {
            ok: true,
            status: 200,
            json: async () => ({ access_token: "marzban-token" })
          },
          {
            ok: true,
            status: 201,
            json: async () => ({ id: "remote-raw-sub-user", username: "raw-sub-user", status: "active" })
          },
          {
            ok: true,
            status: 200,
            json: async () => ({ access_token: "marzban-token" })
          },
          {
            ok: true,
            status: 200,
            json: async () => ({ username: "raw-sub-user", subscription_url: "vless://example@127.0.0.1:123?path=%2F" })
          }
        ],
        [],
        async () => {
          const rawUser = await callApi(handleApi, {
            method: "POST",
            pathname: "/api/admin/users",
            session,
            body: {
              username: "raw-sub-user",
              panelId: rawPanel.id,
              ownerAdminId: owner.id,
              limitBytes: 10,
              usedBytes: 0,
              inboundIds: ["vless:WS TLS:10002"],
              expiresAt: "2030-01-02T00:00:00.000Z"
            }
          });
          rawUserId = rawUser.id;
        }
      );

      store.update("users", rawUserId, {
        subscriptionUrl: "vless://example@127.0.0.1:123?path=%2F"
      });

      await withMockFetch(
        [
          {
            ok: true,
            status: 200,
            json: async () => ({ access_token: "marzban-token" })
          },
          {
            ok: true,
            status: 200,
            json: async () => ({ username: "raw-sub-user", subscription_url: "vless://example@127.0.0.1:123?path=%2F" })
          }
        ],
        [],
        async () => {
          const users = await callApi(handleApi, {
            method: "GET",
            pathname: "/api/admin/users",
            session
          });
          const sanitizedUser = users.find((user) => user.username === "raw-sub-user");
          assert.equal(sanitizedUser.subscriptionUrl, "https://marzban.example.com/sub/raw-sub-user");
        }
      );
      const storedUser = store.list("users").find((user) => user.username === "raw-sub-user");
      assert.equal(storedUser.subscriptionUrl, "https://marzban.example.com/sub/raw-sub-user");

      const backup = await callApi(handleApi, {
        method: "GET",
        pathname: "/api/superadmin/backup",
        session
      });
      assert.equal(backup.app, "AegisPanel");
      assert.equal(backup.version, "0.1.0");
      assert.equal(backup.schemaVersion, 1);
      assert.equal(typeof backup.createdAt, "string");
      assert.equal(backup.data.panels[0].username, "panel-admin");
      assert.equal(backup.data.panels[0].secret, "panel-secret");
      assert.equal(backup.data.panels[0].apiKey, "");
      assert.equal(backup.data.sessionSecret, undefined);
    }
  );
});

test("superadmin restore backup validates metadata and confirmation", async () => {
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

      const invalidJson = await callApiWithOutcome(handleApi, {
        method: "POST",
        pathname: "/api/superadmin/restore",
        session: login.session,
        rawBody: `{"confirmation":"RESTORE","backup":`
      });
      assert.equal(invalidJson.statusCode, 400);
      assert.match(invalidJson.json.error, /Invalid JSON body/);

      const missingMetadata = await callApiWithOutcome(handleApi, {
        method: "POST",
        pathname: "/api/superadmin/restore",
        session: login.session,
        body: {
          confirmation: "RESTORE",
          backup: {
            data: {
              meta: { version: 1, product: "AegisPanel", createdAt: "2026-06-10T00:00:00.000Z" },
              admins: [],
              panels: [],
              users: [],
              trafficEvents: [],
              news: [],
              auditLogs: [],
              distribution: { edition: "community", status: "free", monetization: "disabled", seats: 3, expiresAt: null, updatedAt: "2026-06-10T00:00:00.000Z" }
            }
          }
        }
      });
      assert.equal(missingMetadata.statusCode, 400);
      assert.match(missingMetadata.json.error, /Invalid backup metadata/);

      const noAdmins = await callApiWithOutcome(handleApi, {
        method: "POST",
        pathname: "/api/superadmin/restore",
        session: login.session,
        body: {
          confirmation: "RESTORE",
          backup: {
            app: "AegisPanel",
            version: "0.1.0",
            schemaVersion: 1,
            createdAt: "2026-06-10T00:00:00.000Z",
            data: {
              meta: { version: 1, product: "AegisPanel", createdAt: "2026-06-10T00:00:00.000Z" },
              admins: [],
              panels: [],
              users: [],
              trafficEvents: [],
              news: [],
              auditLogs: [],
              distribution: { edition: "community", status: "free", monetization: "disabled", seats: 3, expiresAt: null, updatedAt: "2026-06-10T00:00:00.000Z" }
            }
          }
        }
      });
      assert.equal(noAdmins.statusCode, 400);
      assert.match(noAdmins.json.error, /Backup must contain at least one active SuperAdmin\./);

      const noSuperadmin = await callApiWithOutcome(handleApi, {
        method: "POST",
        pathname: "/api/superadmin/restore",
        session: login.session,
        body: {
          confirmation: "RESTORE",
          backup: {
            app: "AegisPanel",
            version: "0.1.0",
            schemaVersion: 1,
            createdAt: "2026-06-10T00:00:00.000Z",
            data: {
              meta: { version: 1, product: "AegisPanel", createdAt: "2026-06-10T00:00:00.000Z" },
              admins: [
                { id: "adm_1", username: "inactive-admin", role: "admin", active: true }
              ],
              panels: [],
              users: [],
              trafficEvents: [],
              news: [],
              auditLogs: [],
              distribution: { edition: "community", status: "free", monetization: "disabled", seats: 3, expiresAt: null, updatedAt: "2026-06-10T00:00:00.000Z" }
            }
          }
        }
      });
      assert.equal(noSuperadmin.statusCode, 400);
      assert.match(noSuperadmin.json.error, /Backup must contain at least one active SuperAdmin\./);

      const inactiveSuperadmin = await callApiWithOutcome(handleApi, {
        method: "POST",
        pathname: "/api/superadmin/restore",
        session: login.session,
        body: {
          confirmation: "RESTORE",
          backup: {
            app: "AegisPanel",
            version: "0.1.0",
            schemaVersion: 1,
            createdAt: "2026-06-10T00:00:00.000Z",
            data: {
              meta: { version: 1, product: "AegisPanel", createdAt: "2026-06-10T00:00:00.000Z" },
              admins: [
                { id: "adm_1", username: "disabled-superadmin", role: "superadmin", active: false }
              ],
              panels: [],
              users: [],
              trafficEvents: [],
              news: [],
              auditLogs: [],
              distribution: { edition: "community", status: "free", monetization: "disabled", seats: 3, expiresAt: null, updatedAt: "2026-06-10T00:00:00.000Z" }
            }
          }
        }
      });
      assert.equal(inactiveSuperadmin.statusCode, 400);
      assert.match(inactiveSuperadmin.json.error, /Backup must contain at least one active SuperAdmin\./);

      const confirmationRequired = await callApiWithOutcome(handleApi, {
        method: "POST",
        pathname: "/api/superadmin/restore",
        session: login.session,
        body: {
          confirmation: "NOPE",
          backup: {
            app: "AegisPanel",
            version: "0.1.0",
            schemaVersion: 1,
            createdAt: "2026-06-10T00:00:00.000Z",
            data: {
              meta: { version: 1, product: "AegisPanel", createdAt: "2026-06-10T00:00:00.000Z" },
              admins: [],
              panels: [],
              users: [],
              trafficEvents: [],
              news: [],
              auditLogs: [],
              distribution: { edition: "community", status: "free", monetization: "disabled", seats: 3, expiresAt: null, updatedAt: "2026-06-10T00:00:00.000Z" }
            }
          }
        }
      });
      assert.equal(confirmationRequired.statusCode, 400);
      assert.match(confirmationRequired.json.error, /Type RESTORE to confirm restore/);
    }
  );
});

test("superadmin restore backup updates local store data safely", async () => {
  await withTempEnv(
    {
      AEGIS_ADMIN_USERNAME: "env-admin",
      AEGIS_ADMIN_PASSWORD: "env-pass",
      AEGIS_DATA_DIR: "./tmp-data",
      AEGIS_SESSION_SECRET: "test-secret"
    },
    async () => {
      const handleApi = await importApiFresh();
      const { store } = await import("../src/storage/store.js");
      const login = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/auth/login",
        body: { username: "env-admin", password: "env-pass" }
      });
      const backup = await callApi(handleApi, {
        method: "GET",
        pathname: "/api/superadmin/backup",
        session: login.session
      });
      backup.data.panels.push({
        id: "pan_restore",
        name: "Restored panel",
        type: "marzban",
        url: "https://restore.example.com",
        subscriptionUrl: "https://restore.example.com",
        subscriptionPath: "sub",
        username: "restore-user",
        secret: "restore-secret",
        active: true
      });
      backup.data.meta = { ...backup.data.meta, createdAt: "2026-06-10T00:00:00.000Z" };
      backup.createdAt = "2026-06-10T00:00:00.000Z";
      const restore = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/superadmin/restore",
        session: login.session,
        body: {
          confirmation: "RESTORE",
          backup
        }
      });
      assert.equal(restore.snapshot.includes("aegispanel-restore-snapshot-"), true);
      assert.equal(store.list("panels").some((panel) => panel.id === "pan_restore"), true);
      assert.equal(store.list("panels").find((panel) => panel.id === "pan_restore").secret, "restore-secret");
      const logs = await callApi(handleApi, {
        method: "GET",
        pathname: "/api/superadmin/logs",
        session: login.session
      });
      assert.equal(logs[0].action, "backup.restore");
    }
  );
});

test("non-superadmin cannot restore a backup", async () => {
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
          username: "restore-admin",
          password: "admin-pass",
          role: "admin",
          trafficLimitBytes: 100
        }
      });
      const adminLogin = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/auth/login",
        body: { username: admin.username, password: "admin-pass" }
      });
      const restore = await callApiWithOutcome(handleApi, {
        method: "POST",
        pathname: "/api/superadmin/restore",
        session: adminLogin.session,
        body: {
          confirmation: "RESTORE",
          backup: {
            app: "AegisPanel",
            version: "0.1.0",
            schemaVersion: 1,
            createdAt: "2026-06-10T00:00:00.000Z",
            data: {
              meta: { version: 1, product: "AegisPanel", createdAt: "2026-06-10T00:00:00.000Z" },
              admins: [],
              panels: [],
              users: [],
              trafficEvents: [],
              news: [],
              auditLogs: [],
              distribution: { edition: "community", status: "free", monetization: "disabled", seats: 3, expiresAt: null, updatedAt: "2026-06-10T00:00:00.000Z" }
            }
          }
        }
      });
      assert.equal(restore.statusCode, 403);
      assert.match(restore.json.error, /Insufficient permissions/);
    }
  );
});

test("superadmin can edit panels safely without exposing credentials", async () => {
  await withTempEnv(
    {
      AEGIS_ADMIN_USERNAME: "env-admin",
      AEGIS_ADMIN_PASSWORD: "env-pass",
      AEGIS_DATA_DIR: "./tmp-data",
      AEGIS_SESSION_SECRET: "test-secret"
    },
    async () => {
      const handleApi = await importApiFresh();
      const { store } = await import("../src/storage/store.js");
      const login = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/auth/login",
        body: { username: "env-admin", password: "env-pass" }
      });

      const created = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/superadmin/panels",
        session: login.session,
        body: {
          name: "Editable Panel",
          type: "marzban",
          url: "https://panel.example.com",
          subscriptionUrl: "https://prefix.example.com",
          subscriptionPath: "/links/",
          allowInsecureTls: true,
          username: "panel-user",
          secret: "panel-secret",
          syncIntervalSeconds: 300
        }
      });
      assert.equal(created.allowInsecureTls, true);

      const editable = await callApi(handleApi, {
        method: "GET",
        pathname: `/api/superadmin/panels/${created.id}`,
        session: login.session
      });
      assert.equal(editable.username, "panel-user");
      assert.equal(editable.secret, undefined);
      assert.equal(editable.apiKey, undefined);
      assert.equal(editable.allowInsecureTls, true);

      const blankSecretUpdate = await callApi(handleApi, {
        method: "PUT",
        pathname: `/api/superadmin/panels/${created.id}`,
        session: login.session,
        body: {
          name: "Editable Panel Updated",
          type: "marzban",
          url: "https://panel-updated.example.com",
          subscriptionUrl: "https://prefix-updated.example.com",
          subscriptionPath: "//sub-links//",
          allowInsecureTls: false,
          username: "panel-user-updated",
          secret: "",
          active: false,
          syncIntervalSeconds: 900
        }
      });

      assert.equal(blankSecretUpdate.username, undefined);
      assert.equal(blankSecretUpdate.secret, undefined);
      assert.equal(blankSecretUpdate.apiKey, undefined);

      let panel = store.find("panels", created.id);
      assert.equal(panel.name, "Editable Panel Updated");
      assert.equal(panel.url, "https://panel-updated.example.com");
      assert.equal(panel.subscriptionUrl, "https://prefix-updated.example.com");
      assert.equal(panel.subscriptionPath, "sub-links");
      assert.equal(panel.allowInsecureTls, false);
      assert.equal(panel.username, "panel-user-updated");
      assert.equal(panel.secret, "panel-secret");
      assert.equal(panel.active, false);
      assert.equal(panel.syncIntervalSeconds, 900);

      const credentialUpdate = await callApi(handleApi, {
        method: "PUT",
        pathname: `/api/superadmin/panels/${created.id}`,
        session: login.session,
        body: {
          name: "Editable Panel Updated",
          url: "https://panel-updated.example.com",
          subscriptionUrl: "https://prefix-updated.example.com",
          subscriptionPath: "subscription",
          username: "panel-user-updated",
          secret: "panel-secret-updated",
          active: true,
          syncIntervalSeconds: 900
        }
      });

      assert.equal(credentialUpdate.secret, undefined);
      panel = store.find("panels", created.id);
      assert.equal(panel.secret, "panel-secret-updated");
      assert.equal(panel.subscriptionPath, "subscription");
      assert.equal(panel.active, true);
    }
  );
});

test("panel edit rejects invalid values and non-superadmins cannot edit panels", async () => {
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
          name: "Invalid Panel",
          type: "marzban",
          url: "https://panel.example.com",
          username: "panel-user",
          secret: "panel-secret"
        }
      });
      const invalidUrl = await callApiWithOutcome(handleApi, {
        method: "PUT",
        pathname: `/api/superadmin/panels/${panel.id}`,
        session: login.session,
        body: {
          name: "Invalid Panel",
          url: "ftp://panel.example.com"
        }
      });
      assert.equal(invalidUrl.statusCode, 400);
      assert.match(invalidUrl.json.error, /Invalid url/i);

      const invalidSubscriptionUrl = await callApiWithOutcome(handleApi, {
        method: "PUT",
        pathname: `/api/superadmin/panels/${panel.id}`,
        session: login.session,
        body: {
          name: "Invalid Panel",
          subscriptionUrl: "vless://example@127.0.0.1:123"
        }
      });
      assert.equal(invalidSubscriptionUrl.statusCode, 400);
      assert.match(invalidSubscriptionUrl.json.error, /Invalid subscriptionUrl/i);

      const normalizedPath = await callApi(handleApi, {
        method: "PUT",
        pathname: `/api/superadmin/panels/${panel.id}`,
        session: login.session,
        body: {
          name: "Invalid Panel",
          url: "https://panel-two.example.com",
          subscriptionPath: "//custom-sub//"
        }
      });
      assert.equal(normalizedPath.subscriptionPath, "custom-sub");

      await callApi(handleApi, {
        method: "POST",
        pathname: "/api/superadmin/admins",
        session: login.session,
        body: {
          username: "panel-editor",
          password: "editor-pass",
          role: "admin",
          panelId: panel.id
        }
      });
      const adminLogin = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/auth/login",
        body: { username: "panel-editor", password: "editor-pass" }
      });
      const blocked = await callApiWithOutcome(handleApi, {
        method: "PUT",
        pathname: `/api/superadmin/panels/${panel.id}`,
        session: adminLogin.session,
        body: {
          name: "Should not work",
          url: "https://blocked.example.com"
        }
      });
      assert.equal(blocked.statusCode, 403);
      assert.match(blocked.json.error, /Insufficient permissions/i);
    }
  );
});

test("marzban adapter methods are explicit not-implemented skeletons", async () => {
  for (const method of ["sync"]) {
    await assert.rejects(marzbanAdapter[method](), (error) => {
      assert.equal(error.status, 501);
      assert.match(error.message, /Marzban .* is not implemented yet/);
      return true;
    });
  }
});

test("marzban syncUserTraffic uses the remote user lookup endpoint", async () => {
  const calls = [];
  await withMockFetch(
    [
      {
        ok: true,
        status: 200,
        json: async () => ({ access_token: "marzban-token" })
      },
      {
        ok: true,
        status: 200,
        json: async () => ({ used_traffic: 222 })
      }
    ],
    calls,
    async () => {
      const result = await marzbanAdapter.syncUserTraffic(
        {
          url: "https://marzban.example.com/",
          username: "admin",
          password: "secret"
        },
        {
          username: "alice",
          usedBytes: 10
        }
      );

      assert.deepEqual(result, {
        username: "alice",
        usedBytes: 222,
        subscriptionId: "alice",
        subscriptionUrl: null
      });
    }
  );

  assert.equal(calls.length, 2);
  assert.equal(calls[0].url, "https://marzban.example.com/api/admin/token");
  assert.equal(calls[1].url, "https://marzban.example.com/api/user/alice");
  assert.equal(calls[1].options.headers.authorization, "Bearer marzban-token");
});

test("marzban syncUserTraffic falls back to local usedBytes when remote traffic is missing", async () => {
  await withMockFetch(
    [
      {
        ok: true,
        status: 200,
        json: async () => ({ access_token: "marzban-token" })
      },
      {
        ok: true,
        status: 200,
        json: async () => ({ username: "alice" })
      }
    ],
    [],
    async () => {
      const result = await marzbanAdapter.syncUserTraffic(
        {
          url: "https://marzban.example.com",
          username: "admin",
          password: "secret"
        },
        {
          username: "alice",
          usedBytes: 55
        }
      );

      assert.deepEqual(result, {
        username: "alice",
        usedBytes: 55,
        subscriptionId: "alice",
        subscriptionUrl: null
      });
    }
  );
});

test("marzban deleteUser sends the verified delete endpoint and treats 404 as success", async () => {
  const calls = [];
  await withMockFetch(
    [
      {
        ok: true,
        status: 200,
        json: async () => ({ access_token: "marzban-token" })
      },
      {
        ok: false,
        status: 404,
        json: async () => ({ detail: "not found" })
      }
    ],
    calls,
    async () => {
      const result = await marzbanAdapter.deleteUser(
        {
          url: "https://marzban.example.com/",
          username: "admin",
          password: "secret"
        },
        {
          username: "alice"
        }
      );

      assert.deepEqual(result, { ok: true, username: "alice", status: "missing" });
    }
  );

  assert.equal(calls.length, 2);
  assert.equal(calls[0].url, "https://marzban.example.com/api/admin/token");
  assert.equal(calls[1].url, "https://marzban.example.com/api/user/alice");
  assert.equal(calls[1].options.method, "DELETE");
  assert.equal(calls[1].options.headers.authorization, "Bearer marzban-token");
});

test("marzban getUser looks up remote traffic with Bearer auth", async () => {
  const calls = [];
  await withMockFetch(
    [
      {
        ok: true,
        status: 200,
        json: async () => ({ access_token: "marzban-token" })
      },
      {
        ok: true,
        status: 200,
        json: async () => ({
          used_traffic: 321,
          data: { links: { subscriptionUrl: "https://marzban.example.com/sub/alice" } }
        })
      }
    ],
    calls,
    async () => {
      const result = await marzbanAdapter.getUser(
        {
          url: "https://marzban.example.com/",
          username: "admin",
          password: "secret"
        },
        {
          username: "alice",
          usedBytes: 10
        }
      );

      assert.deepEqual(result, {
        username: "alice",
        usedBytes: 321,
        subscriptionId: "alice",
        subscriptionUrl: "https://marzban.example.com/sub/alice"
      });
    }
  );

  assert.equal(calls.length, 2);
  assert.equal(calls[0].url, "https://marzban.example.com/api/admin/token");
  assert.equal(calls[1].url, "https://marzban.example.com/api/user/alice");
  assert.equal(calls[1].options.headers.authorization, "Bearer marzban-token");
});

test("marzban getUser ignores raw config links when resolving subscriptionUrl", async () => {
  await withMockFetch(
    [
      {
        ok: true,
        status: 200,
        json: async () => ({ access_token: "marzban-token" })
      },
      {
        ok: true,
        status: 200,
        json: async () => ({
          used_traffic: 321,
          subscription_url: "vless://example@127.0.0.1:123?path=%2F"
        })
      }
    ],
    [],
    async () => {
      const result = await marzbanAdapter.getUser(
        {
          url: "https://marzban.example.com",
          subscriptionUrl: "https://marzban.example.com",
          username: "admin",
          password: "secret"
        },
        {
          username: "alice",
          usedBytes: 10
        }
      );

      assert.deepEqual(result, {
        username: "alice",
        usedBytes: 321,
        subscriptionId: "alice",
        subscriptionUrl: "https://marzban.example.com/sub/alice"
      });
    }
  );
});

test("marzban getUser resolves a relative subscription path against the panel base", async () => {
  await withMockFetch(
    [
      {
        ok: true,
        status: 200,
        json: async () => ({ access_token: "marzban-token" })
      },
      {
        ok: true,
        status: 200,
        json: async () => ({
          used_traffic: 321,
          data: { links: { subUrl: "/sub/alice" } }
        })
      }
    ],
    [],
    async () => {
      const result = await marzbanAdapter.getUser(
        {
          url: "https://marzban.example.com/",
          subscriptionUrl: "https://marzban.example.com/subscriptions/",
          username: "admin",
          password: "secret"
        },
        {
          username: "alice",
          usedBytes: 10
        }
      );

      assert.deepEqual(result, {
        username: "alice",
        usedBytes: 321,
        subscriptionId: "alice",
        subscriptionUrl: "https://marzban.example.com/sub/alice"
      });
    }
  );
});

test("marzban getUser builds subscriptionUrl from subscriptionId and panel path", async () => {
  await withMockFetch(
    [
      {
        ok: true,
        status: 200,
        json: async () => ({ access_token: "marzban-token" })
      },
      {
        ok: true,
        status: 200,
        json: async () => ({ used_traffic: 321 })
      }
    ],
    [],
    async () => {
      const result = await marzbanAdapter.getUser(
        {
          url: "https://marzban.example.com/",
          subscriptionUrl: "https://marzban.example.com/",
          subscriptionPath: "subscription",
          username: "admin",
          password: "secret"
        },
        {
          username: "alice",
          subscriptionId: "ticket-123",
          usedBytes: 10
        }
      );

      assert.deepEqual(result, {
        username: "alice",
        usedBytes: 321,
        subscriptionId: "ticket-123",
        subscriptionUrl: "https://marzban.example.com/subscription/ticket-123"
      });
    }
  );
});

test("marzban getUser falls back to local usedBytes when remote traffic is missing", async () => {
  await withMockFetch(
    [
      {
        ok: true,
        status: 200,
        json: async () => ({ access_token: "marzban-token" })
      },
      {
        ok: true,
        status: 200,
        json: async () => ({ username: "alice" })
      }
    ],
    [],
    async () => {
      const result = await marzbanAdapter.getUser(
        {
          url: "https://marzban.example.com",
          username: "admin",
          password: "secret"
        },
        {
          username: "alice",
          usedBytes: 77
        }
      );

      assert.deepEqual(result, {
        username: "alice",
        usedBytes: 77,
        subscriptionId: "alice",
        subscriptionUrl: null
      });
    }
  );
});

test("marzban createUser sends the verified create payload", async () => {
  const calls = [];
  await withMockFetch(
    [
      {
        ok: true,
        status: 200,
        json: async () => ({ access_token: "marzban-token" })
      },
      {
        ok: true,
        status: 201,
        json: async () => ({ id: 42, username: "alice", status: "active", subscription_url: "https://marzban.example.com/sub/alice" })
      }
    ],
    calls,
    async () => {
      const result = await marzbanAdapter.createUser(
        {
          url: "https://marzban.example.com/",
          username: "admin",
          password: "secret"
        },
        {
          username: "alice",
          limitBytes: 1234,
          expiresAt: "2030-01-02T03:04:05.000Z",
          inboundIds: ["vless:WS TLS:10002", "vmess:VMESS TLS:10001"]
        }
      );

      assert.equal(result.id, 42);
      assert.equal(result.username, "alice");
      assert.equal(result.status, "active");
      assert.equal(result.subscriptionUrl, "https://marzban.example.com/sub/alice");
      assert.equal("access_token" in result, false);
      assert.equal("password" in result, false);
      assert.equal("secret" in result, false);

      assert.equal(calls.length, 2);
      assert.equal(calls[0].url, "https://marzban.example.com/api/admin/token");
      assert.equal(calls[0].options.method, "POST");
      assert.equal(calls[0].options.headers["content-type"], "application/x-www-form-urlencoded");
      assert.equal(calls[0].options.body instanceof URLSearchParams, true);
      assert.equal(calls[0].options.body.get("username"), "admin");
      assert.equal(calls[0].options.body.get("password"), "secret");

      assert.equal(calls[1].url, "https://marzban.example.com/api/user");
      assert.equal(calls[1].options.method, "POST");
      assert.equal(calls[1].options.headers.authorization, "Bearer marzban-token");
      assert.equal(calls[1].options.headers["content-type"], "application/json");
      assert.deepEqual(JSON.parse(calls[1].options.body), {
        username: "alice",
        status: "active",
        expire: 1893553445,
        data_limit: 1234,
        data_limit_reset_strategy: "no_reset",
        inbounds: {
          vless: ["WS TLS"],
          vmess: ["VMESS TLS"]
        },
        proxies: {
          vless: {},
          vmess: {}
        },
        note: "",
        on_hold_expire_duration: 0,
        on_hold_timeout: null,
        next_plan: {
          data_limit: 0,
          expire: 0,
          add_remaining_traffic: false,
          fire_on_either: true
        }
      });
    }
  );
});

test("marzban-backed create backfills subscriptionUrl from remote lookup when the create response omits it", async () => {
  const calls = [];
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
      const owner = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/superadmin/admins",
        session: login.session,
        body: {
          username: "create-link-owner",
          password: "admin-pass",
          trafficLimitBytes: 1000
        }
      });
      const panel = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/superadmin/panels",
        session: login.session,
        body: {
          name: "Marzban Panel",
          type: "marzban",
          url: "https://marzban.example.com",
          subscriptionUrl: "https://marzban.example.com",
          username: "panel-admin",
          secret: "panel-secret"
        }
      });

      await withMockFetch(
        [
          {
            ok: true,
            status: 200,
            json: async () => ({ access_token: "marzban-token" })
          },
          {
            ok: true,
            status: 201,
            json: async () => ({ username: "create-link-user", status: "active" })
          },
          {
            ok: true,
            status: 200,
            json: async () => ({ access_token: "marzban-token" })
          },
          {
            ok: true,
            status: 200,
            json: async () => ({ username: "create-link-user" })
          }
        ],
        calls,
        async () => {
          const created = await callApi(handleApi, {
            method: "POST",
            pathname: "/api/admin/users",
            session: login.session,
            body: {
              username: "create-link-user",
              panelId: panel.id,
              ownerAdminId: owner.id,
              limitBytes: 100,
              usedBytes: 0,
              expiresAt: "2030-01-02T23:59:59.000Z",
              inboundIds: ["vless:WS TLS:10002"],
              inboundId: "vless:WS TLS:10002"
            }
          });

          assert.equal(created.subscriptionUrl, "https://marzban.example.com/sub/create-link-user");
          assert.equal(calls.length, 2);
          assert.equal(calls[0].url, "https://marzban.example.com/api/admin/token");
          assert.equal(calls[1].url, "https://marzban.example.com/api/user");
        }
      );
    }
  );
});

test("marzban-backed create does not store raw config links as subscriptionUrl", async () => {
  const calls = [];
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
      const owner = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/superadmin/admins",
        session: login.session,
        body: {
          username: "raw-link-owner",
          password: "admin-pass",
          trafficLimitBytes: 1000
        }
      });
      const panel = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/superadmin/panels",
        session: login.session,
        body: {
          name: "Marzban Panel",
          type: "marzban",
          url: "https://marzban.example.com",
          subscriptionUrl: "https://marzban.example.com",
          username: "panel-admin",
          secret: "panel-secret"
        }
      });

      await withMockFetch(
        [
          {
            ok: true,
            status: 200,
            json: async () => ({ access_token: "marzban-token" })
          },
          {
            ok: true,
            status: 201,
            json: async () => ({
              username: "raw-link-user",
              subscription_url: "vless://example@127.0.0.1:123?path=%2F"
            })
          },
          {
            ok: true,
            status: 200,
            json: async () => ({ access_token: "marzban-token" })
          },
          {
            ok: true,
            status: 200,
            json: async () => ({ username: "raw-link-user" })
          }
        ],
        calls,
        async () => {
          const created = await callApi(handleApi, {
            method: "POST",
            pathname: "/api/admin/users",
            session: login.session,
            body: {
              username: "raw-link-user",
              panelId: panel.id,
              ownerAdminId: owner.id,
              limitBytes: 100,
              usedBytes: 0,
              expiresAt: "2030-01-02T23:59:59.000Z",
              inboundIds: ["vless:WS TLS:10002"],
              inboundId: "vless:WS TLS:10002"
            }
          });

          assert.equal(created.subscriptionUrl, "https://marzban.example.com/sub/raw-link-user");
          assert.equal(calls.length, 2);
        }
      );
    }
  );
});

test("marzban createUser keeps selected inbound order for the local primary id", async () => {
  const calls = [];
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
      const owner = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/superadmin/admins",
        session: login.session,
        body: {
          username: "metrics-preferred-owner",
          password: "admin-pass",
          trafficLimitBytes: 1000
        }
      });
      const panel = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/superadmin/panels",
        session: login.session,
        body: {
          name: "Marzban Panel",
          type: "marzban",
          url: "https://marzban.example.com",
          username: "panel-admin",
          secret: "panel-secret"
        }
      });

      await withMockFetch(
        [
          {
            ok: true,
            status: 200,
            json: async () => ({ access_token: "marzban-token" })
          },
          {
            ok: true,
            status: 201,
            json: async () => ({ username: "metrics-preferred-user" })
          },
          {
            ok: true,
            status: 200,
            json: async () => ({ access_token: "marzban-token" })
          },
          {
            ok: true,
            status: 200,
            json: async () => ({ username: "metrics-preferred-user", subscription_url: "https://marzban.example.com/sub/metrics-preferred-user" })
          }
        ],
        calls,
        async () => {
          const created = await callApi(handleApi, {
            method: "POST",
            pathname: "/api/admin/users",
            session: login.session,
            body: {
              username: "metrics-preferred-user",
              panelId: panel.id,
              ownerAdminId: owner.id,
              limitBytes: 250,
              usedBytes: 25,
              inboundIds: ["vless:METRICS_DUMMY:123", "vless:WS TLS:10002"],
              inboundId: "vless:METRICS_DUMMY:123",
              expiresAt: "2030-01-02T03:04:05.000Z"
            }
          });

          assert.equal(created.username, "metrics-preferred-user");
          assert.equal(created.inboundId, "vless:METRICS_DUMMY:123");
          assert.equal(created.inboundMode, "custom");
          assert.deepEqual(created.inboundIds, ["vless:METRICS_DUMMY:123", "vless:WS TLS:10002"]);
        }
      );

      const admins = await callApi(handleApi, {
        method: "GET",
        pathname: "/api/superadmin/admins",
        session: login.session
      });
      const ownerAfter = admins.find((admin) => admin.username === "metrics-preferred-owner");
      assert.equal(ownerAfter.trafficRemainingBytes, 750);
    }
  );
  assert.equal(calls.length, 4);
});

test("marzban createUser keeps styled inbound selection order", async () => {
  const calls = [];
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
      const owner = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/superadmin/admins",
        session: login.session,
        body: {
          username: "styled-metrics-owner",
          password: "admin-pass",
          trafficLimitBytes: 1000
        }
      });
      const panel = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/superadmin/panels",
        session: login.session,
        body: {
          name: "Marzban Panel",
          type: "marzban",
          url: "https://marzban.example.com",
          username: "panel-admin",
          secret: "panel-secret"
        }
      });

      await withMockFetch(
        [
          {
            ok: true,
            status: 200,
            json: async () => ({ access_token: "marzban-token" })
          },
          {
            ok: true,
            status: 201,
            json: async () => ({ username: "styled-metrics-user" })
          },
          {
            ok: true,
            status: 200,
            json: async () => ({ access_token: "marzban-token" })
          },
          {
            ok: true,
            status: 200,
            json: async () => ({ username: "styled-metrics-user", subscription_url: "https://marzban.example.com/sub/styled-metrics-user" })
          }
        ],
        calls,
        async () => {
          const created = await callApi(handleApi, {
            method: "POST",
            pathname: "/api/admin/users",
            session: login.session,
            body: {
              username: "styled-metrics-user",
              panelId: panel.id,
              ownerAdminId: owner.id,
              limitBytes: 100,
              usedBytes: 0,
              inboundIds: ["vless:𝐌𝐄𝐓𝐑𝐈𝐂𝐒_𝐃𝐔𝐌𝐌𝐘:123", "vless:Falkenstein VLESS WS TLS:10002"],
              inboundId: "vless:𝐌𝐄𝐓𝐑𝐈𝐂𝐒_𝐃𝐔𝐌𝐌𝐘:123",
              expiresAt: "2030-01-02T03:04:05.000Z"
            }
          });

          assert.equal(created.username, "styled-metrics-user");
          assert.equal(created.inboundId, "vless:𝐌𝐄𝐓𝐑𝐈𝐂𝐒_𝐃𝐔𝐌𝐌𝐘:123");
          assert.deepEqual(created.inboundIds, ["vless:𝐌𝐄𝐓𝐑𝐈𝐂𝐒_𝐃𝐔𝐌𝐌𝐘:123", "vless:Falkenstein VLESS WS TLS:10002"]);
        }
      );
      const users = await callApi(handleApi, {
        method: "GET",
        pathname: "/api/admin/users",
        session: login.session
      });
      const createdUser = users.find((user) => user.username === "styled-metrics-user");
      assert.equal(createdUser.inboundId, "vless:𝐌𝐄𝐓𝐑𝐈𝐂𝐒_𝐃𝐔𝐌𝐌𝐘:123");
      assert.equal(calls.length, 4);
    }
  );
});

test("marzban createUser allows metrics-only inbound selection", async () => {
  const calls = [];
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
      const owner = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/superadmin/admins",
        session: login.session,
        body: {
          username: "metrics-only-owner",
          password: "admin-pass",
          trafficLimitBytes: 1000
        }
      });
      const panel = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/superadmin/panels",
        session: login.session,
        body: {
          name: "Marzban Panel",
          type: "marzban",
          url: "https://marzban.example.com",
          username: "panel-admin",
          secret: "panel-secret"
        }
      });

      await withMockFetch(
        [
          {
            ok: true,
            status: 200,
            json: async () => ({ access_token: "marzban-token" })
          },
          {
            ok: true,
            status: 201,
            json: async () => ({ username: "metrics-only-user", subscription_url: "https://marzban.example.com/sub/metrics-only-user" })
          }
        ],
        calls,
        async () => {
          const res = await callApiWithOutcome(handleApi, {
            method: "POST",
            pathname: "/api/admin/users",
            session: login.session,
            body: {
              username: "metrics-only-user",
              panelId: panel.id,
              ownerAdminId: owner.id,
              limitBytes: 100,
              usedBytes: 0,
              inboundIds: ["vless:METRICS_DUMMY:123"],
              inboundId: "vless:METRICS_DUMMY:123",
              expiresAt: "2030-01-02T03:04:05.000Z"
            }
          });

          assert.equal(res.statusCode, 201);
          assert.equal(res.json.data.inboundId, "vless:METRICS_DUMMY:123");
          assert.deepEqual(res.json.data.inboundIds, ["vless:METRICS_DUMMY:123"]);

          const admins = await callApi(handleApi, {
            method: "GET",
            pathname: "/api/superadmin/admins",
            session: login.session
          });
          const ownerAfter = admins.find((admin) => admin.username === "metrics-only-owner");
          assert.equal(ownerAfter.trafficRemainingBytes, 900);
        }
      );
    }
  );
  assert.equal(calls.length, 2);
});

test("marzban-backed user update allows metrics-only inbound selection", async () => {
  const calls = [];
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
      const owner = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/superadmin/admins",
        session: login.session,
        body: {
          username: "metrics-only-edit-owner",
          password: "admin-pass",
          trafficLimitBytes: 1000
        }
      });
      const panel = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/superadmin/panels",
        session: login.session,
        body: {
          name: "Marzban Panel",
          type: "marzban",
          url: "https://marzban.example.com",
          username: "panel-admin",
          secret: "panel-secret"
        }
      });

      await withMockFetch(
        [
          {
            ok: true,
            status: 200,
            json: async () => ({ access_token: "marzban-token" })
          },
          {
            ok: true,
            status: 201,
            json: async () => ({ username: "metrics-only-edit-user", subscription_url: "https://marzban.example.com/sub/metrics-only-edit-user" })
          },
          {
            ok: true,
            status: 200,
            json: async () => ({ access_token: "marzban-token" })
          },
          {
            ok: true,
            status: 200,
            json: async () => ({ username: "metrics-only-edit-user", subscription_url: "https://marzban.example.com/sub/metrics-only-edit-user" })
          }
        ],
        calls,
        async () => {
          const created = await callApi(handleApi, {
            method: "POST",
            pathname: "/api/admin/users",
            session: login.session,
            body: {
              username: "metrics-only-edit-user",
              panelId: panel.id,
              ownerAdminId: owner.id,
              limitBytes: 100,
              usedBytes: 0,
              inboundIds: ["vless:WS TLS:10002"],
              inboundId: "vless:WS TLS:10002",
              expiresAt: "2030-01-02T03:04:05.000Z"
            }
          });

          const res = await callApiWithOutcome(handleApi, {
            method: "PUT",
            pathname: `/api/admin/users/${created.id}`,
            session: login.session,
            body: {
              inboundIds: ["vless:METRICS_DUMMY:123"],
              inboundId: "vless:METRICS_DUMMY:123"
            }
          });

          assert.equal(res.statusCode, 200);
          assert.equal(res.json.data.inboundId, "vless:METRICS_DUMMY:123");
          assert.deepEqual(res.json.data.inboundIds, ["vless:METRICS_DUMMY:123"]);
        }
      );
    }
  );
  assert.equal(calls.length, 4);
});

test("marzban createUser stores inboundMode all when all selected inbounds are sent", async () => {
  const calls = [];
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
      const owner = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/superadmin/admins",
        session: login.session,
        body: {
          username: "all-mode-owner",
          password: "admin-pass",
          trafficLimitBytes: 1000
        }
      });
      const panel = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/superadmin/panels",
        session: login.session,
        body: {
          name: "Marzban Panel",
          type: "marzban",
          url: "https://marzban.example.com",
          username: "panel-admin",
          secret: "panel-secret"
        }
      });

      await withMockFetch(
        [
          {
            ok: true,
            status: 200,
            json: async () => ({ access_token: "marzban-token" })
          },
          {
            ok: true,
            status: 201,
            json: async () => ({ username: "all-mode-user" })
          },
          {
            ok: true,
            status: 200,
            json: async () => ({ access_token: "marzban-token" })
          },
          {
            ok: true,
            status: 200,
            json: async () => ({ username: "all-mode-user", subscription_url: "https://marzban.example.com/sub/all-mode-user" })
          }
        ],
        calls,
        async () => {
          const created = await callApi(handleApi, {
            method: "POST",
            pathname: "/api/admin/users",
            session: login.session,
            body: {
              username: "all-mode-user",
              panelId: panel.id,
              ownerAdminId: owner.id,
              limitBytes: 100,
              usedBytes: 0,
              inboundIds: ["vless:WS TLS:10002", "vmess:VMESS TLS:10001"],
              inboundId: "vless:WS TLS:10002",
              inboundMode: "all",
              expiresAt: "2030-01-02T03:04:05.000Z"
            }
          });

          assert.equal(created.username, "all-mode-user");
          assert.equal(created.inboundMode, "all");
          assert.equal(created.inboundId, "vless:WS TLS:10002");
          assert.deepEqual(created.inboundIds, ["vless:WS TLS:10002", "vmess:VMESS TLS:10001"]);
        }
      );
      assert.equal(calls.length, 4);
    }
  );
});

test("marzban adapter updateUser sends the verified update payload", async () => {
  const calls = [];
  await withMockFetch(
    [
      {
        ok: true,
        status: 200,
        json: async () => ({ access_token: "marzban-token" })
      },
      {
        ok: true,
        status: 200,
        json: async () => ({ id: 42, username: "alice", status: "disabled" })
      }
    ],
    calls,
    async () => {
      const result = await marzbanAdapter.updateUser(
        {
          url: "https://marzban.example.com/",
          username: "admin",
          password: "secret"
        },
        {
          username: "alice",
          limitBytes: 1234,
          expiresAt: "2030-01-02T03:04:05.000Z",
          inboundIds: ["vless:WS TLS:10002", "vmess:VMESS TLS:10001"],
          active: true,
          flow: "xtls-rprx-vision"
        },
        {
          inboundIds: ["vless:WS TLS:10002", "vmess:VMESS TLS:10001"],
          expiresAt: "2030-01-02T03:04:05.000Z",
          flow: "xtls-rprx-vision",
          active: false
        }
      );

      assert.equal(result.id, 42);
      assert.equal(result.username, "alice");
      assert.equal(result.status, "disabled");
      assert.equal(calls.length, 2);
      assert.equal(calls[0].url, "https://marzban.example.com/api/admin/token");
      assert.equal(calls[1].url, "https://marzban.example.com/api/user/alice");
      assert.equal(calls[1].options.method, "PUT");
      assert.equal(calls[1].options.headers.authorization, "Bearer marzban-token");
      assert.equal(calls[1].options.headers["content-type"], "application/json");
      assert.deepEqual(JSON.parse(calls[1].options.body), {
        username: "alice",
        status: "disabled",
        expire: 1893553445,
        data_limit: 1234,
        data_limit_reset_strategy: "no_reset",
        inbounds: {
          vless: ["WS TLS"],
          vmess: ["VMESS TLS"]
        },
        proxies: {
          vless: {},
          vmess: {}
        },
        note: "",
        on_hold_expire_duration: 0,
        on_hold_timeout: null,
        next_plan: {
          data_limit: 0,
          expire: 0,
          add_remaining_traffic: false,
          fire_on_either: true
        }
      });
    }
  );
});

test("marzban createUser fails clearly on remote errors", async () => {
  await withMockFetch(
    [
      {
        ok: true,
        status: 200,
        json: async () => ({ access_token: "marzban-token" })
      },
      {
        ok: false,
        status: 400,
        json: async () => ({ detail: "bad request" })
      }
    ],
    [],
    async () => {
      await assert.rejects(
        marzbanAdapter.createUser(
          {
            url: "https://marzban.example.com",
            username: "admin",
            password: "secret"
          },
          {
            username: "alice",
            limitBytes: 100,
            inboundId: "vless:WS TLS:10002"
          }
        ),
        (error) => {
          assert.equal(error.status, 400);
          assert.match(error.message, /Marzban create user failed with HTTP 400/);
          return true;
        }
      );
    }
  );
});

test("marzban createUser rejects empty selected inbounds before remote calls", async () => {
  const calls = [];
  await withMockFetch([], calls, async () => {
    await assert.rejects(
      marzbanAdapter.createUser(
        {
          url: "https://marzban.example.com",
          username: "admin",
          password: "secret"
        },
        {
          username: "alice",
          limitBytes: 100,
          inboundIds: []
        }
      ),
      (error) => {
        assert.equal(error.status, 400);
        assert.match(error.message, /At least one inbound must be selected for Marzban/i);
        return true;
      }
    );
  });
  assert.equal(calls.length, 0);
});

test("marzban deleteUser fails clearly on remote errors", async () => {
  await withMockFetch(
    [
      {
        ok: true,
        status: 200,
        json: async () => ({ access_token: "marzban-token" })
      },
      {
        ok: false,
        status: 500,
        json: async () => ({ detail: "boom" })
      }
    ],
    [],
    async () => {
      await assert.rejects(
        marzbanAdapter.deleteUser(
          {
            url: "https://marzban.example.com",
            username: "admin",
            password: "secret"
          },
          {
            username: "alice"
          }
        ),
        (error) => {
          assert.equal(error.status, 500);
          assert.match(error.message, /Marzban delete user failed with HTTP 500/);
          return true;
        }
      );
    }
  );
});

test("marzban buildClient normalizes the base URL", async () => {
  const clientA = buildClient({
    url: "https://marzban.example.com/",
    username: "admin",
    password: "secret"
  });
  const clientB = buildClient({
    url: "https://marzban.example.com",
    username: "admin",
    password: "secret"
  });
  assert.equal(clientA.baseUrl, "https://marzban.example.com");
  assert.equal(clientB.baseUrl, "https://marzban.example.com");
  assert.equal(clientA.authUrl, "https://marzban.example.com/api/admin/token");
  assert.equal(clientA.inboundsUrl, "https://marzban.example.com/api/inbounds");
});

test("marzban authenticate and listInbounds use the verified endpoint pattern", async () => {
  const calls = [];
  await withMockFetch([
    {
      ok: true,
      status: 200,
      json: async () => ({ access_token: "marzban-token" })
    },
    {
      ok: true,
      status: 200,
      json: async () => ([
        { id: 1, remark: "Inbound A", protocol: "vless", enabled: true },
        { uuid: "uuid-2", name: "Inbound B", streamSettings: { network: "tcp" }, enabled: false }
      ])
    }
  ], calls, async () => {
    const inbounds = await marzbanAdapter.listInbounds({
      url: "https://marzban.example.com/",
      username: "admin",
      password: "secret"
    });
      assert.deepEqual(inbounds, [
        { id: "1", label: "Inbound A", protocol: "vless", network: "", tls: "", port: null, enabled: true },
        { id: "Inbound B", label: "Inbound B", protocol: "", network: "tcp", tls: "", port: null, enabled: false }
      ]);
  });

  assert.equal(calls.length, 2);
  assert.equal(calls[0].url, "https://marzban.example.com/api/admin/token");
  assert.equal(calls[0].options.method, "POST");
  assert.equal(calls[0].options.headers["content-type"], "application/x-www-form-urlencoded");
  assert.equal(calls[0].options.body instanceof URLSearchParams, true);
  assert.equal(calls[0].options.body.get("username"), "admin");
  assert.equal(calls[0].options.body.get("password"), "secret");
  assert.equal(calls[1].url, "https://marzban.example.com/api/inbounds");
  assert.equal(calls[1].options.headers.authorization, "Bearer marzban-token");
});

test("marzban listInbounds flattens grouped protocol responses", async () => {
  const calls = [];
  await withMockFetch([
    {
      ok: true,
      status: 200,
      json: async () => ({ access_token: "marzban-token" })
    },
    {
      ok: true,
      status: 200,
      json: async () => ({
        vless: [
          { tag: "Falkenstein VLESS WS TLS", protocol: "vless", network: "ws", tls: "tls", port: 10002 }
        ],
        vmess: [
          { tag: "Falkenstein VMess WS TLS", protocol: "vmess", network: "ws", tls: "tls", port: 10001 }
        ]
      })
    }
  ], calls, async () => {
    const inbounds = await marzbanAdapter.listInbounds({
      url: "https://marzban.example.com",
      username: "admin",
      password: "secret"
    });
    assert.deepEqual(inbounds, [
      {
        id: "vless:Falkenstein VLESS WS TLS:10002",
        label: "Falkenstein VLESS WS TLS",
        protocol: "vless",
        network: "ws",
        tls: "tls",
        port: 10002,
        enabled: true
      },
      {
        id: "vmess:Falkenstein VMess WS TLS:10001",
        label: "Falkenstein VMess WS TLS",
        protocol: "vmess",
        network: "ws",
        tls: "tls",
        port: 10001,
        enabled: true
      }
    ]);
    for (const inbound of inbounds) {
      assert.equal("token" in inbound, false);
      assert.equal("credentials" in inbound, false);
      assert.equal("secret" in inbound, false);
    }
  });

  assert.equal(calls[0].url, "https://marzban.example.com/api/admin/token");
  assert.equal(calls[1].url, "https://marzban.example.com/api/inbounds");
});

test("superadmin can fetch normalized marzban inbounds through the api", async () => {
  const calls = [];
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
          name: "Marzban Panel",
          type: "marzban",
          url: "https://marzban.example.com/",
          username: "marzban-admin",
          secret: "marzban-pass"
        }
      });
      await withMockFetch([
        {
          ok: true,
          status: 200,
          json: async () => ({ access_token: "marzban-token" })
        },
        {
          ok: true,
          status: 200,
          json: async () => ({
            vless: [
              { tag: "WS TLS", protocol: "vless", network: "ws", tls: "tls", port: 10002 }
            ]
          })
        }
      ], calls, async () => {
        const res = await callApi(handleApi, {
          method: "GET",
          pathname: `/api/superadmin/panels/${panel.id}/inbounds`,
          session: login.session
        });
        assert.deepEqual(res, [
          {
            id: "vless:WS TLS:10002",
            label: "WS TLS",
            protocol: "vless",
            network: "ws",
            tls: "tls",
            port: 10002,
            enabled: true
          }
        ]);
        for (const inbound of res) {
          assert.equal("username" in inbound, false);
          assert.equal("password" in inbound, false);
          assert.equal("secret" in inbound, false);
          assert.equal("apiKey" in inbound, false);
          assert.equal("token" in inbound, false);
          assert.equal("credentials" in inbound, false);
        }
      });
    }
  );

  assert.equal(calls[0].url, "https://marzban.example.com/api/admin/token");
  assert.equal(calls[1].url, "https://marzban.example.com/api/inbounds");
});

test("reseller can load inbounds for an assigned marzban panel", async () => {
  const calls = [];
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
          name: "Marzban Panel",
          type: "marzban",
          url: "https://marzban.example.com/",
          username: "marzban-admin",
          secret: "marzban-pass"
        }
      });
      const reseller = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/superadmin/admins",
        session: login.session,
        body: {
          username: "reseller-assigned-endpoint",
          password: "admin-pass",
          role: "admin",
          panelId: panel.id,
          trafficLimitBytes: 1000
        }
      });
      const resellerLogin = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/auth/login",
        body: { username: reseller.username, password: "admin-pass" }
      });
      await withMockFetch(
        [
          {
            ok: true,
            status: 200,
            json: async () => ({ access_token: "marzban-token" })
          },
          {
            ok: true,
            status: 200,
            json: async () => ({
              vless: [
                { tag: "VLESS 443", protocol: "vless", network: "ws", tls: "tls", port: 443 }
              ]
            })
          }
        ],
        calls,
        async () => {
          const inbounds = await callApi(handleApi, {
            method: "GET",
            pathname: `/api/admin/panels/${panel.id}/inbounds`,
            session: resellerLogin.session
          });
          assert.deepEqual(inbounds, [
            {
              id: "vless:VLESS 443:443",
              label: "VLESS 443",
              protocol: "vless",
              network: "ws",
              tls: "tls",
              port: 443,
              enabled: true
            }
          ]);
        }
      );
    }
  );
  assert.equal(calls[0].url, "https://marzban.example.com/api/admin/token");
  assert.equal(calls[1].url, "https://marzban.example.com/api/inbounds");
});

test("reseller cannot load inbounds for an unassigned marzban panel", async () => {
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
      const assigned = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/superadmin/panels",
        session: login.session,
        body: {
          name: "Assigned Panel",
          type: "marzban",
          url: "https://assigned.example.com",
          username: "admin",
          secret: "secret"
        }
      });
      const other = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/superadmin/panels",
        session: login.session,
        body: {
          name: "Other Panel",
          type: "marzban",
          url: "https://other.example.com",
          username: "admin",
          secret: "secret"
        }
      });
      const reseller = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/superadmin/admins",
        session: login.session,
        body: {
          username: "reseller-unassigned-endpoint",
          password: "admin-pass",
          role: "admin",
          panelId: assigned.id,
          trafficLimitBytes: 1000
        }
      });
      const resellerLogin = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/auth/login",
        body: { username: reseller.username, password: "admin-pass" }
      });
      const res = await callApiWithOutcome(handleApi, {
        method: "GET",
        pathname: `/api/admin/panels/${other.id}/inbounds`,
        session: resellerLogin.session
      });
      assert.ok([403, 404].includes(res.statusCode));
      assert.match(res.json.error, /Insufficient permissions|Panel not found/i);
    }
  );
});

test("superadmin can load inbounds through the admin-scoped endpoint", async () => {
  const calls = [];
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
          name: "Marzban Panel",
          type: "marzban",
          url: "https://marzban.example.com/",
          username: "admin",
          secret: "secret"
        }
      });
      await withMockFetch(
        [
          {
            ok: true,
            status: 200,
            json: async () => ({ access_token: "marzban-token" })
          },
          {
            ok: true,
            status: 200,
            json: async () => ([{ tag: "WS TLS", protocol: "vless", network: "ws", tls: "tls", port: 10002 }])
          }
        ],
        calls,
        async () => {
          const res = await callApi(handleApi, {
            method: "GET",
            pathname: `/api/admin/panels/${panel.id}/inbounds`,
            session: login.session
          });
          assert.equal(res[0].id, "vless:WS TLS:10002");
        }
      );
      assert.equal(calls[0].url, "https://marzban.example.com/api/admin/token");
      assert.equal(calls[1].url, "https://marzban.example.com/api/inbounds");
    }
  );
});

test("superadmin can test marzban panel connection successfully", async () => {
  const calls = [];
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
          name: "Marzban Panel",
          type: "marzban",
          url: "https://marzban.example.com/",
          username: "admin",
          secret: "secret"
        }
      });
      await withMockFetch(
        [
          {
            ok: true,
            status: 200,
            json: async () => ({ access_token: "marzban-token" })
          },
          {
            ok: true,
            status: 200,
            json: async () => ([
              { tag: "WS TLS", protocol: "vless", network: "ws", tls: "tls", port: 10002 },
              { tag: "VMess WS TLS", protocol: "vmess", network: "ws", tls: "tls", port: 10001 }
            ])
          }
        ],
        calls,
        async () => {
          const res = await callApi(handleApi, {
            method: "POST",
            pathname: `/api/superadmin/panels/${panel.id}/test-connection`,
            session: login.session
          });
          assert.equal(res.ok, true);
          assert.equal(res.panelId, panel.id);
          assert.equal(res.type, "marzban");
          assert.equal(res.inboundCount, 2);
          assert.match(res.message, /Connection OK: 2 inbounds/);
          assert.match(res.checkedAt, /^\d{4}-\d{2}-\d{2}T/);
          assert.equal("secret" in res, false);
          assert.equal("apiKey" in res, false);
          assert.equal("token" in res, false);
          assert.equal("password" in res, false);
        }
      );
      assert.equal(calls[0].url, "https://marzban.example.com/api/admin/token");
      assert.equal(calls[1].url, "https://marzban.example.com/api/inbounds");
    }
  );
});

test("reseller cannot test panel connection", async () => {
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
          name: "Marzban Panel",
          type: "marzban",
          url: "https://marzban.example.com/",
          username: "admin",
          secret: "secret"
        }
      });
      const reseller = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/superadmin/admins",
        session: login.session,
        body: {
          username: "reseller-connection-test",
          password: "admin-pass",
          role: "admin",
          panelId: panel.id,
          trafficLimitBytes: 1000
        }
      });
      const resellerLogin = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/auth/login",
        body: { username: reseller.username, password: "admin-pass" }
      });
      const res = await callApiWithOutcome(handleApi, {
        method: "POST",
        pathname: `/api/superadmin/panels/${panel.id}/test-connection`,
        session: resellerLogin.session
      });
      assert.equal(res.statusCode, 403);
      assert.match(res.json.error, /Insufficient permissions/);
    }
  );
});

test("missing panel returns 404 from test connection", async () => {
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
        pathname: "/api/superadmin/panels/pan_missing/test-connection",
        session: login.session
      });
      assert.equal(res.statusCode, 404);
      assert.match(res.json.error, /Panel not found/);
    }
  );
});

test("marzban auth failure returns a clear connection test error", async () => {
  const calls = [];
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
          name: "Marzban Panel",
          type: "marzban",
          url: "https://marzban.example.com/",
          username: "admin",
          secret: "secret"
        }
      });
      await withMockFetch(
        [
          {
            ok: false,
            status: 401,
            json: async () => ({ detail: "Unauthorized" })
          }
        ],
        calls,
        async () => {
          const res = await callApiWithOutcome(handleApi, {
            method: "POST",
            pathname: `/api/superadmin/panels/${panel.id}/test-connection`,
            session: login.session
          });
          assert.equal(res.statusCode, 401);
          assert.match(res.json.error, /Marzban token request failed with HTTP 401/);
        }
      );
    }
  );
});

test("marzban inbounds failure returns a clear connection test error", async () => {
  const calls = [];
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
          name: "Marzban Panel",
          type: "marzban",
          url: "https://marzban.example.com/",
          username: "admin",
          secret: "secret"
        }
      });
      await withMockFetch(
        [
          {
            ok: true,
            status: 200,
            json: async () => ({ access_token: "marzban-token" })
          },
          {
            ok: false,
            status: 502,
            json: async () => ({ detail: "Bad Gateway" })
          }
        ],
        calls,
        async () => {
          const res = await callApiWithOutcome(handleApi, {
            method: "POST",
            pathname: `/api/superadmin/panels/${panel.id}/test-connection`,
            session: login.session
          });
          assert.equal(res.statusCode, 502);
          assert.match(res.json.error, /Marzban inbounds request failed with HTTP 502/);
        }
      );
    }
  );
});

test("reseller create vpn account flow works without inboundIds", async () => {
  const calls = [];
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
          name: "Marzban Panel",
          type: "marzban",
          url: "https://marzban.example.com/",
          username: "admin",
          secret: "secret"
        }
      });
      const reseller = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/superadmin/admins",
        session: login.session,
        body: {
          username: "reseller-create-endpoint",
          password: "admin-pass",
          role: "admin",
          panelId: panel.id,
          trafficLimitBytes: 1000,
          validUntil: "2030-01-02T23:59:59.000Z"
        }
      });
      const resellerLogin = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/auth/login",
        body: { username: reseller.username, password: "admin-pass" }
      });

      await withMockFetch(
        [
          {
            ok: true,
            status: 200,
            json: async () => ({ access_token: "marzban-token" })
          },
          {
            ok: true,
            status: 200,
            json: async () => ({
              vless: [
                { tag: "WS TLS", protocol: "vless", network: "ws", tls: "tls", port: 10002 }
              ]
            })
          },
          {
            ok: true,
            status: 200,
            json: async () => ({ access_token: "marzban-token" })
          },
          {
            ok: true,
            status: 201,
            json: async () => ({ username: "client-ok" })
          }
        ],
        calls,
        async () => {
          const created = await callApi(handleApi, {
            method: "POST",
            pathname: "/api/admin/users",
            session: resellerLogin.session,
            body: {
              username: "client-ok",
              limitBytes: 100,
              expiresAt: "2030-01-02T23:59:59.000Z",
              note: "default inbound policy"
            }
          });
          assert.equal(created.username, "client-ok");
          assert.equal(created.inboundMode, "all");
          assert.deepEqual(created.inboundIds, ["vless:WS TLS:10002"]);
          assert.equal(created.subscriptionUrl, null);
        }
      );
      assert.equal(calls[0].url, "https://marzban.example.com/api/admin/token");
      assert.equal(calls[1].url, "https://marzban.example.com/api/inbounds");
      assert.equal(calls[2].url, "https://marzban.example.com/api/admin/token");
      assert.equal(calls[3].url, "https://marzban.example.com/api/user");
    }
  );
});

test("marzban-backed user creation stores subscriptionUrl and keeps it scoped to the owner", async () => {
  const calls = [];
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
          name: "Marzban Panel",
          type: "marzban",
          url: "https://marzban.example.com/",
          username: "admin",
          secret: "secret"
        }
      });
      const ownerA = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/superadmin/admins",
        session: login.session,
        body: {
          username: "sub-owner-a",
          password: "admin-pass-a",
          role: "admin",
          panelId: panel.id,
          trafficLimitBytes: 1000
        }
      });
      const ownerB = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/superadmin/admins",
        session: login.session,
        body: {
          username: "sub-owner-b",
          password: "admin-pass-b",
          role: "admin",
          panelId: panel.id,
          trafficLimitBytes: 1000
        }
      });
      const ownerALogin = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/auth/login",
        body: { username: ownerA.username, password: "admin-pass-a" }
      });
      const ownerBLogin = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/auth/login",
        body: { username: ownerB.username, password: "admin-pass-b" }
      });

      await withMockFetch(
        [
          {
            ok: true,
            status: 200,
            json: async () => ({ access_token: "marzban-token" })
          },
          {
            ok: true,
            status: 200,
            json: async () => ({
              vless: [
                { tag: "WS TLS", protocol: "vless", network: "ws", tls: "tls", port: 10002 }
              ]
            })
          },
          {
            ok: true,
            status: 200,
            json: async () => ({ access_token: "marzban-token" })
          },
          {
            ok: true,
            status: 201,
            json: async () => ({
              username: "sub-client-a",
              subscription_url: "https://marzban.example.com/sub/sub-client-a"
            })
          },
          {
            ok: true,
            status: 200,
            json: async () => ({ access_token: "marzban-token" })
          },
          {
            ok: true,
            status: 200,
            json: async () => ({
              vless: [
                { tag: "WS TLS", protocol: "vless", network: "ws", tls: "tls", port: 10002 }
              ]
            })
          },
          {
            ok: true,
            status: 200,
            json: async () => ({ access_token: "marzban-token" })
          },
          {
            ok: true,
            status: 201,
            json: async () => ({ username: "sub-client-b" })
          }
        ],
        calls,
        async () => {
          const created = await callApi(handleApi, {
            method: "POST",
            pathname: "/api/admin/users",
            session: ownerALogin.session,
            body: {
              username: "sub-client-a",
              limitBytes: 100,
              expiresAt: "2030-01-02T23:59:59.000Z",
              note: "with link"
            }
          });
          assert.equal(created.subscriptionUrl, "https://marzban.example.com/sub/sub-client-a");
          assert.equal(created.ownerUsername, ownerA.username);

          const ownerAUsers = await callApi(handleApi, {
            method: "GET",
            pathname: "/api/admin/users",
            session: ownerALogin.session
          });
          const storedA = ownerAUsers.find((user) => user.username === "sub-client-a");
          assert.equal(storedA.subscriptionUrl, "https://marzban.example.com/sub/sub-client-a");
          assert.equal(storedA.ownerUsername, ownerA.username);

          await callApi(handleApi, {
            method: "POST",
            pathname: "/api/admin/users",
            session: ownerBLogin.session,
            body: {
              username: "sub-client-b",
              limitBytes: 100,
              expiresAt: "2030-01-02T23:59:59.000Z",
              note: "no link"
            }
          });

          const ownerBUsers = await callApi(handleApi, {
            method: "GET",
            pathname: "/api/admin/users",
            session: ownerBLogin.session
          });
          assert.equal(ownerBUsers.some((user) => user.username === "sub-client-a"), false);
        }
      );
    }
  );
});

test("reseller create fails clearly when no panel is assigned", async () => {
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
      const reseller = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/superadmin/admins",
        session: login.session,
        body: {
          username: "reseller-no-panel",
          password: "admin-pass",
          role: "admin",
          trafficLimitBytes: 1000
        }
      });
      const resellerLogin = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/auth/login",
        body: { username: reseller.username, password: "admin-pass" }
      });
      const res = await callApiWithOutcome(handleApi, {
        method: "POST",
        pathname: "/api/admin/users",
        session: resellerLogin.session,
        body: {
          username: "client-missing-panel",
          limitBytes: 100,
          expiresAt: "2030-01-02T23:59:59.000Z",
          note: "no panel"
        }
      });
      assert.equal(res.statusCode, 400);
      assert.match(res.json.error, /No panel assigned to this reseller\./i);
    }
  );
});

test("reseller cannot override panelId manually on create", async () => {
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
          name: "Assigned Panel",
          type: "marzban",
          url: "https://assigned.example.com",
          username: "admin",
          secret: "secret"
        }
      });
      const other = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/superadmin/panels",
        session: login.session,
        body: {
          name: "Other Panel",
          type: "marzban",
          url: "https://other.example.com",
          username: "admin",
          secret: "secret"
        }
      });
      const reseller = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/superadmin/admins",
        session: login.session,
        body: {
          username: "reseller-override",
          password: "admin-pass",
          role: "admin",
          panelId: panel.id,
          trafficLimitBytes: 1000
        }
      });
      const resellerLogin = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/auth/login",
        body: { username: reseller.username, password: "admin-pass" }
      });
      const res = await callApiWithOutcome(handleApi, {
        method: "POST",
        pathname: "/api/admin/users",
        session: resellerLogin.session,
        body: {
          username: "client-override",
          panelId: other.id,
          limitBytes: 100,
          expiresAt: "2030-01-02T23:59:59.000Z"
        }
      });
      assert.equal(res.statusCode, 400);
      assert.match(res.json.error, /Cannot set panelId/i);
    }
  );
});

test("superadmin create still requires panelId", async () => {
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
        pathname: "/api/admin/users",
        session: login.session,
        body: {
          username: "super-client",
          limitBytes: 100,
          expiresAt: "2030-01-02T23:59:59.000Z"
        }
      });
      assert.equal(res.statusCode, 400);
      assert.match(res.json.error, /Missing required field: panelId/i);
    }
  );
});

test("superadmin admins API returns reseller metrics and role distinction", async () => {
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
          name: "Metrics Panel",
          type: "tx-ui",
          url: "https://metrics.example.com"
        }
      });
      const reseller = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/superadmin/admins",
        session: login.session,
        body: {
          username: "metrics-reseller",
          password: "reseller-pass",
          role: "admin",
          panelId: panel.id,
          trafficLimitBytes: 1000,
          validUntil: "2035-01-02T23:59:59.000Z"
        }
      });
      await callApi(handleApi, {
        method: "POST",
        pathname: "/api/admin/users",
        session: login.session,
        body: {
          username: "metrics-user-a",
          panelId: panel.id,
          ownerAdminId: reseller.id,
          limitBytes: 100,
          expiresAt: "2030-01-02T23:59:59.000Z",
          note: "a"
        }
      });
      await callApi(handleApi, {
        method: "POST",
        pathname: "/api/admin/users",
        session: login.session,
        body: {
          username: "metrics-user-b",
          panelId: panel.id,
          ownerAdminId: reseller.id,
          limitBytes: 150,
          expiresAt: "2030-01-02T23:59:59.000Z",
          note: "b"
        }
      });

      const admins = await callApi(handleApi, {
        method: "GET",
        pathname: "/api/superadmin/admins",
        session: login.session
      });
      const resellerRow = admins.find((admin) => admin.username === reseller.username);
      assert.equal(resellerRow.role, "admin");
      assert.equal(resellerRow.userCount, 2);
      assert.equal(resellerRow.allocatedTrafficBytes, 250);
      assert.equal(resellerRow.usedTrafficBytes, 0);
      assert.equal(resellerRow.remainingTrafficBytes, 750);
      assert.equal(resellerRow.trafficLimitBytes, 1000);
      assert.equal(admins.some((admin) => admin.role === "superadmin"), true);
    }
  );
});

test("superadmin can edit reseller quota, panel, validity, and return policies", async () => {
  await withTempEnv(
    {
      AEGIS_ADMIN_USERNAME: "env-admin",
      AEGIS_ADMIN_PASSWORD: "env-pass",
      AEGIS_DATA_DIR: "./tmp-data",
      AEGIS_SESSION_SECRET: "test-secret"
    },
    async () => {
      const handleApi = await importApiFresh();
      const { store } = await import("../src/storage/store.js");
      const login = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/auth/login",
        body: { username: "env-admin", password: "env-pass" }
      });
      const panelA = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/superadmin/panels",
        session: login.session,
        body: { name: "Panel A", type: "tx-ui", url: "https://panel-a.example.com" }
      });
      const panelB = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/superadmin/panels",
        session: login.session,
        body: { name: "Panel B", type: "tx-ui", url: "https://panel-b.example.com" }
      });
      const reseller = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/superadmin/admins",
        session: login.session,
        body: {
          username: "editable-reseller",
          password: "reseller-pass",
          role: "admin",
          panelId: panelA.id,
          trafficLimitBytes: 1000,
          trafficRemainingBytes: 800,
          validUntil: "2035-01-02T23:59:59.000Z",
          deleteReturnTraffic: true,
          updateReturnTraffic: true
        }
      });

      const updated = await callApi(handleApi, {
        method: "PUT",
        pathname: `/api/superadmin/admins/${reseller.id}`,
        session: login.session,
        body: {
          username: reseller.username,
          panelId: panelB.id,
          trafficLimitBytes: 2000,
          trafficRemainingBytes: 1500,
          validUntil: "2035-02-03T23:59:59.000Z",
          active: false,
          deleteReturnTraffic: false,
          updateReturnTraffic: false,
          password: "new-pass"
        }
      });

      assert.equal(updated.panelId, panelB.id);
      assert.equal(updated.trafficLimitBytes, 2000);
      assert.equal(updated.trafficRemainingBytes, 1500);
      assert.equal(updated.validUntil, "2035-02-03T23:59:59.000Z");
      assert.equal(updated.active, false);
      assert.equal(updated.deleteReturnTraffic, false);
      assert.equal(updated.updateReturnTraffic, false);

      const stored = store.find("admins", reseller.id);
      assert.equal(stored.panelId, panelB.id);
      assert.equal(stored.trafficLimitBytes, 2000);
      assert.equal(stored.trafficRemainingBytes, 1500);
      assert.equal(stored.validUntil, "2035-02-03T23:59:59.000Z");
      assert.equal(verifyPassword("new-pass", stored.passwordHash), true);
    }
  );
});

test("empty reseller password preserves the existing credential", async () => {
  await withTempEnv(
    {
      AEGIS_ADMIN_USERNAME: "env-admin",
      AEGIS_ADMIN_PASSWORD: "env-pass",
      AEGIS_DATA_DIR: "./tmp-data",
      AEGIS_SESSION_SECRET: "test-secret"
    },
    async () => {
      const handleApi = await importApiFresh();
      const { store } = await import("../src/storage/store.js");
      const login = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/auth/login",
        body: { username: "env-admin", password: "env-pass" }
      });
      const panel = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/superadmin/panels",
        session: login.session,
        body: { name: "Password Panel", type: "tx-ui", url: "https://password.example.com" }
      });
      const reseller = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/superadmin/admins",
        session: login.session,
        body: {
          username: "password-preserve",
          password: "old-pass",
          role: "admin",
          panelId: panel.id,
          trafficLimitBytes: 1000
        }
      });
      const beforeHash = store.find("admins", reseller.id).passwordHash;

      await callApi(handleApi, {
        method: "PUT",
        pathname: `/api/superadmin/admins/${reseller.id}`,
        session: login.session,
        body: {
          username: reseller.username,
          panelId: panel.id,
          trafficLimitBytes: 1000,
          trafficRemainingBytes: 1000,
          validUntil: "2035-01-02T23:59:59.000Z",
          password: ""
        }
      });

      const stored = store.find("admins", reseller.id);
      assert.equal(stored.passwordHash, beforeHash);
      assert.equal(verifyPassword("old-pass", stored.passwordHash), true);
    }
  );
});

test("non-empty reseller password updates the stored credential", async () => {
  await withTempEnv(
    {
      AEGIS_ADMIN_USERNAME: "env-admin",
      AEGIS_ADMIN_PASSWORD: "env-pass",
      AEGIS_DATA_DIR: "./tmp-data",
      AEGIS_SESSION_SECRET: "test-secret"
    },
    async () => {
      const handleApi = await importApiFresh();
      const { store } = await import("../src/storage/store.js");
      const login = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/auth/login",
        body: { username: "env-admin", password: "env-pass" }
      });
      const panel = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/superadmin/panels",
        session: login.session,
        body: { name: "Password Update Panel", type: "tx-ui", url: "https://password-update.example.com" }
      });
      const reseller = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/superadmin/admins",
        session: login.session,
        body: {
          username: "password-update",
          password: "old-pass",
          role: "admin",
          panelId: panel.id,
          trafficLimitBytes: 1000
        }
      });

      await callApi(handleApi, {
        method: "PUT",
        pathname: `/api/superadmin/admins/${reseller.id}`,
        session: login.session,
        body: {
          username: reseller.username,
          panelId: panel.id,
          trafficLimitBytes: 1000,
          trafficRemainingBytes: 1000,
          validUntil: "2035-01-02T23:59:59.000Z",
          password: "new-pass"
        }
      });

      const stored = store.find("admins", reseller.id);
      assert.equal(verifyPassword("new-pass", stored.passwordHash), true);
      assert.equal(verifyPassword("old-pass", stored.passwordHash), false);
    }
  );
});

test("traffic limit below allocated user traffic is rejected for reseller edits", async () => {
  await withTempEnv(
    {
      AEGIS_ADMIN_USERNAME: "env-admin",
      AEGIS_ADMIN_PASSWORD: "env-pass",
      AEGIS_DATA_DIR: "./tmp-data",
      AEGIS_SESSION_SECRET: "test-secret"
    },
    async () => {
      const handleApi = await importApiFresh();
      const { store } = await import("../src/storage/store.js");
      const login = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/auth/login",
        body: { username: "env-admin", password: "env-pass" }
      });
      const panel = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/superadmin/panels",
        session: login.session,
        body: { name: "Quota Panel", type: "tx-ui", url: "https://quota.example.com" }
      });
      const reseller = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/superadmin/admins",
        session: login.session,
        body: {
          username: "quota-reseller",
          password: "reseller-pass",
          role: "admin",
          panelId: panel.id,
          trafficLimitBytes: 1000
        }
      });
      await callApi(handleApi, {
        method: "POST",
        pathname: "/api/admin/users",
        session: login.session,
        body: {
          username: "quota-user-a",
          panelId: panel.id,
          ownerAdminId: reseller.id,
          limitBytes: 100,
          expiresAt: "2030-01-02T23:59:59.000Z"
        }
      });
      await callApi(handleApi, {
        method: "POST",
        pathname: "/api/admin/users",
        session: login.session,
        body: {
          username: "quota-user-b",
          panelId: panel.id,
          ownerAdminId: reseller.id,
          limitBytes: 150,
          expiresAt: "2030-01-02T23:59:59.000Z"
        }
      });

      const res = await callApiWithOutcome(handleApi, {
        method: "PUT",
        pathname: `/api/superadmin/admins/${reseller.id}`,
        session: login.session,
        body: {
          username: reseller.username,
          panelId: panel.id,
          trafficLimitBytes: 200,
          trafficRemainingBytes: 200,
          validUntil: "2035-01-02T23:59:59.000Z"
        }
      });
      assert.equal(res.statusCode, 400);
      assert.match(res.json.error, /Traffic limit cannot be below allocated user traffic/i);
      const stored = store.find("admins", reseller.id);
      assert.equal(stored.trafficLimitBytes, 1000);
      assert.equal(stored.trafficRemainingBytes, 750);
    }
  );
});

test("non-superadmin cannot edit a reseller", async () => {
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
        body: { name: "Permissions Panel", type: "tx-ui", url: "https://permissions.example.com" }
      });
      const reseller = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/superadmin/admins",
        session: login.session,
        body: {
          username: "permissions-reseller",
          password: "reseller-pass",
          role: "admin",
          panelId: panel.id,
          trafficLimitBytes: 1000
        }
      });
      const resellerLogin = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/auth/login",
        body: { username: reseller.username, password: "reseller-pass" }
      });

      const res = await callApiWithOutcome(handleApi, {
        method: "PUT",
        pathname: `/api/superadmin/admins/${reseller.id}`,
        session: resellerLogin.session,
        body: {
          username: reseller.username,
          panelId: panel.id,
          trafficLimitBytes: 1000,
          trafficRemainingBytes: 1000,
          validUntil: "2035-01-02T23:59:59.000Z"
        }
      });
      assert.equal(res.statusCode, 403);
      assert.match(res.json.error, /Insufficient permissions/i);
    }
  );
});

test("missing panel returns 404 for inbounds", async () => {
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
        method: "GET",
        pathname: "/api/superadmin/panels/pan_missing/inbounds",
        session: login.session
      });
      assert.equal(res.statusCode, 404);
      assert.match(res.json.error, /Panel not found/i);
    }
  );
});

test("non-marzban panels fail clearly for real inbounds", async () => {
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
          name: "Tx Panel",
          type: "tx-ui",
          url: "https://tx.example.com"
        }
      });
      const res = await callApiWithOutcome(handleApi, {
        method: "GET",
        pathname: `/api/superadmin/panels/${panel.id}/inbounds`,
        session: login.session
      });
      assert.equal(res.statusCode, 501);
      assert.match(res.json.error, /Real inbounds are not available for this panel type yet/i);
    }
  );
});

test("marzban token and inbounds failures fail clearly", async () => {
  await withMockFetch([
    {
      ok: false,
      status: 401,
      json: async () => ({ detail: "invalid" })
    }
  ], [], async () => {
    await assert.rejects(
      marzbanAdapter.authenticate({
        authUrl: "https://marzban.example.com/api/admin/token",
        username: "admin",
        password: "secret"
      }),
      (error) => {
        assert.equal(error.status, 401);
        assert.match(error.message, /HTTP 401/);
        return true;
      }
    );
  });

  await withMockFetch([
    {
      ok: true,
      status: 200,
      json: async () => ({ access_token: "marzban-token" })
    },
    {
      ok: false,
      status: 500,
      json: async () => ({ detail: "boom" })
    }
  ], [], async () => {
    await assert.rejects(
      marzbanAdapter.listInbounds({
        url: "https://marzban.example.com",
        username: "admin",
        password: "secret"
      }),
      (error) => {
        assert.equal(error.status, 500);
        assert.match(error.message, /inbounds request failed/i);
        return true;
      }
    );
  });
});

test("marzban missing base URL or credentials fail clearly", async () => {
  await assert.rejects(
    marzbanAdapter.buildClient({ username: "admin", password: "secret" }),
    (error) => {
      assert.equal(error.status, 400);
      assert.match(error.message, /base URL is required/i);
      return true;
    }
  );
  await assert.rejects(
    marzbanAdapter.buildClient({ url: "https://marzban.example.com", username: "admin" }),
    (error) => {
      assert.equal(error.status, 400);
      assert.match(error.message, /username and password are required/i);
      return true;
    }
  );
});

test("marzban sync does not claim success before the adapter is implemented", async () => {
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
          name: "Marzban Panel",
          type: "marzban",
          url: "https://marzban.example.com"
        }
      });

      const res = await callApiWithOutcome(handleApi, {
        method: "POST",
        pathname: `/api/panels/${panel.id}/sync`,
        session: login.session
      });
      assert.equal(res.statusCode, 501);
      assert.match(res.json.error, /Marzban sync is not implemented yet/);
    }
  );
});

test("superadmin deleting a reseller cascades owned Marzban users and allows username reuse", async () => {
  const calls = [];
  await withTempEnv(
    {
      AEGIS_ADMIN_USERNAME: "env-admin",
      AEGIS_ADMIN_PASSWORD: "env-pass",
      AEGIS_DATA_DIR: "./tmp-data",
      AEGIS_SESSION_SECRET: "test-secret"
    },
    async () => {
      const handleApi = await importApiFresh();
      const { store } = await import("../src/storage/store.js");
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
          name: "Cascade Panel",
          type: "marzban",
          url: "https://cascade.example.com",
          subscriptionUrl: "https://cascade.example.com",
          username: "panel-user",
          secret: "panel-secret"
        }
      });
      const reseller = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/superadmin/admins",
        session: login.session,
        body: {
          username: "cascade-reseller",
          password: "reseller-pass",
          role: "admin",
          panelId: panel.id,
          trafficLimitBytes: 1000
        }
      });

      await withMockFetch(
        [
          { ok: true, status: 200, json: async () => ({ access_token: "marzban-token" }) },
          { ok: true, status: 201, json: async () => ({ username: "cascade-a" }) },
          { ok: true, status: 200, json: async () => ({ access_token: "marzban-token" }) },
          { ok: true, status: 201, json: async () => ({ username: "cascade-b" }) },
          { ok: true, status: 200, json: async () => ({ access_token: "marzban-token" }) },
          { ok: true, status: 204, json: async () => ({}) },
          { ok: true, status: 200, json: async () => ({ access_token: "marzban-token" }) },
          { ok: true, status: 204, json: async () => ({}) },
          { ok: true, status: 200, json: async () => ({ access_token: "marzban-token" }) },
          { ok: true, status: 201, json: async () => ({ username: "cascade-a" }) }
        ],
        calls,
        async () => {
          await callApi(handleApi, {
            method: "POST",
            pathname: "/api/admin/users",
            session: login.session,
            body: {
              username: "cascade-a",
              panelId: panel.id,
              ownerAdminId: reseller.id,
              limitBytes: 100,
              expiresAt: "2030-01-02T23:59:59.000Z",
              note: "first",
              inboundIds: ["vless:Cascade WS TLS:10002"]
            }
          });
          await callApi(handleApi, {
            method: "POST",
            pathname: "/api/admin/users",
            session: login.session,
            body: {
              username: "cascade-b",
              panelId: panel.id,
              ownerAdminId: reseller.id,
              limitBytes: 100,
              expiresAt: "2030-01-02T23:59:59.000Z",
              note: "second",
              inboundIds: ["vless:Cascade WS TLS:10002"]
            }
          });

          const deleteReseller = await callApi(handleApi, {
            method: "DELETE",
            pathname: `/api/superadmin/admins/${reseller.id}`,
            session: login.session
          });
          assert.equal(deleteReseller.ok, true);

          assert.equal(store.find("admins", reseller.id), undefined);
          assert.equal(store.list("users").some((user) => user.ownerAdminId === reseller.id), false);

          const recreated = await callApi(handleApi, {
            method: "POST",
            pathname: "/api/admin/users",
            session: login.session,
            body: {
              username: "cascade-a",
              panelId: panel.id,
              ownerAdminId: login.admin.id,
              limitBytes: 100,
              expiresAt: "2030-01-02T23:59:59.000Z",
              inboundIds: ["vless:Cascade WS TLS:10002"]
            }
          });
          assert.equal(recreated.username, "cascade-a");
        }
      );
    }
  );
  assert.equal(calls.filter((call) => call.options?.method === "DELETE").length, 2);
});

test("remote 404 is treated as success when cascading reseller users", async () => {
  await withTempEnv(
    {
      AEGIS_ADMIN_USERNAME: "env-admin",
      AEGIS_ADMIN_PASSWORD: "env-pass",
      AEGIS_DATA_DIR: "./tmp-data",
      AEGIS_SESSION_SECRET: "test-secret"
    },
    async () => {
      const handleApi = await importApiFresh();
      const { store } = await import("../src/storage/store.js");
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
          name: "Missing User Panel",
          type: "marzban",
          url: "https://missing-user.example.com",
          subscriptionUrl: "https://missing-user.example.com",
          username: "panel-user",
          secret: "panel-secret"
        }
      });
      const reseller = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/superadmin/admins",
        session: login.session,
        body: {
          username: "missing-user-reseller",
          password: "reseller-pass",
          role: "admin",
          panelId: panel.id,
          trafficLimitBytes: 1000
        }
      });

      await withMockFetch(
        [
          { ok: true, status: 200, json: async () => ({ access_token: "marzban-token" }) },
          { ok: true, status: 201, json: async () => ({ username: "missing-user" }) },
          { ok: true, status: 200, json: async () => ({ access_token: "marzban-token" }) },
          { ok: false, status: 404, json: async () => ({ detail: "missing" }) }
        ],
        [],
        async () => {
          await callApi(handleApi, {
            method: "POST",
            pathname: "/api/admin/users",
            session: login.session,
            body: {
              username: "missing-user",
              panelId: panel.id,
              ownerAdminId: reseller.id,
              limitBytes: 100,
              expiresAt: "2030-01-02T23:59:59.000Z",
              note: "missing",
              inboundIds: ["vless:Missing WS TLS:10002"]
            }
          });

          const deleted = await callApi(handleApi, {
            method: "DELETE",
            pathname: `/api/superadmin/admins/${reseller.id}`,
            session: login.session
          });
          assert.equal(deleted.ok, true);
          assert.equal(store.find("admins", reseller.id), undefined);
          assert.equal(store.list("users").some((user) => user.username === "missing-user"), false);
        }
      );
    }
  );
});

test("remote delete failure blocks reseller deletion and preserves local users", async () => {
  await withTempEnv(
    {
      AEGIS_ADMIN_USERNAME: "env-admin",
      AEGIS_ADMIN_PASSWORD: "env-pass",
      AEGIS_DATA_DIR: "./tmp-data",
      AEGIS_SESSION_SECRET: "test-secret"
    },
    async () => {
      const handleApi = await importApiFresh();
      const { store } = await import("../src/storage/store.js");
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
          name: "Fail Delete Panel",
          type: "marzban",
          url: "https://fail-delete.example.com",
          subscriptionUrl: "https://fail-delete.example.com",
          username: "panel-user",
          secret: "panel-secret"
        }
      });
      const reseller = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/superadmin/admins",
        session: login.session,
        body: {
          username: "fail-delete-reseller",
          password: "reseller-pass",
          role: "admin",
          panelId: panel.id,
          trafficLimitBytes: 1000
        }
      });

      await withMockFetch(
        [
          { ok: true, status: 200, json: async () => ({ access_token: "marzban-token" }) },
          { ok: true, status: 201, json: async () => ({ username: "fail-delete-user" }) },
          { ok: true, status: 200, json: async () => ({ access_token: "marzban-token" }) },
          { ok: false, status: 500, json: async () => ({ detail: "boom" }) }
        ],
        [],
        async () => {
          await callApi(handleApi, {
            method: "POST",
            pathname: "/api/admin/users",
            session: login.session,
            body: {
              username: "fail-delete-user",
              panelId: panel.id,
              ownerAdminId: reseller.id,
              limitBytes: 100,
              expiresAt: "2030-01-02T23:59:59.000Z",
              note: "keep",
              inboundIds: ["vless:Fail WS TLS:10002"]
            }
          });

          const blocked = await callApiWithOutcome(handleApi, {
            method: "DELETE",
            pathname: `/api/superadmin/admins/${reseller.id}`,
            session: login.session
          });
          assert.equal(blocked.statusCode, 502);
          assert.match(blocked.json.error, /Cannot delete reseller because one or more remote users could not be deleted/i);
          assert.ok(store.find("admins", reseller.id));
          assert.equal(store.list("users").some((user) => user.username === "fail-delete-user"), true);
        }
      );
    }
  );
});

test("superadmin users api exposes owner usernames and orphaned users are marked missing", async () => {
  await withTempEnv(
    {
      AEGIS_ADMIN_USERNAME: "env-admin",
      AEGIS_ADMIN_PASSWORD: "env-pass",
      AEGIS_DATA_DIR: "./tmp-data",
      AEGIS_SESSION_SECRET: "test-secret"
    },
    async () => {
      const handleApi = await importApiFresh();
      const { store } = await import("../src/storage/store.js");
      const login = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/auth/login",
        body: { username: "env-admin", password: "env-pass" }
      });
      const owner = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/superadmin/admins",
        session: login.session,
        body: {
          username: "owner-visible",
          password: "owner-pass",
          role: "admin",
          trafficLimitBytes: 1000
        }
      });
      const orphanOwner = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/superadmin/admins",
        session: login.session,
        body: {
          username: "orphan-owner",
          password: "orphan-pass",
          role: "admin",
          trafficLimitBytes: 1000
        }
      });
      const panel = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/superadmin/panels",
        session: login.session,
        body: {
          name: "Visibility Panel",
          type: "tx-ui",
          url: "https://visibility.example.com"
        }
      });
      const ownerUser = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/admin/users",
        session: login.session,
        body: {
          username: "visible-user",
          panelId: panel.id,
          ownerAdminId: owner.id,
          limitBytes: 10,
          expiresAt: "2030-01-02T23:59:59.000Z",
          note: "owner visible"
        }
      });
      assert.equal(ownerUser.ownerUsername, owner.username);

      const orphanUserRecord = store.list("users").find((user) => user.username === "visible-user");
      store.update("users", orphanUserRecord.id, { ownerAdminId: "missing-owner" });

      const users = await callApi(handleApi, {
        method: "GET",
        pathname: "/api/admin/users",
        session: login.session
      });
      const visibleUser = users.find((user) => user.username === "visible-user");
      assert.equal(visibleUser.ownerUsername, null);

      const ownerLogin = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/auth/login",
        body: { username: owner.username, password: "owner-pass" }
      });
      const ownerUsers = await callApi(handleApi, {
        method: "GET",
        pathname: "/api/admin/users",
        session: ownerLogin.session
      });
      assert.equal(ownerUsers.some((user) => user.username === "visible-user"), false);

      const orphanedUser = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/admin/users",
        session: login.session,
        body: {
          username: "orphaned-user",
          panelId: panel.id,
          ownerAdminId: orphanOwner.id,
          limitBytes: 10,
          expiresAt: "2030-01-02T23:59:59.000Z",
          note: "orphan owner"
        }
      });
      assert.equal(orphanedUser.ownerUsername, orphanOwner.username);
      store.update("admins", orphanOwner.id, { active: false });
      store.remove("admins", orphanOwner.id);
      const refreshed = await callApi(handleApi, {
        method: "GET",
        pathname: "/api/admin/users",
        session: login.session
      });
      const orphanedVisible = refreshed.find((user) => user.username === "orphaned-user");
      assert.equal(orphanedVisible.ownerUsername, null);
    }
  );
});

test("dashboard totals count reseller accounts only", async () => {
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
      const before = await callApi(handleApi, {
        method: "GET",
        pathname: "/api/dashboard",
        session: login.session
      });
      await callApi(handleApi, {
        method: "POST",
        pathname: "/api/superadmin/admins",
        session: login.session,
        body: {
          username: "reseller-count-a",
          password: "reseller-pass-a",
          role: "admin",
          trafficLimitBytes: 1000
        }
      });
      await callApi(handleApi, {
        method: "POST",
        pathname: "/api/superadmin/admins",
        session: login.session,
        body: {
          username: "superadmin-count",
          password: "super-pass",
          role: "superadmin"
        }
      });

      const dashboard = await callApi(handleApi, {
        method: "GET",
        pathname: "/api/dashboard",
        session: login.session
      });
      assert.equal(dashboard.totals.resellers, before.totals.resellers + 1);
      assert.ok(dashboard.totals.admins >= before.totals.admins + 2);
    }
  );
});

test("sidebar nav stays role scoped for superadmin and reseller", async () => {
  const source = await readFile(join(process.cwd(), "web/app.js"), "utf8");
  const roleViewsSource = source.slice(source.indexOf("function roleScopedViews()"), source.indexOf("function requireSuperadminUi()"));
  const dashboardSource = source.slice(source.indexOf("function dashboard()"), source.indexOf("function panels()"));
  const panelsSource = source.slice(source.indexOf("function panels()"), source.indexOf("function admins()"));
  const navSource = source.slice(source.indexOf("function nav()"), source.indexOf("function shell("));
  const usersSource = source.slice(source.indexOf("function users()"), source.indexOf("function operations()"));
  assert.match(roleViewsSource, /return isReseller\(\) \? \["dashboard", "users"\] : \["dashboard", "panels", "admins", "operations"\];/);
  const superadminNav = navSource.match(/: \[\s*\n([\s\S]*?)\n\s*\];/);
  assert.ok(superadminNav);
  assert.doesNotMatch(superadminNav[1], /Customer Users|Users|VPN Accounts/);
  assert.match(superadminNav[1], /\["dashboard", "Dashboard", "Overview and live totals"\]/);
  assert.match(superadminNav[1], /\["panels", "Panels", "Panel registry and sync"\]/);
  assert.match(superadminNav[1], /\["admins", "Resellers", "SuperAdmin and reseller accounts"\]/);
  assert.match(superadminNav[1], /\["operations", "Operations", "Backup, logs, system"\]/);
  const resellerNav = navSource.match(/\?\s*\[\s*\n([\s\S]*?)\n\s*\]\s*:\s*\[/);
  assert.ok(resellerNav);
  assert.match(resellerNav[1], /\["dashboard", "Dashboard", "Quota and validity"\]/);
  assert.match(resellerNav[1], /\["users", "Users", "Customers and traffic"\]/);
  assert.doesNotMatch(resellerNav[1], /Panels|Resellers|Operations/);
  assert.match(dashboardSource, /pageTitle\("Dashboard", "Overview of panels, resellers, users, and traffic\."\)/);
  assert.doesNotMatch(dashboardSource, /Unified Dashboard/);
  assert.doesNotMatch(dashboardSource, /Panel adapters/);
  assert.doesNotMatch(dashboardSource, /Release mode/);
  assert.doesNotMatch(dashboardSource, /Recent activity/);
  assert.doesNotMatch(dashboardSource, /latest audit events/);
  assert.doesNotMatch(dashboardSource, /logsTable\(state\.logs\.slice\(/);
  const operationsSource = source.slice(source.indexOf("function operations()"), source.indexOf("window.Aegis ="));
  assert.match(operationsSource, /pageTitle\("Operations", "Backup and restore JSON, audit logs, news, and system maintenance\."/);
  assert.match(operationsSource, /<h3>Backup JSON<\/h3>/);
  assert.match(operationsSource, /Backup may include stored panel credentials\. Keep this file private\./);
  assert.match(operationsSource, /<h3>Restore JSON<\/h3>/);
  assert.match(operationsSource, /Type RESTORE before restoring the local store\./);
  assert.match(operationsSource, /<h3>Audit Logs<\/h3><span class="muted">Latest system and admin events\.<\/span>/);
  assert.match(operationsSource, /Show Logs/);
  assert.match(operationsSource, /showAuditLogs\(\)/);
  assert.match(operationsSource, /showRestoreBackupForm\(\)/);
  assert.match(operationsSource, /Show News/);
  assert.match(operationsSource, /Create News/);
  assert.match(operationsSource, /logsTable\(state\.logs\.slice\(0, 10\)\)/);
  assert.doesNotMatch(operationsSource, /logsTable\(state\.logs(?!\.slice)\)/);
  assert.match(source, /return `aegispanel-backup-\$\{year\}-\$\{month\}-\$\{day\}-\$\{hour\}-\$\{minute\}\.json`;/);
  assert.match(panelsSource, /pageTitle\("Panels", "Create upstream panels, check adapter capability, and trigger sync jobs\.", `<button class="primary" onclick="window\.Aegis\.showPanelForm\(\)">New panel<\/button>`, \{ showRefresh: false \}\)/);
  assert.doesNotMatch(panelsSource, /<button class="ghost" onclick="window\.Aegis\.load\(\)">Refresh<\/button>/);
  assert.match(source, /Allow insecure TLS/);
  assert.match(source, /Use only for test\/self-signed\/IP certificate panels\./);
  assert.match(panelsSource, /iconActionButton\("✎", "Edit panel"/);
  assert.match(panelsSource, /iconActionButton\("≡", "View inbounds"/);
  assert.match(panelsSource, /iconActionButton\("✓", "Test connection"/);
  assert.match(panelsSource, /iconActionButton\("↻", "Sync not ready"|iconActionButton\("↻", "Sync panel"/);
  assert.match(panelsSource, /iconActionButton\("🗑", "Delete panel"/);
  assert.match(usersSource, /pageTitle\("Users", "Customer users and owner visibility across assigned quota and validity\.", "", \{ showRefresh: false \}\)/);
  assert.match(usersSource, /<th>User<\/th>/);
  assert.match(usersSource, /No users yet\./);
});

test("create and edit user forms keep Marzban inbounds selectable", async () => {
  const source = (await readFile(join(process.cwd(), "web/app.js"), "utf8")).replace(/\r\n/g, "\n");
  assert.doesNotMatch(source, /realMarzbanInbounds|isDummyOrMetricsInbound/);
  assert.match(source, /normalMarzbanInboundIds\(inbounds\) \{\n  return \(inbounds \|\| \[\]\)\.map\(\(inbound\) => inbound\.id\);\n\}/);
  assert.match(source, /preferredMarzbanInboundId\(inboundIds, fallbackId = ""\) \{\n  const selected = Array\.isArray\(inboundIds\) \? inboundIds\.filter\(\(id\) => typeof id === "string" && id\.trim\(\)\) : \[\];\n  return selected\[0\] \|\| fallbackId \|\| "default";\n\}/);
  assert.match(source, /#user-create-error/);
  assert.match(source, /#edit-user-error/);
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

async function withMockFetch(responses, calls, fn) {
  const originalFetch = globalThis.fetch;
  let index = 0;
  globalThis.fetch = async (url, options = {}) => {
    calls.push({ url: String(url), options });
    const response = responses[index] ?? responses[responses.length - 1];
    index += 1;
    return response;
  };
  try {
    return await fn();
  } finally {
    globalThis.fetch = originalFetch;
  }
}

function createFetchResponse(body, { status = 200, headers = {} } = {}) {
  const text = typeof body === "string" ? body : body === undefined ? "" : JSON.stringify(body);
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: new Headers(headers),
    text: async () => text,
    json: async () => {
      if (!text) return null;
      return typeof body === "string" ? JSON.parse(text) : body;
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
  const panels = supportedPanels();
  const types = panels.map((panel) => panel.type).sort();
  assert.deepEqual(types, ["guard", "marzban", "s-ui", "three-x-ui", "tx-ui"]);
  for (const panel of panels) {
    assert.equal(typeof panel.type, "string");
    assert.equal(typeof panel.label, "string");
    assert.equal(typeof panel.capabilities, "object");
    assert.equal("secret" in panel, false);
    assert.equal("apiKey" in panel, false);
    assert.equal("password" in panel, false);
    assert.equal("token" in panel, false);
    assert.equal("credentials" in panel, false);
  }
  assert.equal(adapterFor("three-x-ui").label, "3x-ui / Sanaei");
  assert.deepEqual(adapterFor("three-x-ui").capabilities, {
    canTestConnection: true,
    canListInbounds: true,
    canCreateUser: true,
    canUpdateUser: true,
    canDeleteUser: true,
    canSyncTraffic: true,
    canBuildSubscriptionUrl: true,
    canGetUser: true
  });
  assert.equal(adapterFor("marzban").label, "Marzban");
  assert.deepEqual(adapterFor("marzban").capabilities, {
    canTestConnection: true,
    canListInbounds: true,
    canCreateUser: true,
    canUpdateUser: true,
    canDeleteUser: true,
    canSyncTraffic: true,
    canBuildSubscriptionUrl: true,
    canGetUser: true
  });
});

test("three-x-ui authenticates with bearer token or session cookie and normalizes inbounds", async () => {
  assert.equal(
    buildThreeXUiClient({
      url: "https://panel.example.com/rabEtXgGAk0JBV0uaC/panel/",
      apiKey: "panel-token",
      allowInsecureTls: true
    }).apiBase,
    "https://panel.example.com/rabEtXgGAk0JBV0uaC/panel/api"
  );
  assert.equal(
    buildThreeXUiClient({
      url: "https://panel.example.com/rabEtXgGAk0JBV0uaC/panel/",
      apiKey: "panel-token",
      allowInsecureTls: true
    }).allowInsecureTls,
    true
  );

  const bearerCalls = [];
  await withMockFetch(
    [
      createFetchResponse({
        success: true,
        msg: "",
        obj: [
          {
            id: 1,
            remark: "VLESS 443",
            protocol: "vless",
            port: 443,
            enable: true,
            streamSettings: { network: "ws", security: "tls" }
          },
          {
            id: 2,
            tag: "VMess 80",
            protocol: "vmess",
            port: 80,
            enabled: false,
            network: "tcp",
            tls: ""
          }
        ]
      })
    ],
    bearerCalls,
    async () => {
      const inbounds = await threeXUiAdapter.listInbounds({
        url: "https://panel.example.com/rabEtXgGAk0JBV0uaC/panel",
        apiKey: "panel-token"
      });
      assert.deepEqual(inbounds, [
        {
          id: "1",
          label: "VLESS 443",
          protocol: "vless",
          network: "ws",
          tls: "tls",
          port: 443,
          enabled: true
        },
        {
          id: "2",
          label: "VMess 80",
          protocol: "vmess",
          network: "tcp",
          tls: "",
          port: 80,
          enabled: false
        }
      ]);
      assert.equal(bearerCalls.length, 1);
      assert.equal(bearerCalls[0].url, "https://panel.example.com/rabEtXgGAk0JBV0uaC/panel/api/inbounds/list");
      assert.equal(bearerCalls[0].options.headers.authorization, "Bearer panel-token");
    }
  );

  const cookieCalls = [];
  await withMockFetch(
    [
      createFetchResponse(
        { success: true, obj: "csrf-token-123" },
        { status: 200, headers: { "set-cookie": "_xui_session=csrf123; Path=/; HttpOnly" } }
      ),
      createFetchResponse(
        { success: true, msg: "ok" },
        { status: 200, headers: { "set-cookie": "_xui_session=session123; Path=/; HttpOnly" } }
      ),
      createFetchResponse({
        success: true,
        msg: "",
        obj: [
          {
            id: 3,
            remark: "Out",
            protocol: "trojan",
            port: 8443,
            enable: true,
            streamSettings: { network: "ws", security: "tls" }
          }
        ]
      })
    ],
    cookieCalls,
    async () => {
      const inbounds = await threeXUiAdapter.listInbounds({
        url: "https://panel.example.com/rabEtXgGAk0JBV0uaC/panel/",
        username: "admin",
        password: "secret"
      });
      assert.equal(cookieCalls.length, 3);
      assert.equal(cookieCalls[0].url, "https://panel.example.com/rabEtXgGAk0JBV0uaC/csrf-token");
      assert.equal(cookieCalls[0].options.method, "GET");
      assert.equal(cookieCalls[0].options.headers["x-requested-with"], "XMLHttpRequest");
      assert.equal(cookieCalls[1].url, "https://panel.example.com/rabEtXgGAk0JBV0uaC/login");
      assert.equal(cookieCalls[1].options.method, "POST");
      assert.equal(cookieCalls[1].options.headers["content-type"], "application/x-www-form-urlencoded");
      assert.equal(cookieCalls[1].options.headers["x-csrf-token"], "csrf-token-123");
      assert.equal(cookieCalls[1].options.headers.cookie, "_xui_session=csrf123");
      assert.equal(cookieCalls[1].options.body, "username=admin&password=secret");
      assert.equal(cookieCalls[2].options.headers.cookie, "_xui_session=session123");
      assert.equal(cookieCalls[2].url, "https://panel.example.com/rabEtXgGAk0JBV0uaC/panel/api/inbounds/list");
      assert.equal(inbounds[0].label, "Out");
    }
  );
});

test("three-x-ui falls back to the alternate login root when the stripped root fails", async () => {
  const calls = [];
  await withMockFetch(
    [
      createFetchResponse("", { status: 403 }),
      createFetchResponse(
        { success: true, obj: "csrf-token-abc" },
        { status: 200, headers: { "set-cookie": "_xui_session=csrf456; Path=/; HttpOnly" } }
      ),
      createFetchResponse(
        { success: true, msg: "ok" },
        { status: 200, headers: { "set-cookie": "_xui_session=session456; Path=/; HttpOnly" } }
      ),
      createFetchResponse({
        success: true,
        msg: "",
        obj: [
          {
            id: 3,
            remark: "Out",
            protocol: "trojan",
            port: 8443,
            enable: true,
            streamSettings: { network: "ws", security: "tls" }
          }
        ]
      })
    ],
    calls,
    async () => {
      const inbounds = await threeXUiAdapter.listInbounds({
        url: "https://panel.example.com/rabEtXgGAk0JBV0uaC/panel/",
        username: "admin",
        password: "secret"
      });
      assert.equal(calls.length, 4);
      assert.equal(calls[0].url, "https://panel.example.com/rabEtXgGAk0JBV0uaC/csrf-token");
      assert.equal(calls[1].url, "https://panel.example.com/rabEtXgGAk0JBV0uaC/panel/csrf-token");
      assert.equal(calls[2].url, "https://panel.example.com/rabEtXgGAk0JBV0uaC/panel/login");
      assert.equal(calls[3].url, "https://panel.example.com/rabEtXgGAk0JBV0uaC/panel/api/inbounds/list");
      assert.equal(inbounds[0].label, "Out");
    }
  );
});

test("three-x-ui uses insecure TLS request handling only when enabled", async () => {
  const originalFetch = global.fetch;
  const originalRequest = https.request;
  const originalTransport = process.env.AEGIS_3XUI_POWERSHELL_TRANSPORT;
  const calls = [];
  try {
    process.env.AEGIS_3XUI_POWERSHELL_TRANSPORT = "0";
    global.fetch = () => {
      throw new Error("fetch should not be used when insecure TLS is enabled");
    };
    https.request = (url, options, callback) => {
      const requestBody = [];
      const req = new EventEmitter();
      req.write = (chunk) => {
        requestBody.push(Buffer.isBuffer(chunk) ? chunk.toString("utf8") : String(chunk));
      };
      req.end = () => {
        const target = typeof url === "string" ? new URL(url) : url;
        calls.push({
          url: target.toString(),
          options,
          body: requestBody.join("")
        });
        const response = new EventEmitter();
        response.statusCode = 200;
        response.headers = target.pathname.endsWith("/login") || target.pathname.endsWith("/csrf-token")
          ? { "set-cookie": ["_xui_session=session123; Path=/; HttpOnly"] }
          : {};
        callback(response);
        const payload = target.pathname.endsWith("/csrf-token")
          ? { success: true, obj: "csrf-token-xyz" }
          : target.pathname.endsWith("/login")
          ? { success: true, msg: "ok" }
          : {
              success: true,
              msg: "",
              obj: [
                {
                  id: 1,
                  remark: "VLESS 443",
                  protocol: "vless",
                  port: 443,
                  enable: true,
                  streamSettings: { network: "ws", security: "tls" }
                }
              ]
            };
        response.emit("data", Buffer.from(JSON.stringify(payload)));
        response.emit("end");
      };
      return req;
    };

    const result = await threeXUiAdapter.testConnection({
      url: "https://panel.example.com/rabEtXgGAk0JBV0uaC/panel/",
      username: "panel-user",
      secret: "panel-secret",
      allowInsecureTls: true
    });

    assert.equal(result.ok, true);
    assert.equal(result.inboundCount, 1);
    assert.equal(calls.length, 3);
    assert.equal(calls[0].url, "https://panel.example.com/rabEtXgGAk0JBV0uaC/csrf-token");
    assert.equal(calls[1].url, "https://panel.example.com/rabEtXgGAk0JBV0uaC/login");
    assert.equal(calls[0].options.agent.options.rejectUnauthorized, false);
    assert.equal(calls[1].options.headers["x-csrf-token"], "csrf-token-xyz");
    assert.equal(calls[1].options.headers.cookie, "_xui_session=session123");
    assert.equal(calls[1].options.agent.options.rejectUnauthorized, false);
    assert.equal(calls[2].options.headers.cookie, "_xui_session=session123");
    assert.equal(calls[2].url, "https://panel.example.com/rabEtXgGAk0JBV0uaC/panel/api/inbounds/list");
    assert.equal(calls[2].options.agent.options.rejectUnauthorized, false);
  } finally {
    global.fetch = originalFetch;
    https.request = originalRequest;
    if (originalTransport === undefined) {
      delete process.env.AEGIS_3XUI_POWERSHELL_TRANSPORT;
    } else {
      process.env.AEGIS_3XUI_POWERSHELL_TRANSPORT = originalTransport;
    }
  }
});

test("three-x-ui buildSubscriptionUrl uses the configured panel prefix and path", async () => {
  assert.equal(
    await threeXUiAdapter.buildSubscriptionUrl(
      {
        subscriptionUrl: "https://prefix.example.com/",
        subscriptionPath: "/subscription/"
      },
      { subId: "ticket-123" },
      { username: "alice" }
    ),
    "https://prefix.example.com/subscription/ticket-123"
  );
  assert.equal(
    await threeXUiAdapter.buildSubscriptionUrl(
      {
        subscriptionUrl: "vless://example@127.0.0.1:123",
        subscriptionPath: "sub"
      },
      { subId: "ticket-123" },
      { username: "alice" }
    ),
    null
  );
});

test("three-x-ui createUser sends the verified payload and builds a subscription URL", async () => {
  const calls = [];
  await withMockFetch(
    [
      createFetchResponse({
        success: true,
        msg: "",
        obj: {
          client: {
            id: 94,
            email: "alice",
            subId: "ticket-123",
            enable: true
          },
          inboundIds: [1, 2]
        }
      })
    ],
    calls,
    async () => {
      const result = await threeXUiAdapter.createUser(
        {
          url: "https://panel.example.com/rabEtXgGAk0JBV0uaC/panel",
          subscriptionUrl: "https://prefix.example.com/",
          subscriptionPath: "sub",
          apiKey: "panel-token"
        },
        {
          username: "alice",
          limitBytes: 4294967296,
          expiresAt: "2030-01-02T03:04:05.000Z",
          active: false,
          note: "demo note",
          flow: "xtls-rprx-vision",
          inboundIds: [2, 1],
          subscriptionId: "ticket-123"
        }
      );
      assert.equal(calls.length, 1);
      assert.equal(calls[0].url, "https://panel.example.com/rabEtXgGAk0JBV0uaC/panel/api/clients/add");
      assert.equal(calls[0].options.method, "POST");
      assert.equal(calls[0].options.headers.authorization, "Bearer panel-token");
      const body = JSON.parse(calls[0].options.body);
      assert.equal(body.client.email, "alice");
      assert.equal(typeof body.client.uuid, "string");
      assert.equal(body.client.subId, "ticket-123");
      assert.equal(body.client.totalGB, 4294967296);
      assert.equal(body.client.expiryTime, new Date("2030-01-02T03:04:05.000Z").getTime());
      assert.equal(body.client.enable, false);
      assert.equal(body.client.flow, "xtls-rprx-vision");
      assert.equal(body.client.comment, "demo note");
      assert.deepEqual(body.inboundIds, [2, 1]);
      assert.equal(result.subscriptionId, "ticket-123");
      assert.equal(result.subscriptionUrl, "https://prefix.example.com/sub/ticket-123");
    }
  );
});

test("three-x-ui updateUser sends the verified payload", async () => {
  const calls = [];
  await withMockFetch(
    [
      createFetchResponse({
        success: true,
        msg: "",
        obj: {
          client: {
            id: 94,
            email: "alice",
            subId: "ticket-123",
            enable: false
          },
          inboundIds: [2, 3]
        }
      })
    ],
    calls,
    async () => {
      const result = await threeXUiAdapter.updateUser(
      {
        url: "https://panel.example.com/rabEtXgGAk0JBV0uaC/panel",
        subscriptionUrl: "https://prefix.example.com/",
        subscriptionPath: "subscription",
        apiKey: "panel-token"
        },
        {
          username: "alice",
          subscriptionId: "ticket-123",
          limitBytes: 1024,
          expiresAt: "2030-01-02T03:04:05.000Z",
          active: true,
          note: "old note",
          flow: "",
          inboundIds: [1]
        },
        {
          limitBytes: 2048,
          expiresAt: "2030-02-03T04:05:06.000Z",
          active: false,
          note: "updated note",
          flow: "xtls-rprx-vision",
          inboundIds: [2, 3]
        }
      );
      assert.equal(calls.length, 3);
      assert.equal(calls[0].url, "https://panel.example.com/rabEtXgGAk0JBV0uaC/panel/api/clients/update/alice");
      assert.equal(calls[0].options.method, "POST");
      const body = JSON.parse(calls[0].options.body);
      assert.equal(body.email, "alice");
      assert.equal(body.subId, "ticket-123");
      assert.equal(body.totalGB, 2048);
      assert.equal(body.expiryTime, new Date("2030-02-03T04:05:06.000Z").getTime());
      assert.equal(body.enable, false);
      assert.equal(body.comment, "updated note");
      assert.equal(body.flow, "xtls-rprx-vision");
      assert.equal("inboundIds" in body, false);
      assert.equal(calls[1].url, "https://panel.example.com/rabEtXgGAk0JBV0uaC/panel/api/clients/alice/attach");
      assert.deepEqual(JSON.parse(calls[1].options.body), { inboundIds: [2, 3] });
      assert.equal(calls[2].url, "https://panel.example.com/rabEtXgGAk0JBV0uaC/panel/api/clients/alice/detach");
      assert.deepEqual(JSON.parse(calls[2].options.body), { inboundIds: [1] });
      assert.equal(result.subscriptionUrl, "https://prefix.example.com/subscription/ticket-123");
    }
  );
});

test("three-x-ui syncUserTraffic maps traffic and ignores raw config links", async () => {
  const calls = [];
  await withMockFetch(
    [
      createFetchResponse(
        { success: true, obj: "csrf-token-sync" },
        { status: 200, headers: { "set-cookie": "_xui_session=csrf-sync; Path=/; HttpOnly" } }
      ),
      createFetchResponse(
        { success: true, msg: "ok" },
        { status: 200, headers: { "set-cookie": "_xui_session=session-sync; Path=/; HttpOnly" } }
      ),
      createFetchResponse({
        success: true,
        msg: "",
        obj: {
          client: {
            id: 94,
            email: "alice",
            subId: "ticket-123",
            enable: true
          },
          inboundIds: [1, 2],
          links: ["vless://example@127.0.0.1:123?path=%2F"]
        }
      }),
      createFetchResponse({
        success: true,
        msg: "",
        obj: {
          up: 120,
          down: 30
        }
      })
    ],
    calls,
    async () => {
      const result = await threeXUiAdapter.syncUserTraffic({
        url: "https://panel.example.com/rabEtXgGAk0JBV0uaC/panel/",
        subscriptionUrl: "https://prefix.example.com/",
        username: "admin",
        password: "secret"
      }, {
        username: "alice",
        usedBytes: 999
      });
      assert.equal(calls.length, 4);
      assert.equal(calls[0].url, "https://panel.example.com/rabEtXgGAk0JBV0uaC/csrf-token");
      assert.equal(calls[1].url, "https://panel.example.com/rabEtXgGAk0JBV0uaC/login");
      assert.equal(calls[2].url, "https://panel.example.com/rabEtXgGAk0JBV0uaC/panel/api/clients/get/alice");
      assert.equal(calls[3].url, "https://panel.example.com/rabEtXgGAk0JBV0uaC/panel/api/clients/traffic/alice");
      assert.equal(result.usedBytes, 150);
      assert.equal(result.subscriptionId, "ticket-123");
      assert.equal(result.subscriptionUrl, "https://prefix.example.com/sub/ticket-123");
    }
  );
});

test("three-x-ui deleteUser treats missing clients as success", async () => {
  const calls = [];
  await withMockFetch(
    [
      createFetchResponse(
        { success: true, obj: "csrf-token-delete" },
        { status: 200, headers: { "set-cookie": "_xui_session=csrf-delete; Path=/; HttpOnly" } }
      ),
      createFetchResponse(
        { success: true, msg: "ok" },
        { status: 200, headers: { "set-cookie": "_xui_session=session-delete; Path=/; HttpOnly" } }
      ),
      createFetchResponse("", { status: 404 })
    ],
    calls,
    async () => {
      const result = await threeXUiAdapter.deleteUser({
        url: "https://panel.example.com/rabEtXgGAk0JBV0uaC/panel",
        username: "admin",
        password: "secret"
      }, {
        username: "alice"
      });
      assert.equal(calls.length, 3);
      assert.equal(calls[0].url, "https://panel.example.com/rabEtXgGAk0JBV0uaC/csrf-token");
      assert.equal(calls[1].url, "https://panel.example.com/rabEtXgGAk0JBV0uaC/login");
      assert.equal(calls[2].url, "https://panel.example.com/rabEtXgGAk0JBV0uaC/panel/api/clients/del/alice");
      assert.equal(calls[2].options.method, "POST");
      assert.equal(result.status, "missing");
      assert.equal("token" in result, false);
      assert.equal("password" in result, false);
    }
  );
});

test("superadmin can fetch normalized three-x-ui inbounds through the api", async () => {
  const calls = [];
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
          name: "3x-ui Panel",
          type: "three-x-ui",
          url: "https://panel.example.com/rabEtXgGAk0JBV0uaC/panel",
          subscriptionUrl: "https://prefix.example.com",
          username: "admin",
          secret: "secret"
        }
      });

      await withMockFetch(
        [
          createFetchResponse({ success: true, obj: "csrf-token-list" }, { status: 200, headers: { "set-cookie": "_xui_session=csrf-list; Path=/; HttpOnly" } }),
          createFetchResponse({ success: true, msg: "ok" }, { status: 200, headers: { "set-cookie": "_xui_session=session123; Path=/; HttpOnly" } }),
          createFetchResponse({
            success: true,
            msg: "",
            obj: [
              {
                id: 1,
                remark: "VLESS 443",
                protocol: "vless",
                port: 443,
                enable: true,
                streamSettings: { network: "ws", security: "tls" }
              },
              {
                id: 2,
                tag: "VMess 80",
                protocol: "vmess",
                port: 80,
                enabled: false,
                network: "tcp",
                tls: ""
              }
            ]
          })
        ],
        calls,
        async () => {
          const inbounds = await callApi(handleApi, {
            method: "GET",
            pathname: `/api/superadmin/panels/${panel.id}/inbounds`,
            session: login.session
          });
          assert.deepEqual(inbounds, [
            {
              id: "1",
              label: "VLESS 443",
              protocol: "vless",
              network: "ws",
              tls: "tls",
              port: 443,
              enabled: true
            },
            {
              id: "2",
              label: "VMess 80",
              protocol: "vmess",
              network: "tcp",
              tls: "",
              port: 80,
              enabled: false
            }
          ]);
        }
      );
    }
  );
  assert.equal(calls[0].url, "https://panel.example.com/rabEtXgGAk0JBV0uaC/csrf-token");
  assert.equal(calls[1].url, "https://panel.example.com/rabEtXgGAk0JBV0uaC/login");
  assert.equal(calls[2].url, "https://panel.example.com/rabEtXgGAk0JBV0uaC/panel/api/inbounds/list");
});

test("reseller can fetch normalized three-x-ui inbounds through the admin-scoped api", async () => {
  const calls = [];
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
          name: "3x-ui Panel",
          type: "three-x-ui",
          url: "https://panel.example.com/rabEtXgGAk0JBV0uaC/panel",
          subscriptionUrl: "https://prefix.example.com",
          username: "admin",
          secret: "secret"
        }
      });
      const reseller = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/superadmin/admins",
        session: login.session,
        body: {
          username: "three-reseller-inbounds",
          password: "reseller-pass",
          panelId: panel.id,
          trafficLimitBytes: 1000
        }
      });
      const resellerLogin = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/auth/login",
        body: { username: reseller.username, password: "reseller-pass" }
      });

      await withMockFetch(
        [
          createFetchResponse({ success: true, obj: "csrf-token-list" }, { status: 200, headers: { "set-cookie": "_xui_session=csrf-list; Path=/; HttpOnly" } }),
          createFetchResponse({ success: true, msg: "ok" }, { status: 200, headers: { "set-cookie": "_xui_session=session123; Path=/; HttpOnly" } }),
          createFetchResponse({
            success: true,
            msg: "",
            obj: [
              { id: 1, remark: "VLESS 443", protocol: "vless", port: 443, enable: true, streamSettings: { network: "ws", security: "tls" } },
              { id: 2, remark: "VMess 80", protocol: "vmess", port: 80, enable: false, network: "tcp", tls: "" }
            ]
          })
        ],
        calls,
        async () => {
          const inbounds = await callApi(handleApi, {
            method: "GET",
            pathname: `/api/admin/panels/${panel.id}/inbounds`,
            session: resellerLogin.session
          });
          assert.deepEqual(inbounds, [
            {
              id: "1",
              label: "VLESS 443",
              protocol: "vless",
              network: "ws",
              tls: "tls",
              port: 443,
              enabled: true
            },
            {
              id: "2",
              label: "VMess 80",
              protocol: "vmess",
              network: "tcp",
              tls: "",
              port: 80,
              enabled: false
            }
          ]);
        }
      );
    }
  );
  assert.equal(calls[0].url, "https://panel.example.com/rabEtXgGAk0JBV0uaC/csrf-token");
  assert.equal(calls[1].url, "https://panel.example.com/rabEtXgGAk0JBV0uaC/login");
  assert.equal(calls[2].url, "https://panel.example.com/rabEtXgGAk0JBV0uaC/panel/api/inbounds/list");
});

test("reseller create through a three-x-ui panel stores a safe subscriptionUrl", async () => {
  const calls = [];
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
          name: "3x-ui Panel",
          type: "three-x-ui",
          url: "https://panel.example.com/rabEtXgGAk0JBV0uaC/panel",
          subscriptionUrl: "https://prefix.example.com",
          username: "panel-admin",
          secret: "panel-secret"
        }
      });
      const reseller = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/superadmin/admins",
        session: login.session,
        body: {
          username: "three-reseller",
          password: "reseller-pass",
          panelId: panel.id,
          trafficLimitBytes: 1000
        }
      });
      const resellerLogin = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/auth/login",
        body: { username: reseller.username, password: "reseller-pass" }
      });

      await withMockFetch(
        [
          createFetchResponse(
            { success: true, obj: "csrf-token-create-list" },
            { status: 200, headers: { "set-cookie": "_xui_session=create-list; Path=/; HttpOnly" } }
          ),
          createFetchResponse(
            { success: true, msg: "ok" },
            { status: 200, headers: { "set-cookie": "_xui_session=session-create-list; Path=/; HttpOnly" } }
          ),
          createFetchResponse({
            success: true,
            msg: "",
            obj: [
              { id: 11, remark: "VLESS 443", protocol: "vless", port: 443, enable: true },
              { id: 12, remark: "VMess 80", protocol: "vmess", port: 80, enable: true }
            ]
          }),
          createFetchResponse(
            { success: true, obj: "csrf-token-create-user" },
            { status: 200, headers: { "set-cookie": "_xui_session=create-user; Path=/; HttpOnly" } }
          ),
          createFetchResponse(
            { success: true, msg: "ok" },
            { status: 200, headers: { "set-cookie": "_xui_session=session-create-user; Path=/; HttpOnly" } }
          ),
          createFetchResponse({
            success: true,
            msg: "",
            obj: {
              client: {
                id: 94,
                email: "three-user",
                subId: "sub-123",
                enable: true
              },
              inboundIds: [11, 12],
              links: ["vless://raw.example.com:443?path=%2F"]
            }
          })
        ],
        calls,
        async () => {
          const created = await callApi(handleApi, {
            method: "POST",
            pathname: "/api/admin/users",
            session: resellerLogin.session,
            body: {
              username: "three-user",
              limitBytes: 100,
              expiresAt: "2030-01-02T23:59:59.000Z",
              note: "three-ui customer"
            }
          });
          assert.equal(created.username, "three-user");
          assert.equal(created.subscriptionId, "sub-123");
          assert.equal(created.subscriptionUrl, "https://prefix.example.com/sub/sub-123");
          assert.equal(created.inboundMode, "all");
          assert.deepEqual(created.inboundIds, ["11", "12"]);

          const users = await callApi(handleApi, {
            method: "GET",
            pathname: "/api/admin/users",
            session: resellerLogin.session
          });
          const stored = users.find((user) => user.username === "three-user");
          assert.equal(stored.subscriptionUrl, "https://prefix.example.com/sub/sub-123");
          assert.equal(stored.ownerUsername, reseller.username);
        }
      );
    }
  );
  assert.equal(calls[0].url, "https://panel.example.com/rabEtXgGAk0JBV0uaC/csrf-token");
  assert.equal(calls[1].url, "https://panel.example.com/rabEtXgGAk0JBV0uaC/login");
  assert.equal(calls[2].url, "https://panel.example.com/rabEtXgGAk0JBV0uaC/panel/api/inbounds/list");
  assert.equal(calls[3].url, "https://panel.example.com/rabEtXgGAk0JBV0uaC/csrf-token");
  assert.equal(calls[4].url, "https://panel.example.com/rabEtXgGAk0JBV0uaC/login");
  assert.equal(calls[5].url, "https://panel.example.com/rabEtXgGAk0JBV0uaC/panel/api/clients/add");
  const createBody = JSON.parse(calls[5].options.body);
  assert.deepEqual(createBody.inboundIds, [11, 12]);
  assert.equal(createBody.client.email, "three-user");
});

test("reseller create through a three-x-ui panel rolls back local state on remote failure", async () => {
  const calls = [];
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
          name: "3x-ui Panel",
          type: "three-x-ui",
          url: "https://panel.example.com/rabEtXgGAk0JBV0uaC/panel",
          subscriptionUrl: "https://prefix.example.com",
          apiKey: "panel-token"
        }
      });
      const reseller = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/superadmin/admins",
        session: login.session,
        body: {
          username: "three-reseller-rollback",
          password: "reseller-pass",
          panelId: panel.id,
          trafficLimitBytes: 1000
        }
      });
      const resellerLogin = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/auth/login",
        body: { username: reseller.username, password: "reseller-pass" }
      });

      await withMockFetch(
        [
          createFetchResponse({
            success: true,
            msg: "",
            obj: [
              { id: 41, remark: "VLESS 443", protocol: "vless", port: 443, enable: true }
            ]
          }),
          createFetchResponse({ success: false, msg: "boom" }, { status: 500 })
        ],
        calls,
        async () => {
          const created = await callApiWithOutcome(handleApi, {
            method: "POST",
            pathname: "/api/admin/users",
            session: resellerLogin.session,
            body: {
              username: "three-user-rollback",
              limitBytes: 100,
              expiresAt: "2030-01-02T23:59:59.000Z",
              note: "rollback me"
            }
          });
          assert.ok([500, 502].includes(created.statusCode));
          assert.match(created.json.error, /failed/i);

          const users = await callApi(handleApi, {
            method: "GET",
            pathname: "/api/admin/users",
            session: resellerLogin.session
          });
          assert.equal(users.some((user) => user.username === "three-user-rollback"), false);

          const admins = await callApi(handleApi, {
            method: "GET",
            pathname: "/api/superadmin/admins",
            session: login.session
          });
          const storedReseller = admins.find((item) => item.username === reseller.username);
          assert.equal(storedReseller.trafficRemainingBytes, 1000);
        }
      );
    }
  );
  assert.equal(calls[0].url, "https://panel.example.com/rabEtXgGAk0JBV0uaC/panel/api/inbounds/list");
  assert.equal(calls[1].url, "https://panel.example.com/rabEtXgGAk0JBV0uaC/panel/api/clients/add");
});

test("reseller update, sync, and delete through three-x-ui call the adapter and preserve quota safety", async () => {
  const calls = [];
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
          name: "3x-ui Panel",
          type: "three-x-ui",
          url: "https://panel.example.com/rabEtXgGAk0JBV0uaC/panel",
          subscriptionUrl: "https://prefix.example.com",
          apiKey: "panel-token"
        }
      });
      const reseller = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/superadmin/admins",
        session: login.session,
        body: {
          username: "three-reseller-update",
          password: "reseller-pass",
          panelId: panel.id,
          trafficLimitBytes: 1000
        }
      });
      const resellerLogin = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/auth/login",
        body: { username: reseller.username, password: "reseller-pass" }
      });

      await withMockFetch(
        [
          createFetchResponse({
            success: true,
            msg: "",
            obj: [
              { id: 21, remark: "VLESS 443", protocol: "vless", port: 443, enable: true },
              { id: 22, remark: "VMess 80", protocol: "vmess", port: 80, enable: true }
            ]
          }),
          createFetchResponse({
            success: true,
            msg: "",
            obj: {
              client: { id: 95, email: "three-user-update", subId: "sub-321", enable: true },
              inboundIds: [21, 22]
            }
          }),
          createFetchResponse({
            success: true,
            msg: "",
            obj: {
              client: { id: 95, email: "three-user-update", subId: "sub-321", enable: true }
            }
          }),
          createFetchResponse({
            success: true,
            msg: "",
            obj: {
              client: { id: 95, email: "three-user-update", subId: "sub-321", enable: true }
            }
          }),
          createFetchResponse({
            success: true,
            msg: "",
            obj: {
              up: 120,
              down: 30
            }
          })
        ],
        calls,
        async () => {
          const created = await callApi(handleApi, {
            method: "POST",
            pathname: "/api/admin/users",
            session: resellerLogin.session,
            body: {
              username: "three-user-update",
              limitBytes: 100,
              expiresAt: "2030-01-02T23:59:59.000Z",
              note: "update me"
            }
          });
          const updated = await callApi(handleApi, {
            method: "PUT",
            pathname: `/api/admin/users/${created.id}`,
            session: resellerLogin.session,
            body: {
              limitBytes: 300,
              note: "updated note"
            }
          });
          assert.equal(updated.limitBytes, 300);
          assert.equal(updated.reservedBytes, 300);

          const synced = await callApi(handleApi, {
            method: "POST",
            pathname: `/api/admin/users/${created.id}/sync-traffic`,
            session: resellerLogin.session
          });
          assert.equal(synced.usedBytes, 150);

          const admins = await callApi(handleApi, {
            method: "GET",
            pathname: "/api/superadmin/admins",
            session: login.session
          });
          const storedReseller = admins.find((admin) => admin.username === reseller.username);
          assert.equal(storedReseller.trafficRemainingBytes, 700);
        }
      );
    }
  );
  assert.equal(calls[0].url, "https://panel.example.com/rabEtXgGAk0JBV0uaC/panel/api/inbounds/list");
  assert.equal(calls[1].url, "https://panel.example.com/rabEtXgGAk0JBV0uaC/panel/api/clients/add");
  assert.equal(calls[2].url, "https://panel.example.com/rabEtXgGAk0JBV0uaC/panel/api/clients/update/three-user-update");
  assert.equal(calls[3].url, "https://panel.example.com/rabEtXgGAk0JBV0uaC/panel/api/clients/get/three-user-update");
  assert.equal(calls[4].url, "https://panel.example.com/rabEtXgGAk0JBV0uaC/panel/api/clients/traffic/three-user-update");
});

test("reseller delete through a three-x-ui panel calls the adapter before local removal", async () => {
  const calls = [];
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
          name: "3x-ui Panel",
          type: "three-x-ui",
          url: "https://panel.example.com/rabEtXgGAk0JBV0uaC/panel",
          subscriptionUrl: "https://prefix.example.com",
          apiKey: "panel-token"
        }
      });
      const reseller = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/superadmin/admins",
        session: login.session,
        body: {
          username: "three-reseller-delete",
          password: "reseller-pass",
          panelId: panel.id,
          trafficLimitBytes: 1000
        }
      });
      const resellerLogin = await callApi(handleApi, {
        method: "POST",
        pathname: "/api/auth/login",
        body: { username: reseller.username, password: "reseller-pass" }
      });

      await withMockFetch(
        [
          createFetchResponse({
            success: true,
            msg: "",
            obj: [
              { id: 31, remark: "VLESS 443", protocol: "vless", port: 443, enable: true }
            ]
          }),
          createFetchResponse({
            success: true,
            msg: "",
            obj: {
              client: {
                id: 96,
                email: "three-user-delete",
                subId: "sub-delete",
                enable: true
              },
              inboundIds: [31]
            }
          }),
          createFetchResponse({
            success: true,
            msg: "",
            obj: {
              client: {
                id: 96,
                email: "three-user-delete",
                subId: "sub-delete",
                enable: true
              }
            }
          }),
          createFetchResponse({
            success: true,
            msg: "",
            obj: {
              up: 0,
              down: 0
            }
          }),
          createFetchResponse({ success: true, msg: "ok" })
        ],
        calls,
        async () => {
          const created = await callApi(handleApi, {
            method: "POST",
            pathname: "/api/admin/users",
            session: resellerLogin.session,
            body: {
              username: "three-user-delete",
              limitBytes: 100,
              expiresAt: "2030-01-02T23:59:59.000Z",
              note: "delete me"
            }
          });

          const deleted = await callApi(handleApi, {
            method: "DELETE",
            pathname: `/api/admin/users/${created.id}`,
            session: resellerLogin.session
          });
          assert.equal(deleted.ok, true);

          const afterDeleteUsers = await callApi(handleApi, {
            method: "GET",
            pathname: "/api/admin/users",
            session: resellerLogin.session
          });
          assert.equal(afterDeleteUsers.some((user) => user.username === "three-user-delete"), false);

          const admins = await callApi(handleApi, {
            method: "GET",
            pathname: "/api/superadmin/admins",
            session: login.session
          });
          const storedReseller = admins.find((admin) => admin.username === reseller.username);
          assert.equal(storedReseller.trafficRemainingBytes, 1000);
        }
      );
    }
  );
  assert.equal(calls[0].url, "https://panel.example.com/rabEtXgGAk0JBV0uaC/panel/api/inbounds/list");
  assert.equal(calls[1].url, "https://panel.example.com/rabEtXgGAk0JBV0uaC/panel/api/clients/add");
  assert.equal(calls[2].url, "https://panel.example.com/rabEtXgGAk0JBV0uaC/panel/api/clients/get/three-user-delete");
  assert.equal(calls[3].url, "https://panel.example.com/rabEtXgGAk0JBV0uaC/panel/api/clients/traffic/three-user-delete");
  assert.equal(calls[4].url, "https://panel.example.com/rabEtXgGAk0JBV0uaC/panel/api/clients/del/three-user-delete");
});

test("skeleton adapters fail clearly on contract methods", async () => {
  const adapter = adapterFor("s-ui");
  assert.equal(typeof adapter.testConnection, "function");
  assert.equal(typeof adapter.listInbounds, "function");
  assert.equal(typeof adapter.createUser, "function");
  assert.equal(typeof adapter.updateUser, "function");
  assert.equal(typeof adapter.deleteUser, "function");
  assert.equal(typeof adapter.getUser, "function");
  assert.equal(typeof adapter.syncUserTraffic, "function");
  assert.equal(typeof adapter.buildSubscriptionUrl, "function");
  await assert.rejects(adapter.testConnection({}), /s-ui testConnection is not implemented yet/);
  await assert.rejects(adapter.listInbounds({}), /s-ui listInbounds is not implemented yet/);
  await assert.rejects(adapter.createUser({}, {}), /s-ui createUser is not implemented yet/);
  await assert.rejects(adapter.updateUser({}, {}, {}), /s-ui updateUser is not implemented yet/);
  await assert.rejects(adapter.deleteUser({}, {}), /s-ui deleteUser is not implemented yet/);
  await assert.rejects(adapter.getUser({}, {}), /s-ui getUser is not implemented yet/);
  await assert.rejects(adapter.syncUserTraffic({}, {}), /s-ui syncUserTraffic is not implemented yet/);
  await assert.rejects(adapter.buildSubscriptionUrl({}, {}, {}), /s-ui buildSubscriptionUrl is not implemented yet/);
});
