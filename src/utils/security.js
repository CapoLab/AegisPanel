import { createHmac, randomBytes, scryptSync, timingSafeEqual } from "node:crypto";

const encoder = new TextEncoder();

export function hashPassword(password, salt = randomBytes(16).toString("hex")) {
  const hash = scryptSync(password, salt, 64).toString("hex");
  return `${salt}:${hash}`;
}

export function verifyPassword(password, stored) {
  const [salt, expected] = String(stored || "").split(":");
  if (!salt || !expected) return false;
  const actual = scryptSync(password, salt, 64);
  const expectedBuffer = Buffer.from(expected, "hex");
  return actual.length === expectedBuffer.length && timingSafeEqual(actual, expectedBuffer);
}

function base64url(input) {
  return Buffer.from(input).toString("base64url");
}

export function signSession(payload, secret, ttlSeconds = 86400) {
  const header = { alg: "HS256", typ: "AegisSession" };
  const body = { ...payload, exp: Math.floor(Date.now() / 1000) + ttlSeconds };
  const unsigned = `${base64url(JSON.stringify(header))}.${base64url(JSON.stringify(body))}`;
  const signature = createHmac("sha256", secret).update(unsigned).digest("base64url");
  return `${unsigned}.${signature}`;
}

export function verifySession(session, secret) {
  const parts = String(session || "").split(".");
  if (parts.length !== 3) return null;
  const [header, body, signature] = parts;
  const unsigned = `${header}.${body}`;
  const expected = createHmac("sha256", secret).update(unsigned).digest("base64url");
  const actualBytes = encoder.encode(signature);
  const expectedBytes = encoder.encode(expected);
  if (actualBytes.length !== expectedBytes.length || !timingSafeEqual(actualBytes, expectedBytes)) return null;
  const payload = JSON.parse(Buffer.from(body, "base64url").toString("utf8"));
  if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) return null;
  return payload;
}

export function safeId(prefix) {
  return `${prefix}_${randomBytes(9).toString("base64url")}`;
}
