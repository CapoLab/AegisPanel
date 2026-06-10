export async function readJson(req, { limitBytes = 1024 * 1024 } = {}) {
  const chunks = [];
  let totalBytes = 0;
  for await (const chunk of req) {
    totalBytes += chunk.length;
    if (totalBytes > limitBytes) {
      const error = new Error("Request body too large");
      error.status = 413;
      throw error;
    }
    chunks.push(chunk);
  }
  if (!chunks.length) return {};
  const raw = Buffer.concat(chunks).toString("utf8");
  try {
    return JSON.parse(raw);
  } catch {
    const error = new Error("Invalid JSON body");
    error.status = 400;
    throw error;
  }
}

export function sendJson(res, status, payload) {
  const body = JSON.stringify(payload, null, 2);
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store"
  });
  res.end(body);
}

export function notFound(res) {
  sendJson(res, 404, { ok: false, error: "Route not found" });
}

export function parseRoute(req) {
  const url = new URL(req.url, "http://localhost");
  return {
    method: req.method,
    pathname: url.pathname.replace(/\/+$/, "") || "/",
    search: url.searchParams
  };
}
