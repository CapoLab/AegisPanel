import { createServer } from "node:http";
import { createReadStream, existsSync } from "node:fs";
import { extname, join, normalize } from "node:path";
import { config } from "./config.js";
import { handleApi } from "./routes/api.js";
import { notFound, parseRoute, sendJson } from "./utils/http.js";

const publicDir = join(process.cwd(), "web");

const types = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".svg": "image/svg+xml",
  ".json": "application/json; charset=utf-8"
};

function serveStatic(req, res, route) {
  const requested = route.pathname === "/" ? "/index.html" : route.pathname;
  const filePath = normalize(join(publicDir, requested));
  if (!filePath.startsWith(publicDir) || !existsSync(filePath)) {
    const fallback = join(publicDir, "index.html");
    res.writeHead(200, { "content-type": types[".html"] });
    createReadStream(fallback).pipe(res);
    return;
  }
  res.writeHead(200, {
    "content-type": types[extname(filePath)] || "application/octet-stream",
    "cache-control": "no-store"
  });
  createReadStream(filePath).pipe(res);
}

const server = createServer(async (req, res) => {
  const route = parseRoute(req);
  try {
    if (route.pathname.startsWith("/api/")) {
      const handled = await handleApi(req, res, route);
      if (handled === false) notFound(res);
      return;
    }
    serveStatic(req, res, route);
  } catch (error) {
    sendJson(res, error.status || 500, {
      ok: false,
      error: error.message || "Internal server error"
    });
  }
});

server.listen(config.port, config.host, () => {
  console.log(`AegisPanel listening on http://${config.host}:${config.port}`);
});
