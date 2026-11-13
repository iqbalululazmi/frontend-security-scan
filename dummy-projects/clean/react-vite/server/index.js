import http from "node:http";
import { assertAllowedUrl } from "./url-guard.js";

// Every outbound request is either to a fixed host or validated by an allowlist guard.
const server = http.createServer(async (req, res) => {
  const reqUrl = new URL(req.url, "http://localhost");

  if (reqUrl.pathname === "/api/weather") {
    const city = encodeURIComponent(reqUrl.searchParams.get("city") ?? "");
    const r = await fetch(`https://api.weather.example.com/v1/${city}`); // SAFE-EXPECTED
    res.end(await r.text());
    return;
  }

  if (reqUrl.pathname === "/api/proxy") {
    const target = assertAllowedUrl(String(reqUrl.searchParams.get("url")));
    const r = await fetch(target.toString()); // SAFE-EXPECTED
    res.end(await r.text());
    return;
  }

  res.statusCode = 404;
  res.end();
});

server.listen(3002);
