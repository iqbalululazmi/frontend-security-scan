import express from "express";
import axios from "axios";
import got from "got";
import http from "node:http";
import { assertAllowedUrl } from "./url-guard.js";

const app = express();
app.use(express.json());

// --- vulnerable endpoints -------------------------------------------------

app.get("/api/proxy", async (req, res) => {
  const { data } = await axios.get(req.query.url); // VULN-EXPECTED
  res.send(data);
});

app.post("/api/webhook-test", async (req, res) => {
  const { callbackUrl } = req.body;
  const r = await fetch(callbackUrl, { method: "POST" }); // VULN-EXPECTED
  res.json({ status: r.status });
});

app.get("/api/avatar", (req, res) => {
  http.get(req.query.u, (upstream) => upstream.pipe(res)); // VULN-EXPECTED
});

app.get("/api/fetch/:target", async (req, res) => {
  const body = await got(req.params.target).text(); // VULN-EXPECTED
  res.send(body);
});

// multi-tenant config: host taken from a request header
app.get("/api/tenant-config", async (req, res) => {
  const host = req.headers["x-tenant-host"];
  const r = await fetch(`https://${host}/config.json`); // VULN-EXPECTED
  res.json(await r.json());
});

// --- safe endpoints -------------------------------------------------------

app.get("/api/safe-proxy", async (req, res) => {
  const target = assertAllowedUrl(String(req.query.url));
  const { data } = await axios.get(target.toString()); // SAFE-EXPECTED
  res.send(data);
});

app.get("/api/weather", async (req, res) => {
  const city = encodeURIComponent(String(req.query.city));
  const { data } = await axios.get(`https://api.weather.example.com/v1/${city}`); // SAFE-EXPECTED
  res.json(data);
});

app.listen(3001);
