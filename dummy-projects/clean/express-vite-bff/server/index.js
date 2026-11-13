import express from "express";
import axios from "axios";
import { assertAllowedUrl } from "./url-guard.js";
import { escapeHtml } from "./html.js";

// Secrets come from the environment (never committed) and stay on the server.
const stripeKey = process.env.STRIPE_SECRET_KEY; // SAFE-EXPECTED
const sessionSecret = process.env.SESSION_SECRET; // SAFE-EXPECTED

const app = express();
app.use(express.json());

// Same features as the vulnerable app, but every outbound request is guarded or fixed-host.
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

app.get("/health", (_req, res) => res.json({ ok: Boolean(stripeKey && sessionSecret) }));

// Same features as vulnerable/xss/express-api, but output is escaped or not HTML.
app.get("/hello", (req, res) => {
  res.send("<h1>Hello " + escapeHtml(req.query.name) + "</h1>"); // SAFE-EXPECTED
});

app.get("/items/:id", (req, res) => {
  res.status(404).send(`<p>Item ${escapeHtml(req.params.id)} not found</p>`); // SAFE-EXPECTED
});

app.get("/search", (req, res) => {
  res.json({ q: req.query.q, results: [] }); // SAFE-EXPECTED
});

app.get("/echo", (req, res) => {
  res.type("text/plain").send(String(req.query.q)); // SAFE-EXPECTED
});

app.post("/preview", (req, res) => {
  res.send(escapeHtml(req.body.html)); // SAFE-EXPECTED
});

app.listen(3003);
