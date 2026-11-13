// Rule tests for ssrf.yml. Run: python3 scan.py self-test
// "ruleid" = must be reported on the next line, "ok" = must NOT be reported.
import axios from "axios";
import got from "got";
import http from "node:http";
import { assertAllowedUrl, validateTargetUrl } from "./url-guard";

declare const app: any;

// ------------------------------ Express style ------------------------------
app.get("/a", async (req: any, res: any) => {
  // ruleid: ssrf-user-input-to-server-request
  const r = await fetch(req.query.url);
  res.send(await r.text());
});

app.post("/b", async (req: any, res: any) => {
  const { callbackUrl } = req.body;
  // ruleid: ssrf-user-input-to-server-request
  await fetch(callbackUrl, { method: "POST" });
  res.end();
});

app.get("/c", async (req: any, res: any) => {
  // ruleid: ssrf-user-input-to-server-request
  const { data } = await axios.get(req.query.url);
  res.send(data);
});

app.get("/d", async (req: any, res: any) => {
  // ruleid: ssrf-user-input-to-server-request
  const body = await got(req.params.target).text();
  res.send(body);
});

app.get("/e", (req: any, res: any) => {
  // ruleid: ssrf-user-input-to-server-request
  http.get(req.query.u, (up) => up.pipe(res));
});

app.get("/f", async (req: any, res: any) => {
  const host = req.headers["x-tenant-host"];
  // ruleid: ssrf-user-input-to-server-request
  const r = await fetch(`https://${host}/config.json`);
  res.json(await r.json());
});

app.post("/g", async (req: any, res: any) => {
  // ruleid: ssrf-user-input-to-server-request
  await axios({ url: req.body.endpoint, method: "POST" });
  res.end();
});

// ------------------------- Fetch API / Next / Remix -------------------------
export async function GET(req: Request) {
  const target = new URL(req.url).searchParams.get("url");
  // ruleid: ssrf-user-input-to-server-request
  const up = await fetch(target!);
  return new Response(up.body);
}

export async function POST(request: Request) {
  const { target } = await request.json();
  // ruleid: ssrf-user-input-to-server-request
  const up = await fetch(target);
  return new Response(up.body);
}

export async function action({ request }: { request: Request }) {
  const form = await request.formData();
  const endpoint = form.get("endpoint") as string;
  // ruleid: ssrf-user-input-to-server-request
  await fetch(endpoint, { method: "POST" });
  return null;
}

export default async function Page({ searchParams }: { searchParams: Promise<{ url?: string }> }) {
  const { url } = await searchParams;
  // ruleid: ssrf-user-input-to-server-request
  const res = await fetch(url!);
  return res.text();
}

export async function loader({ params }: { params: { tenant: string } }) {
  // ruleid: ssrf-user-input-to-server-request
  const res = await fetch(`http://${params.tenant}.internal/api`);
  return res.json();
}

export async function checkWebhook(formData: FormData) {
  const endpoint = formData.get("endpoint") as string;
  // ruleid: ssrf-user-input-to-server-request
  const res = await fetch(endpoint, { method: "POST" });
  return res.ok;
}

// ----------------------------------- Safe -----------------------------------
app.get("/ok1", async (req: any, res: any) => {
  const target = assertAllowedUrl(String(req.query.url));
  // ok: ssrf-user-input-to-server-request
  const r = await fetch(target.toString());
  res.send(await r.text());
});

app.get("/ok2", async (req: any, res: any) => {
  const url = String(req.query.url);
  validateTargetUrl(url);
  // ok: ssrf-user-input-to-server-request
  const r = await fetch(url);
  res.send(await r.text());
});

app.get("/ok3", async (req: any, res: any) => {
  const city = encodeURIComponent(String(req.query.city));
  // ok: ssrf-user-input-to-server-request
  const { data } = await axios.get(`https://api.weather.example.com/v1/${city}`);
  res.json(data);
});

app.get("/ok4", async (req: any, res: any) => {
  const id = req.params.id;
  // ok: ssrf-user-input-to-server-request
  const r = await fetch(`https://api.example.com/users/${id}`);
  res.json(await r.json());
});

app.get("/ok5", async (req: any, res: any) => {
  // ok: ssrf-user-input-to-server-request
  const r = await fetch("https://api.example.com/health");
  res.json(await r.json());
});

app.get("/ok6", async (req: any, res: any) => {
  const page = Number(req.query.page);
  // ok: ssrf-user-input-to-server-request
  const r = await fetch(`${process.env.API_BASE}/items?page=${page}`);
  res.json(await r.json());
});

// Browser code: no server-side request, no request-like source
function clientSide(userInput: string) {
  // ok: ssrf-user-input-to-server-request
  return fetch(userInput);
}

// ------------------------------- next.config.js -------------------------------
const nextConfig = {
  images: {
    remotePatterns: [
      // ruleid: nextjs-image-remote-patterns-wildcard-host
      { protocol: "https", hostname: "**" },
      // ok: nextjs-image-remote-patterns-wildcard-host
      { protocol: "https", hostname: "images.example.com" },
    ],
  },
};
