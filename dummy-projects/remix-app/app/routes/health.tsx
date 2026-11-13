import { json } from "@remix-run/node";

export async function loader() {
  const res = await fetch("https://status.example.com/health"); // SAFE-EXPECTED
  return json({ upstream: res.status });
}
