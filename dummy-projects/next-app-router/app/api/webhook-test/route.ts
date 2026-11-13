import { NextResponse } from "next/server";

// POST /api/webhook-test { "callbackUrl": "https://customer.example/hook" }
export async function POST(req: Request) {
  const { callbackUrl } = await req.json();

  const res = await fetch(callbackUrl, { method: "POST", body: JSON.stringify({ ping: true }) }); // VULN-EXPECTED
  return NextResponse.json({ delivered: res.ok, status: res.status });
}
