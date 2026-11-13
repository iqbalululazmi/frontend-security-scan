import { NextRequest, NextResponse } from "next/server";

// GET /api/proxy?url=https://example.com/data.json  -- generic "fetch this URL for me" endpoint
export async function GET(req: NextRequest) {
  const target = req.nextUrl.searchParams.get("url");
  if (!target) return NextResponse.json({ error: "url required" }, { status: 400 });

  const upstream = await fetch(target); // VULN-EXPECTED
  return new NextResponse(upstream.body, { status: upstream.status });
}
