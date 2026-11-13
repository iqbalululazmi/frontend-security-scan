import { NextRequest, NextResponse } from "next/server";
import { assertAllowedUrl } from "@/lib/url-guard";

// Same feature as /api/proxy, but the destination goes through the allowlist guard first.
export async function GET(req: NextRequest) {
  const raw = req.nextUrl.searchParams.get("url") ?? "";
  const target = assertAllowedUrl(raw);

  const upstream = await fetch(target); // SAFE-EXPECTED
  return new NextResponse(upstream.body, { status: upstream.status });
}
