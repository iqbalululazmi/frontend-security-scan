import { NextRequest, NextResponse } from "next/server";

// User input only fills a path segment of a fixed host.
export async function GET(req: NextRequest) {
  const id = req.nextUrl.searchParams.get("id");
  const res = await fetch(`https://api.example.com/users/${id}`); // SAFE-EXPECTED
  return NextResponse.json(await res.json());
}
