import type { NextApiRequest, NextApiResponse } from "next";

// Fixed host, user value is URL-encoded into the path only.
export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const ip = encodeURIComponent(String(req.query.ip));
  const r = await fetch(`https://ipapi.example.com/json/${ip}`); // SAFE-EXPECTED
  res.status(200).json(await r.json());
}
