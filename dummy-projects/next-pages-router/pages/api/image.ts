import type { NextApiRequest, NextApiResponse } from "next";

// /api/image?src=https://example.com/pic.png  -- resizing proxy
export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const { src } = req.query;
  const upstream = await fetch(src as string); // VULN-EXPECTED
  const buf = Buffer.from(await upstream.arrayBuffer());
  res.setHeader("content-type", upstream.headers.get("content-type") ?? "image/png");
  res.send(buf);
}
