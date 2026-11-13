import type { NextApiRequest, NextApiResponse } from "next";
import { validateTargetUrl } from "../../lib/url-guard";

// User supplies a full URL, but it must pass the allowlist guard (throws otherwise).
export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const url = String(req.query.url);
  validateTargetUrl(url);
  const r = await fetch(url); // SAFE-EXPECTED
  res.status(200).send(await r.text());
}
