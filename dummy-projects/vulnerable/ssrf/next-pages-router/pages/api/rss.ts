import type { NextApiRequest, NextApiResponse } from "next";
import axios from "axios";

// /api/rss?feed=https://blog.example/feed.xml
export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const feedUrl = String(req.query.feed);
  const { data } = await axios.get(feedUrl); // VULN-EXPECTED
  res.status(200).send(data);
}
