import type { LoaderFunctionArgs } from "@remix-run/node";
import { json } from "@remix-run/node";

// /preview?u=https://site.example
export async function loader({ request }: LoaderFunctionArgs) {
  const url = new URL(request.url).searchParams.get("u");
  const res = await fetch(url!); // VULN-EXPECTED
  return json({ status: res.status, body: await res.text() });
}
