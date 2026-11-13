import type { LoaderFunctionArgs } from "@remix-run/node";
import { json } from "@remix-run/node";

// Fixed host; params.id only fills a path segment.
export async function loader({ params }: LoaderFunctionArgs) {
  const res = await fetch(`https://api.internal.example.com/users/${params.id}`); // SAFE-EXPECTED
  return json(await res.json());
}
