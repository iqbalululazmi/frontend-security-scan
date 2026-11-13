import type { LoaderFunctionArgs } from "@remix-run/node";
import { json } from "@remix-run/node";

// /tenants/acme -> http://acme.internal/api/info   (tenant name becomes the HOST)
export async function loader({ params }: LoaderFunctionArgs) {
  const res = await fetch(`http://${params.tenant}.internal/api/info`); // VULN-EXPECTED
  return json(await res.json());
}
