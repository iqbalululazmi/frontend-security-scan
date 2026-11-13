import type { ActionFunctionArgs } from "@remix-run/node";
import { json } from "@remix-run/node";

export async function action({ request }: ActionFunctionArgs) {
  const form = await request.formData();
  const endpoint = form.get("endpoint") as string;
  const res = await fetch(endpoint, { method: "POST" }); // VULN-EXPECTED
  return json({ ok: res.ok });
}
